//! Long-term identity key, fingerprints and the trusted-peer store.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Identity {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// SHA-256 of the public key, hex, grouped for easy visual comparison: `ab12-cd34-...` (first 24 hex chars).
pub fn fingerprint(public: &[u8]) -> String {
    let h = hex(&Sha256::digest(public));
    h[..24].as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

const KEY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// New random security key: 20 symbols (100 bits), shown as `ABCDE-FGHJK-LMNPQ-RSTUV`.
pub fn generate_key() -> Result<String> {
    let kp = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?).generate_keypair()?;
    let chars: Vec<char> = kp.private[8..28].iter().map(|b| KEY_ALPHABET[(*b & 31) as usize] as char).collect();
    Ok(chars.chunks(5).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("-"))
}

/// Canonical form (upper case, no separators) or `None` if it isn't a valid key.
pub fn normalize_key(s: &str) -> Option<String> {
    let n: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase();
    (n.len() == 20 && n.bytes().all(|b| KEY_ALPHABET.contains(&b))).then_some(n)
}

/// Pre-shared key for the Noise handshake, derived from the security key.
pub fn psk_from_key(s: &str) -> Option<[u8; 32]> {
    let n = normalize_key(s)?;
    Some(Sha256::digest(format!("flowdesk-psk-v1:{n}").as_bytes()).into())
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let kp = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?).generate_keypair()?;
        Ok(Identity { private: kp.private, public: kp.public })
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    /// Load the identity from `dir/identity.key`, creating it on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("identity.key");
        if let Ok(txt) = std::fs::read_to_string(&path) {
            let mut it = txt.lines();
            if let (Some(p), Some(q)) = (it.next().and_then(unhex), it.next().and_then(unhex)) {
                if p.len() == 32 && q.len() == 32 {
                    return Ok(Identity { private: p, public: q });
                }
            }
        }
        let id = Self::generate()?;
        std::fs::write(&path, format!("{}\n{}\n", hex(&id.private), hex(&id.public)))
            .context("writing identity")?;
        restrict_permissions(&path);
        Ok(id)
    }
}

#[cfg(unix)]
fn restrict_permissions(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_: &Path) {}

pub fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("flowdesk")
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct TrustStore {
    /// fingerprint -> friendly name
    pub peers: BTreeMap<String, String>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl TrustStore {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("trusted.json");
        let mut s: TrustStore =
            std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        s.path = Some(path);
        s
    }
    pub fn in_memory() -> Self {
        Self::default()
    }
    pub fn is_trusted(&self, fp: &str) -> bool {
        self.peers.contains_key(fp)
    }
    pub fn trust(&mut self, fp: &str, name: &str) {
        self.peers.insert(fp.to_string(), name.to_string());
        self.save();
    }
    pub fn forget(&mut self, fp: &str) {
        self.peers.remove(fp);
        self.save();
    }
    fn save(&self) {
        if let Some(p) = &self.path {
            if let Ok(t) = serde_json::to_string_pretty(self) {
                let _ = std::fs::write(p, t);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_key_format_and_normalisation() {
        let k = generate_key().unwrap();
        assert_eq!(k.len(), 23);
        assert_ne!(k, generate_key().unwrap());
        assert_eq!(psk_from_key(&k), psk_from_key(&k.to_lowercase().replace('-', " ")));
        assert!(psk_from_key("short").is_none());
        assert_ne!(psk_from_key(&k), psk_from_key(&generate_key().unwrap()));
    }

    #[test]
    fn fingerprint_format_and_stability() {
        let id = Identity::generate().unwrap();
        let f = id.fingerprint();
        assert_eq!(f.len(), 29);
        assert_eq!(f, fingerprint(&id.public));
        assert_ne!(f, Identity::generate().unwrap().fingerprint());
    }

    #[test]
    fn identity_persists_and_trust_roundtrips() {
        let dir = std::env::temp_dir().join(format!("flowdesk-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.public, b.public);
        let mut t = TrustStore::load(&dir);
        assert!(!t.is_trusted("x"));
        t.trust("x", "box");
        assert!(TrustStore::load(&dir).is_trusted("x"));
        t.forget("x");
        assert!(!TrustStore::load(&dir).is_trusted("x"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
