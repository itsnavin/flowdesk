//! Rolling latency statistics for the diagnostics view.

use std::collections::VecDeque;

#[derive(Default, Clone)]
pub struct LatencyStats {
    samples: VecDeque<u64>,
    pub total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Summary {
    pub count: usize,
    pub last_us: u64,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
}

const CAP: usize = 600;

impl LatencyStats {
    pub fn record(&mut self, rtt_us: u64) {
        if self.samples.len() == CAP {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt_us);
        self.total += 1;
    }

    pub fn history(&self) -> Vec<u64> {
        self.samples.iter().copied().collect()
    }

    pub fn summary(&self) -> Summary {
        if self.samples.is_empty() {
            return Summary::default();
        }
        let mut v: Vec<u64> = self.samples.iter().copied().collect();
        v.sort_unstable();
        let pct = |p: f64| v[(((v.len() - 1) as f64) * p).round() as usize];
        Summary {
            count: v.len(),
            last_us: *self.samples.back().unwrap(),
            min_us: v[0],
            p50_us: pct(0.50),
            p95_us: pct(0.95),
            p99_us: pct(0.99),
            max_us: *v.last().unwrap(),
            mean_us: v.iter().sum::<u64>() / v.len() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        let mut s = LatencyStats::default();
        assert_eq!(s.summary().count, 0);
        for i in 1..=100 {
            s.record(i);
        }
        let r = s.summary();
        assert_eq!((r.min_us, r.max_us, r.last_us), (1, 100, 100));
        assert!((r.p50_us as i64 - 50).abs() <= 1);
        assert!(r.p95_us >= 94 && r.p95_us <= 96);
    }

    #[test]
    fn ring_is_bounded() {
        let mut s = LatencyStats::default();
        for i in 0..2000 {
            s.record(i);
        }
        assert_eq!(s.history().len(), CAP);
        assert_eq!(s.total, 2000);
    }
}
