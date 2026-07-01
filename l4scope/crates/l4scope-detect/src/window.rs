//! A fixed-memory rolling event-rate counter (ring of per-second buckets).
//! Used for host-wide rate signals (RST storms, connection churn).

const NS_PER_SEC: u64 = 1_000_000_000;

pub struct RollingRate {
    window_secs: u64,
    buckets: Vec<u64>,
    epoch: Vec<u64>, // which second each bucket currently represents
}

impl RollingRate {
    pub fn new(window_secs: u64) -> Self {
        let w = window_secs.max(1);
        RollingRate {
            window_secs: w,
            buckets: vec![0; w as usize],
            epoch: vec![u64::MAX; w as usize],
        }
    }

    /// Record one event at time `now_ns`.
    pub fn record(&mut self, now_ns: u64) {
        let sec = now_ns / NS_PER_SEC;
        let i = (sec % self.window_secs) as usize;
        if self.epoch[i] != sec {
            self.epoch[i] = sec;
            self.buckets[i] = 0;
        }
        self.buckets[i] += 1;
    }

    /// Total events within the last `window_secs` seconds ending at `now_ns`.
    pub fn count_window(&self, now_ns: u64) -> u64 {
        let sec = now_ns / NS_PER_SEC;
        let lo = sec.saturating_sub(self.window_secs - 1);
        let mut total = 0;
        for i in 0..self.buckets.len() {
            let e = self.epoch[i];
            if e != u64::MAX && e >= lo && e <= sec {
                total += self.buckets[i];
            }
        }
        total
    }

    /// Average events per second over the window.
    pub fn per_sec(&self, now_ns: u64) -> f64 {
        self.count_window(now_ns) as f64 / self.window_secs as f64
    }
}
