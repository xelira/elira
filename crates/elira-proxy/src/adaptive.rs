use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct State {
    limit: f64,
    inflight: usize,
    ewma_ms: f64,
}

pub(crate) struct AdaptiveLimiter {
    state: Mutex<State>,
    target_ms: f64,
    min: f64,
    max: f64,
}

pub(crate) struct AdaptiveGuard {
    limiter: Arc<AdaptiveLimiter>,
    started: Instant,
}

impl AdaptiveLimiter {
    pub(crate) fn new(target: Duration, min: usize, max: usize) -> Arc<Self> {
        let min = min.max(1) as f64;
        let max = (max.max(min as usize)) as f64;
        Arc::new(Self {
            state: Mutex::new(State {
                limit: min,
                inflight: 0,
                ewma_ms: target.as_secs_f64() * 1000.0,
            }),
            target_ms: target.as_secs_f64() * 1000.0,
            min,
            max,
        })
    }

    pub(crate) fn acquire(self: &Arc<Self>) -> Option<AdaptiveGuard> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.inflight as f64 >= state.limit {
            return None;
        }
        state.inflight += 1;
        Some(AdaptiveGuard {
            limiter: self.clone(),
            started: Instant::now(),
        })
    }

    fn release(&self, elapsed: Duration) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.inflight = state.inflight.saturating_sub(1);
        let sample = elapsed.as_secs_f64() * 1000.0;
        state.ewma_ms = state.ewma_ms * 0.8 + sample * 0.2;
        if state.ewma_ms > self.target_ms * 1.2 && state.limit > self.min {
            state.limit = (state.limit * 0.9).max(self.min);
        } else if state.ewma_ms < self.target_ms * 0.8 && state.limit < self.max {
            state.limit = (state.limit + 1.0).min(self.max);
        }
    }
}

impl Drop for AdaptiveGuard {
    fn drop(&mut self) {
        self.limiter.release(self.started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_when_the_limit_is_reached() {
        let limiter = AdaptiveLimiter::new(Duration::from_millis(50), 1, 8);
        let first = limiter.acquire().expect("first");
        assert!(limiter.acquire().is_none());
        drop(first);
        assert!(limiter.acquire().is_some());
    }

    #[test]
    fn fast_requests_raise_the_limit() {
        let limiter = AdaptiveLimiter::new(Duration::from_millis(50), 1, 8);
        for _ in 0..4 {
            let guard = limiter.acquire().expect("guard");
            drop(guard);
        }
        let first = limiter.acquire().expect("first");
        let second = limiter.acquire().expect("second");
        drop(first);
        drop(second);
    }
}
