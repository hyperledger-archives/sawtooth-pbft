use std::time::{Duration, Instant};

enum TimeoutState {
    Active,
    Expired,
}

pub struct Timeout {
    state: TimeoutState,
    duration: Duration,
    start: Instant,
}

impl Timeout {
    pub fn new(duration: Duration) -> Self {
        Timeout {
            state: TimeoutState::Active,
            duration: duration,
            start: Instant::now(),
        }
    }

    pub fn is_expired(&mut self) -> bool {
        if Instant::now() - self.start > self.duration {
            self.state = TimeoutState::Expired;
        }
        match self.state {
            TimeoutState::Active => false,
            TimeoutState::Expired => true,
        }
    }
}
