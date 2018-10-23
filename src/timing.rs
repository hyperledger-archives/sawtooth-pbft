/*
 * Copyright 2018 Bitwise IO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

//! Timing-related structures
use serde_millis;
use std::time::{Duration, Instant};

/// Encapsulates calling a function every so often
pub struct Ticker {
    last: Instant,
    timeout: Duration,
}

impl Ticker {
    pub fn new(period: Duration) -> Self {
        Ticker {
            last: Instant::now(),
            timeout: period,
        }
    }

    // Do some work if the timeout has expired
    pub fn tick<T: FnMut()>(&mut self, mut callback: T) {
        let elapsed = Instant::now() - self.last;
        if elapsed >= self.timeout {
            callback();
            self.last = Instant::now();
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum TimeoutState {
    Active,
    Inactive,
    Expired,
}

/// A timer that expires after a given duration
/// Check back on this timer every so often to see if it's expired
#[derive(Debug, Serialize, Deserialize)]
pub struct Timeout {
    state: TimeoutState,
    duration: Duration,
    #[serde(with = "serde_millis")]
    start: Instant,
}

impl Timeout {
    pub fn new(duration: Duration) -> Self {
        Timeout {
            state: TimeoutState::Inactive,
            duration,
            start: Instant::now(),
        }
    }

    /// Update the timer state, and check if the timer is expired
    pub fn check_expired(&mut self) -> bool {
        if self.state == TimeoutState::Active && Instant::now() - self.start > self.duration {
            self.state = TimeoutState::Expired;
        }
        match self.state {
            TimeoutState::Active | TimeoutState::Inactive => false,
            TimeoutState::Expired => true,
        }
    }

    pub fn start(&mut self) {
        self.state = TimeoutState::Active;
        self.start = Instant::now();
    }

    pub fn stop(&mut self) {
        self.state = TimeoutState::Inactive;
        self.start = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_tolerance {
        ($val1:expr, $val2:expr, $tol:expr) => {
            if $val2 > $val1 && $val2 - $val1 > $tol {
                panic!(
                    "Value is not within tolerance ({:?} - {:?} > {:?})",
                    $val2, $val1, $tol
                );
            }
            if $val1 > $val2 && $val1 - $val2 > $tol {
                panic!(
                    "Value is not within tolerance ({:?} - {:?} > {:?})",
                    $val1, $val2, $tol
                );
            }
        };
    }

    /// Tell the ticker to wait for 100ms, then see if it actually waited 100 +/- 1ms
    #[test]
    fn ticker() {
        let time = Duration::from_millis(100);
        let mut t = Ticker::new(time);
        let start_time = Instant::now();
        let mut end_time = Instant::now();
        let mut triggered = false;
        while !triggered {
            t.tick(|| {
                end_time = Instant::now();
                triggered = true;
            })
        }
        assert_tolerance!(end_time - start_time, time, Duration::from_millis(1));
    }

    /// Create a Timeout that lasts for 100ms and check that it expires anytime after 100ms have
    /// passed. Check whether `.start()` and `.stop()` work as expected.
    #[test]
    fn timeout() {
        let start_time = Instant::now();
        let mut t = Timeout::new(Duration::from_millis(100));
        assert_eq!(t.state, TimeoutState::Inactive);
        assert_tolerance!(t.start, start_time, Duration::from_millis(1));

        t.start();
        assert_eq!(t.state, TimeoutState::Active);
        ::std::thread::sleep(Duration::from_millis(110));

        assert!(t.check_expired());
        assert_eq!(t.state, TimeoutState::Expired);

        t.stop();
        assert_eq!(t.state, TimeoutState::Inactive);
    }
}
