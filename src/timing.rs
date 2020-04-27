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

use std::thread::sleep;
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

    #[cfg(test)]
    pub fn duration(&self) -> Duration {
        self.duration
    }

    pub fn is_active(&self) -> bool {
        self.state == TimeoutState::Active
    }
}

/// With exponential backoff, repeatedly try the callback until the result is `Ok`
pub fn retry_until_ok<T, E, F: FnMut() -> Result<T, E>>(
    base: Duration,
    max: Duration,
    mut callback: F,
) -> T {
    let mut delay = base;
    loop {
        match callback() {
            Ok(res) => return res,
            Err(_) => {
                sleep(delay);
                // Only increase delay if it's less than the max
                if delay < max {
                    delay = delay
                        .checked_mul(2)
                        .unwrap_or_else(|| Duration::from_millis(std::u64::MAX));
                    // Make sure the max isn't exceeded
                    if delay > max {
                        delay = max;
                    }
                }
            }
        }
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

    /// Tell the ticker to wait for 100ms, then see if it actually waited 100 +/- 5ms
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
        assert_tolerance!(end_time - start_time, time, Duration::from_millis(5));
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

    /// Retry a function that fails three times and succeeds on the 4th try with the
    /// `retry_until_ok` method, a 10ms base, and 20ms max; the total time should be 50ms.
    #[test]
    fn retry() {
        let start_time = Instant::now();
        let vec = vec![Err(()), Err(()), Err(()), Ok(())];
        let mut iter = vec.iter().cloned();
        retry_until_ok(Duration::from_millis(10), Duration::from_millis(20), || {
            iter.next().unwrap()
        });
        let end_time = Instant::now();
        assert_tolerance!(
            end_time - start_time,
            Duration::from_millis(50),
            Duration::from_millis(5)
        );
    }
}
