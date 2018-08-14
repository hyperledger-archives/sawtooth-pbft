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

use std::time::{Duration, Instant};

// Encapsulates doing some work every time a timeout has elapsed
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

    // Do some work if the timeout has elapsed
    pub fn tick<T: FnMut()>(&mut self, mut callback: T) {
        let elapsed = Instant::now() - self.last;
        if elapsed >= self.timeout {
            callback();
            self.last = Instant::now();
        }
    }
}

#[derive(Debug)]
enum TimeoutState {
    Active,
    Expired,
}

// Check back on this timer every so often to see if it's expired
#[derive(Debug)]
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

    pub fn reset(&mut self) {
        self.state = TimeoutState::Active;
        self.duration = self.duration;
        self.start = Instant::now();
    }
}
