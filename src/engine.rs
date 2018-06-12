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
 * -----------------------------------------------------------------------------
 */

use sawtooth_sdk::consensus::{engine::*, service::Service};
use std::sync::mpsc::{Receiver, RecvTimeoutError};

use std::time::Duration;

// How long to wait in between trying to publish blocks
const BLOCK_DURATION: Duration = Duration::from_millis(3000);

// How many requests in between each checkpoint
const CHECKPOINT_PERIOD: u64 = 100;

// How long to wait for a message to arrive
const MESSAGE_TIMEOUT: Duration = Duration::from_millis(10);

pub struct PbftEngine {
    id: u64,
}

impl PbftEngine {
    pub fn new(id: u64) -> Self {
        PbftEngine { id: id }
    }
}

impl Engine for PbftEngine {
    fn start(
        &mut self,
        updates: Receiver<Update>,
        mut service: Box<Service>,
        chain_head: Block,
        _peers: Vec<PeerInfo>,
    ) {
        // Event loop. Keep going until the system exits
        loop {
            let incoming_message = updates.recv_timeout(MESSAGE_TIMEOUT);

            match incoming_message {
                Ok(Update::BlockNew(block)) => {}
                Ok(Update::BlockValid(block_id)) => {}
                Ok(Update::BlockCommit(block_id)) => {}
                Ok(Update::PeerMessage(message, _sender_id)) => {}
                Ok(Update::Shutdown) => break,
                Err(RecvTimeoutError::Timeout) => {
                    error!("Timed out waiting for message");
                }
                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    break;
                }
                _ => unimplemented!(),
            }
        }
    }

    fn version(&self) -> String {
        String::from("0.1")
    }

    fn name(&self) -> String {
        String::from("sawtooth-pbft")
    }
}
