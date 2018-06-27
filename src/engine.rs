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

use std::sync::mpsc::{Receiver, RecvTimeoutError};

use std::time::Duration;

use sawtooth_sdk::consensus::{engine::*, service::Service};

use node::PbftNode;

use config;
use timing;

// How long to wait in between trying to publish blocks
const BLOCK_DURATION: Duration = Duration::from_millis(2000);

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
        let mut working_ticker = timing::Ticker::new(BLOCK_DURATION);

        let config = config::load_pbft_config(chain_head.block_id, &mut service);

        info!("Peers: {:?}", config.peers);

        service
            .initialize_block(None)
            .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));

        let mut node = PbftNode::new(self.id, config.peers, service);

        // Event loop. Keep going until we receive a shutdown message.
        loop {
            let incoming_message = updates.recv_timeout(MESSAGE_TIMEOUT);

            match incoming_message {
                Ok(Update::BlockNew(block)) => node.on_block_new(block),
                Ok(Update::BlockValid(block_id)) => node.on_block_valid(block_id),
                Ok(Update::BlockCommit(block_id)) => node.on_block_commit(block_id),
                Ok(Update::PeerMessage(message, _sender_id)) => node.on_peer_message(message),
                Ok(Update::Shutdown) => break,
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    break;
                }
                _ => unimplemented!(), // TODO: implement BlockInvalid?
            }

            // TODO: fill out this method
            working_ticker.tick(|| {
                node.update_working_block();
            });
        }
    }

    fn version(&self) -> String {
        String::from("0.1")
    }

    fn name(&self) -> String {
        String::from("sawtooth-pbft")
    }
}
