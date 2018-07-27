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

use sawtooth_sdk::consensus::{engine::*, service::Service};

use node::node::PbftNode;

use node::config;
use node::timing;

use node::error::PbftError;

use std::fs::File;
use std::io::prelude::*;

pub struct PbftEngine {
    id: u64,
}

impl PbftEngine {
    pub fn new(id: u64) -> Self {
        PbftEngine {
            id: id,
        }
    }
}

impl Engine for PbftEngine {
    fn start(
        &mut self,
        updates: Receiver<Update>,
        mut service: Box<Service>,
        startup_state: StartupState,
    ) {
        let StartupState {
            chain_head,
            peers,
            local_peer_info: _,
        } = startup_state;

        // Load on-chain settings
        let config = config::load_pbft_config(chain_head.block_id, &mut service);

        let mut working_ticker = timing::Ticker::new(config.block_duration);

        let mut node = PbftNode::new(self.id, &config, service);

        debug!("Starting state: {:#?}", node.state);

        let mut mod_file = File::create(format!("state_{}.txt", self.id).as_str()).unwrap();
        mod_file
            .write_all(&format!("{:#?}", node.state).into_bytes())
            .unwrap();

        // Event loop. Keep going until we receive a shutdown message.
        loop {
            let incoming_message = updates.recv_timeout(config.message_timeout);

            let res = match incoming_message {
                Ok(Update::BlockNew(block)) => node.on_block_new(block),
                Ok(Update::BlockValid(block_id)) => node.on_block_valid(block_id),
                Ok(Update::BlockInvalid(block_id)) => {
                    // Just hang out until the block becomes valid
                    warn!("{}: BlockInvalid", node.state);
                    Ok(())
                }
                Ok(Update::BlockCommit(block_id)) => node.on_block_commit(block_id),
                Ok(Update::PeerMessage(message, _sender_id)) => node.on_peer_message(message),
                Ok(Update::Shutdown) => break,
                Err(RecvTimeoutError::Timeout) => Err(PbftError::Timeout),
                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    break;
                }
                x => Ok(error!("THIS IS UNIMPLEMENTED {:?}", x)),
            };
            handle_pbft_result(res);

            working_ticker.tick(|| {
                if let Err(e) = node.try_publish() {
                    error!("{}", e);
                }
            });

            // Check to see if timeout has expired; initiate ViewChange if necessary
            if node.check_timeout_expired() {
                handle_pbft_result(node.start_view_change());
            }

            handle_pbft_result(node.retry_backlog());
        }
    }

    fn version(&self) -> String {
        String::from("0.1")
    }

    fn name(&self) -> String {
        String::from("sawtooth-pbft")
    }
}

fn handle_pbft_result(res: Result<(), PbftError>) {
    if let Err(e) = res {
        match e {
            PbftError::Timeout => (),
            PbftError::WrongNumMessages(_, _, _) => trace!("{}", e),
            _ => error!("{}", e),
        }
    }
}
