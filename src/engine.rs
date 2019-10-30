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

//! Entry point for the consensus algorithm, including the main event loop

use std::sync::mpsc::{Receiver, RecvTimeoutError};

use sawtooth_sdk::consensus::{engine::*, service::Service};

use crate::config::PbftConfig;
use crate::error::PbftError;
use crate::message_type::ParsedMessage;
use crate::node::PbftNode;
use crate::state::{PbftMode, PbftState};
use crate::storage::get_storage;
use crate::timing;

pub struct PbftEngine {
    config: PbftConfig,
}

impl PbftEngine {
    pub fn new(config: PbftConfig) -> Self {
        PbftEngine { config }
    }
}

impl Engine for PbftEngine {
    fn start(
        &mut self,
        updates: Receiver<Update>,
        mut service: Box<dyn Service>,
        startup_state: StartupState,
    ) -> Result<(), Error> {
        info!("Startup state received from validator: {:?}", startup_state);

        let StartupState {
            chain_head,
            peers,
            local_peer_info,
        } = startup_state;

        // Load on-chain settings
        self.config
            .load_settings(chain_head.block_id.clone(), &mut *service);

        info!("PBFT config loaded: {:?}", self.config);

        let mut pbft_state = get_storage(&self.config.storage_location, || {
            PbftState::new(
                local_peer_info.peer_id.clone(),
                chain_head.block_num,
                &self.config,
            )
        })
        .unwrap_or_else(|err| panic!("Failed to load state due to error: {}", err));

        info!("PBFT state created: {}", **pbft_state.read());

        let mut block_publishing_ticker = timing::Ticker::new(self.config.block_publishing_delay);

        let mut node = PbftNode::new(
            &self.config,
            chain_head,
            peers,
            service,
            &mut pbft_state.write(),
        );

        node.start_idle_timeout(&mut pbft_state.write());

        // Main event loop; keep going until PBFT receives a Shutdown message or is disconnected
        loop {
            let incoming_message = updates.recv_timeout(self.config.update_recv_timeout);
            let state = &mut **pbft_state.write();

            trace!("{} received message {:?}", state, incoming_message);

            match handle_update(&mut node, incoming_message, state) {
                Ok(again) => {
                    if !again {
                        break;
                    }
                }
                Err(err) => log_any_error(Err(err)),
            }

            // If the block publishing delay has passed, attempt to publish a block
            block_publishing_ticker.tick(|| log_any_error(node.try_publish(state)));

            // If the idle timeout has expired, initiate a view change
            if node.check_idle_timeout_expired(state) {
                warn!("Idle timeout expired; proposing view change");
                log_any_error(node.start_view_change(state, state.view + 1));
            }

            // If the commit timeout has expired, initiate a view change
            if node.check_commit_timeout_expired(state) {
                warn!("Commit timeout expired; proposing view change");
                log_any_error(node.start_view_change(state, state.view + 1));
            }

            // Check the view change timeout if the node is view changing so we can start a new
            // view change if we don't get a NewView in time
            if let PbftMode::ViewChanging(v) = state.mode {
                if node.check_view_change_timeout_expired(state) {
                    warn!(
                        "View change timeout expired; proposing view change for view {}",
                        v + 1
                    );
                    log_any_error(node.start_view_change(state, v + 1));
                }
            }
        }

        Ok(())
    }

    fn version(&self) -> String {
        "1.0".into()
    }

    fn name(&self) -> String {
        "pbft".into()
    }

    fn additional_protocols(&self) -> Vec<(String, String)> {
        vec![]
    }
}

fn handle_update(
    node: &mut PbftNode,
    incoming_message: Result<Update, RecvTimeoutError>,
    state: &mut PbftState,
) -> Result<bool, PbftError> {
    match incoming_message {
        Ok(Update::BlockNew(block)) => node.on_block_new(block, state)?,
        Ok(Update::BlockValid(block_id)) => node.on_block_valid(block_id, state)?,
        Ok(Update::BlockInvalid(block_id)) => node.on_block_invalid(block_id)?,
        Ok(Update::BlockCommit(block_id)) => node.on_block_commit(block_id, state)?,
        Ok(Update::PeerMessage(message, _)) => {
            // Since the signer ID in the PeerMessageHeader is verified by the validator, it can be
            // ensured that the PbftMessage was in fact created and signed by the node that it
            // claims to be from by comparing the header's signer and the PbftMessage's signer
            let verified_signer_id = message.header.signer_id.clone();
            let parsed_message = ParsedMessage::from_peer_message(message, state.id.as_slice())?;
            let pbft_signer_id = parsed_message.info().get_signer_id().to_vec();

            if pbft_signer_id != verified_signer_id {
                return Err(PbftError::InvalidMessage(format!(
                    "Mismatch between PbftMessage's signer ID ({:?}) and PeerMessage's signer ID \
                     ({:?}) of peer message: {:?}",
                    pbft_signer_id, verified_signer_id, parsed_message
                )));
            }

            node.on_peer_message(parsed_message, state)?
        }
        Ok(Update::Shutdown) => {
            info!("Received shutdown; stopping PBFT");
            return Ok(false);
        }
        Ok(Update::PeerConnected(info)) => {
            info!("Received PeerConnected message with peer info: {:?}", info);
            node.on_peer_connected(info.peer_id, state)?
        }
        Ok(Update::PeerDisconnected(id)) => {
            info!("Received PeerDisconnected for peer ID: {:?}", id);
        }
        Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => {
            error!("Disconnected from validator; stopping PBFT");
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
pub fn test_handle_update(
    node: &mut PbftNode,
    incoming_message: Result<Update, RecvTimeoutError>,
    state: &mut PbftState,
) -> Result<bool, PbftError> {
    handle_update(node, incoming_message, state)
}

fn log_any_error(res: Result<(), PbftError>) {
    if let Err(e) = res {
        // Treat errors that result from other nodes' messages as warnings
        match e {
            PbftError::SigningError(_)
            | PbftError::FaultyPrimary(_)
            | PbftError::InvalidMessage(_) => warn!("{}", e),
            _ => error!("{}", e),
        }
    }
}
