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

//! The message log used by PBFT nodes to save messages

#![allow(unknown_lints)]

use std::collections::HashSet;
use std::fmt;

use hex;
use sawtooth_sdk::consensus::engine::Block;

use crate::config::PbftConfig;
use crate::error::PbftError;
use crate::message_type::{ParsedMessage, PbftMessageType};
use crate::protos::pbft_message::PbftMessageInfo;
use crate::state::PbftState;

/// Struct for storing messages that a PbftNode receives
pub struct PbftLog {
    /// All blocks received from the validator that have not been garbage collected
    blocks: HashSet<Block>,

    /// All messages accepted by the node that have not been garbage collected
    messages: HashSet<ParsedMessage>,

    /// Maximum log size
    max_log_size: u64,
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_infos: Vec<PbftMessageInfo> = self
            .messages
            .iter()
            .map(|ref msg| msg.info().clone())
            .collect();
        let string_infos: Vec<String> = msg_infos
            .iter()
            .map(|info: &PbftMessageInfo| -> String {
                format!(
                    "    {{ {}, view: {}, seq: {}, signer: {} }}",
                    info.get_msg_type(),
                    info.get_view(),
                    info.get_seq_num(),
                    hex::encode(info.get_signer_id()),
                )
            })
            .collect();

        write!(f, "\nPbftLog:\n{}", string_infos.join("\n"))
    }
}

impl PbftLog {
    /// Create a new, empty `PbftLog` with the `max_log_size` specified in the `config`
    pub fn new(config: &PbftConfig) -> Self {
        PbftLog {
            blocks: HashSet::new(),
            messages: HashSet::new(),
            max_log_size: config.max_log_size,
        }
    }

    /// Add a `Block` to the log
    pub fn add_block(&mut self, block: Block) {
        trace!("Adding block to log: {:?}", block);
        self.blocks.insert(block);
    }

    /// Get all `Block`s in the message log with the specified block number
    pub fn get_blocks_with_num(&self, block_num: u64) -> Vec<&Block> {
        self.blocks
            .iter()
            .filter(|block| block.block_num == block_num)
            .collect()
    }

    /// Get the `Block` with the specified block ID
    pub fn get_block_with_id(&self, block_id: &[u8]) -> Option<&Block> {
        self.blocks
            .iter()
            .find(|block| block.block_id.as_slice() == block_id)
    }

    /// Add a parsed PBFT message to the log
    pub fn add_message(&mut self, msg: ParsedMessage, state: &PbftState) -> Result<(), PbftError> {
        // Except for ViewChanges, the message must be for the current view to be accepted
        let msg_type = PbftMessageType::from(msg.info().get_msg_type());
        if msg_type != PbftMessageType::ViewChange && msg.info().get_view() != state.view {
            return Err(PbftError::InvalidMessage(format!(
                "Node is on view {}, but a message for view {} was received",
                state.view,
                msg.info().get_view(),
            )));
        }

        trace!("{}: Adding message to log: {:?}", state, msg);

        self.messages.insert(msg);

        Ok(())
    }

    /// Check if the log has a PrePrepare at the node's current view and sequence number that
    /// matches the given block ID
    pub fn has_pre_prepare(&self, seq_num: u64, view: u64, block_id: &[u8]) -> bool {
        self.get_messages_of_type_seq_view(PbftMessageType::PrePrepare, seq_num, view)
            .iter()
            .any(|msg| msg.get_block_id() == block_id)
    }

    /// Check if the log contains `required` number of messages that match:
    /// - The `msg_type`
    /// - Sequence + view number of the provided `ref_msg`
    /// - The block_id in `ref_msg` (only if `check_block_id` is `true`)
    pub fn has_required_msgs(
        &self,
        msg_type: PbftMessageType,
        ref_msg: &ParsedMessage,
        check_block_id: bool,
        required: u64,
    ) -> bool {
        let msgs = self.get_messages_of_type_seq_view(
            msg_type,
            ref_msg.info().get_seq_num(),
            ref_msg.info().get_view(),
        );

        let msgs = if check_block_id {
            msgs.iter()
                .filter(|msg| msg.get_block_id() == ref_msg.get_block_id())
                .cloned()
                .collect()
        } else {
            msgs
        };

        msgs.len() as u64 >= required
    }

    /// Get the first message matching the type, view, and sequence number of the `info` (if one
    /// exists)
    pub fn get_first_msg(
        &self,
        info: &PbftMessageInfo,
        msg_type: PbftMessageType,
    ) -> Option<&ParsedMessage> {
        let msgs =
            self.get_messages_of_type_seq_view(msg_type, info.get_seq_num(), info.get_view());
        msgs.first().cloned()
    }

    /// Obtain all messages from the log that match the given type and sequence_number
    pub fn get_messages_of_type_seq(
        &self,
        msg_type: PbftMessageType,
        sequence_number: u64,
    ) -> Vec<&ParsedMessage> {
        self.messages
            .iter()
            .filter(|&msg| {
                let info = (*msg).info();
                info.get_msg_type() == String::from(msg_type)
                    && info.get_seq_num() == sequence_number
            })
            .collect()
    }

    /// Obtain all messages from the log that match the given type and view
    pub fn get_messages_of_type_view(
        &self,
        msg_type: PbftMessageType,
        view: u64,
    ) -> Vec<&ParsedMessage> {
        self.messages
            .iter()
            .filter(|&msg| {
                let info = (*msg).info();
                info.get_msg_type() == String::from(msg_type) && info.get_view() == view
            })
            .collect()
    }

    /// Obtain all messages from the log that match the given type, sequence number, and view
    pub fn get_messages_of_type_seq_view(
        &self,
        msg_type: PbftMessageType,
        sequence_number: u64,
        view: u64,
    ) -> Vec<&ParsedMessage> {
        self.messages
            .iter()
            .filter(|&msg| {
                let info = (*msg).info();
                info.get_msg_type() == String::from(msg_type)
                    && info.get_seq_num() == sequence_number
                    && info.get_view() == view
            })
            .collect()
    }

    /// Garbage collect the log if it has reached the `max_log_size`
    #[allow(clippy::ptr_arg)]
    pub fn garbage_collect(&mut self, current_seq_num: u64) {
        // If the max log size has been reached, filter out all old messages
        if self.messages.len() as u64 >= self.max_log_size {
            // The node needs to keep messages from the previous sequence number in case it
            // needs to build the next consensus seal
            self.messages
                .retain(|msg| msg.info().get_seq_num() >= current_seq_num - 1);

            self.blocks
                .retain(|block| block.block_num >= current_seq_num - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::protos::pbft_message::PbftMessage;
    use sawtooth_sdk::consensus::engine::PeerId;

    /// Create a PbftMessage, given its type, view, sequence number, and who it's from
    fn make_msg(
        msg_type: PbftMessageType,
        view: u64,
        seq_num: u64,
        signer_id: PeerId,
    ) -> ParsedMessage {
        let mut info = PbftMessageInfo::new();
        info.set_msg_type(String::from(msg_type));
        info.set_view(view);
        info.set_seq_num(seq_num);
        info.set_signer_id(Vec::<u8>::from(signer_id.clone()));

        let mut msg = PbftMessage::new();
        msg.set_info(info);
        msg.set_block_id(vec![]);

        ParsedMessage::from_pbft_message(msg).expect("Failed to parse PbftMessage")
    }

    /// Obtain the PeerId for node `which`
    fn get_peer_id(cfg: &PbftConfig, which: usize) -> PeerId {
        cfg.peers[which].clone()
    }

    /// Test that adding one message works as expected
    #[test]
    fn one_message() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);
        let state = PbftState::new(vec![], 0, &cfg);

        let msg = make_msg(PbftMessageType::PrePrepare, 0, 1, get_peer_id(&cfg, 0));

        log.add_message(msg.clone(), &state).unwrap();

        let gotten_msgs = log.get_messages_of_type_seq_view(PbftMessageType::PrePrepare, 1, 0);

        assert_eq!(gotten_msgs.len(), 1);
        assert_eq!(&msg, gotten_msgs[0]);
    }

    /// Make sure that log garbage collection works as expected
    /// (All messages up to, but not including, the previous sequence number are deleted)
    #[test]
    fn garbage_collection() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);
        let state = PbftState::new(vec![], 0, &cfg);

        for seq in 1..5 {
            log.add_block(Block::default());

            let msg = make_msg(PbftMessageType::PrePrepare, 0, seq, get_peer_id(&cfg, 0));
            log.add_message(msg.clone(), &state).unwrap();

            for peer in 0..4 {
                let msg = make_msg(PbftMessageType::Prepare, 0, seq, get_peer_id(&cfg, peer));

                log.add_message(msg.clone(), &state).unwrap();
            }

            for peer in 0..4 {
                let msg = make_msg(PbftMessageType::Commit, 0, seq, get_peer_id(&cfg, peer));

                log.add_message(msg.clone(), &state).unwrap();
            }
        }

        log.max_log_size = 20;
        log.garbage_collect(5);

        for old in 1..3 {
            for msg_type in &[
                PbftMessageType::PrePrepare,
                PbftMessageType::Prepare,
                PbftMessageType::Commit,
            ] {
                assert_eq!(
                    log.get_messages_of_type_seq_view(*msg_type, old, 0).len(),
                    0
                );
            }
        }

        assert!(log.blocks.is_empty());

        assert_eq!(
            log.get_messages_of_type_seq_view(PbftMessageType::PrePrepare, 4, 0)
                .len(),
            1
        );

        for msg_type in vec![PbftMessageType::Prepare, PbftMessageType::Commit] {
            assert_eq!(log.get_messages_of_type_seq_view(msg_type, 4, 0).len(), 4);
        }
    }
}
