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

use std::collections::{HashMap, HashSet};
use std::fmt;

use sawtooth_sdk::consensus::engine::{Block, BlockId};

use crate::config::PbftConfig;
use crate::message_type::{ParsedMessage, PbftMessageType};
use crate::protos::pbft_message::PbftMessageInfo;

/// Struct for storing messages that a PbftNode receives
pub struct PbftLog {
    /// All blocks received from the validator that have not been validated yet
    unvalidated_blocks: HashMap<BlockId, Block>,

    /// All blocks received from the validator that have been validated and not yet garbage
    /// collected
    blocks: HashSet<Block>,

    /// All messages accepted by the node that have not been garbage collected
    messages: HashSet<ParsedMessage>,

    /// Maximum log size
    max_log_size: u64,
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_infos: Vec<PbftMessageInfo> =
            self.messages.iter().map(|msg| msg.info().clone()).collect();
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
            unvalidated_blocks: HashMap::new(),
            blocks: HashSet::new(),
            messages: HashSet::new(),
            max_log_size: config.max_log_size,
        }
    }

    /// Add an already validated `Block` to the log
    pub fn add_validated_block(&mut self, block: Block) {
        trace!("Adding validated block to log: {:?}", block);
        self.blocks.insert(block);
    }

    /// Add an unvalidated `Block` to the log
    pub fn add_unvalidated_block(&mut self, block: Block) {
        trace!("Adding unvalidated block to log: {:?}", block);
        self.unvalidated_blocks
            .insert(block.block_id.clone(), block);
    }

    /// Move the `Block` corresponding to `block_id` from `unvalidated_blocks` to `blocks`. Return
    /// the block itself to be used by the calling code.
    pub fn block_validated(&mut self, block_id: BlockId) -> Option<Block> {
        trace!("Marking block as validated: {:?}", block_id);
        self.unvalidated_blocks.remove(&block_id).map(|block| {
            self.blocks.insert(block.clone());
            block
        })
    }

    /// Drop the `Block` corresponding to `block_id` from `unvalidated_blocks`.
    pub fn block_invalidated(&mut self, block_id: BlockId) -> bool {
        trace!("Dropping invalidated block: {:?}", block_id);
        self.unvalidated_blocks.remove(&block_id).is_some()
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

    /// Get the `Block` with the specified block ID from `unvalidated_blocks`.
    pub fn get_unvalidated_block_with_id(&self, block_id: &[u8]) -> Option<&Block> {
        self.unvalidated_blocks.get(block_id)
    }

    /// Add a parsed PBFT message to the log
    pub fn add_message(&mut self, msg: ParsedMessage) {
        trace!("Adding message to log: {:?}", msg);
        self.messages.insert(msg);
    }

    /// Check if the log has a PrePrepare at the given view and sequence number that matches the
    /// given block ID
    pub fn has_pre_prepare(&self, seq_num: u64, view: u64, block_id: &[u8]) -> bool {
        self.get_messages_of_type_seq_view(PbftMessageType::PrePrepare, seq_num, view)
            .iter()
            .any(|msg| msg.get_block_id() == block_id)
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

    /// Obtain all messages from the log that match the given type, sequence number, view, and
    /// block_id
    pub fn get_messages_of_type_seq_view_block(
        &self,
        msg_type: PbftMessageType,
        sequence_number: u64,
        view: u64,
        block_id: &[u8],
    ) -> Vec<&ParsedMessage> {
        self.messages
            .iter()
            .filter(|&msg| {
                let info = (*msg).info();
                let msg_block_id = (*msg).get_block_id();
                info.get_msg_type() == String::from(msg_type)
                    && info.get_seq_num() == sequence_number
                    && info.get_view() == view
                    && msg_block_id == block_id
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

    #[cfg(test)]
    pub fn set_max_log_size(&mut self, size: u64) {
        self.max_log_size = size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;

    /// The `PbftLog` must reliably store and retrieve blocks for the node to keep track of the
    /// blocks it receives from the validator, perform consensus on them, and commit or fail them.
    ///
    /// Blocks are usually added to the `PbftLog` using the `add_unvalidated_block` method, then
    /// later marked as valid using the `block_validated` method or dropped using the
    /// `block_invalidated` method. These blocks cannot be retrieved from the log until they are
    /// marked as valid.
    ///
    /// Blocks may also be added to the log using the `add_validated_block` method; in this case,
    /// the block can be retrived immediately without marking it as valid.
    ///
    /// Blocks are retrieved using the following methods:
    /// - `get_block_with_id` will get the block that matches the specified block ID
    /// - `get_blocks_with_num` will get all blocks that have the specified block number
    /// - `get_unvalidated_block_with_id` will get the unvalidated block that matches the specified
    ///   block ID
    ///
    /// This test will verify that blocks can be added to a `PbftLog` using block adding methods,
    /// that blocks are properly marked as valid or dropped, and that the methods for retrieving
    /// blocks work as intended.
    #[test]
    fn test_block_logging() {
        // Initialize an empty log
        let cfg = mock_config(4);
        let mut log = PbftLog::new(&cfg);

        // Add block 1 (unvalidated) to the log
        let block1 = mock_block(1);
        log.add_unvalidated_block(block1.clone());

        // Verify the block is stored as unvalidated
        assert!(log
            .get_unvalidated_block_with_id(&block1.block_id)
            .is_some());
        assert!(log.blocks.is_empty());

        // Validate block, then verify that the block is returned and the block is marked as valid
        // in the log
        let block = log
            .block_validated(block1.block_id.clone())
            .expect("Block was not in log");
        assert_eq!(block, block1);
        assert!(log.unvalidated_blocks.is_empty());
        assert!(log.blocks.get(&block1).is_some());

        // Verify log correctly retrieves blocks by ID
        assert_eq!(
            &block1,
            log.get_block_with_id(&block1.block_id)
                .expect("Block 1 not retrieved"),
        );
        assert!(log.get_block_with_id(&vec![2]).is_none());

        // Add an (already validated) block to the log
        let mut block2 = mock_block(2);
        block2.block_num = 1;
        log.add_validated_block(block2.clone());

        // Verify adding an already validated block works
        assert!(log.unvalidated_blocks.is_empty());
        assert!(log.blocks.get(&block2).is_some());

        // Add a 3rd block to the log
        let block3 = mock_block(3);
        log.add_validated_block(block3.clone());

        // Verify log correctly retrieves blocks by number
        let blocks_with_num_1 = log.get_blocks_with_num(1);
        assert_eq!(2, blocks_with_num_1.len());
        assert!(blocks_with_num_1.contains(&&block1));
        assert!(blocks_with_num_1.contains(&&block2));
    }

    /// The log must reliably store PBFT messages so that each node can use these messages to
    /// verify the progress of the network as it performs consensus on various blocks and decides
    /// on view changes.
    ///
    /// However, to ensure that messages are counted properly and that duplicate messages/blocks
    /// can’t be used to by a malicious node to trick the network, the `PbftLog` must not allow
    /// duplicate messages. If duplicate messages were not prevented, a bad node could, for
    /// instance, send the same `Commit` message multiple times to trick the other nodes into
    /// thinking that the necessary number of Commit messages have been received to safely commit
    /// that block.
    ///
    /// All messages are added to the `PbftLog` using the `add_message` method, and messages are
    /// retrieved using these methods that each provide a different filter for the messages:
    /// - `get_messages_of_type_seq` will retrieve all messages that match the specified message
    ///   type and sequence number
    /// - `get_messages_of_type_view` will retrieve all message that match the specified message
    ///   type and view number
    /// - `get_messages_of_type_seq_view` will retrieve all message that match the specified
    ///   message type, sequence number, and view number
    /// - `get_messages_of_type_seq_view_block` will retrieve all messages that match the specified
    ///   message type, sequence number, view number, and block ID
    ///
    /// This test will verify that messages can be added to a `PbftLog` using its `add_message`
    /// method, that the log will not store duplicate messages, and that the methods for retrieving
    /// messages work as intended.
    #[test]
    fn test_message_logging() {
        // Initialize an empty log
        let cfg = mock_config(4);
        let mut log = PbftLog::new(&cfg);

        // Verify adding single message works
        let msg1 = mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![1], false);
        log.add_message(msg1.clone());
        assert_eq!(1, log.messages.len());
        assert!(log.messages.contains(&msg1));

        // Verify messages aren't duplicated
        log.add_message(msg1.clone());
        assert_eq!(1, log.messages.len());

        // Verify get_messages_of_type_seq() works
        let msg2 = mock_msg(PbftMessageType::Commit, 0, 1, vec![0], vec![1], false);
        log.add_message(msg2.clone());
        let msg3 = mock_msg(PbftMessageType::Commit, 0, 2, vec![0], vec![2], false);
        log.add_message(msg3.clone());
        let msg4 = mock_msg(PbftMessageType::Commit, 1, 2, vec![0], vec![2], false);
        log.add_message(msg4.clone());

        let res1 = log.get_messages_of_type_seq(PbftMessageType::Commit, 1);
        assert_eq!(1, res1.len());
        assert!(res1.contains(&&msg2));

        let res2 = log.get_messages_of_type_seq(PbftMessageType::Commit, 2);
        assert_eq!(2, res2.len());
        assert!(res2.contains(&&msg3));
        assert!(res2.contains(&&msg4));

        // Verify get_messages_of_type_view() works
        let msg5 = mock_msg(PbftMessageType::ViewChange, 0, 1, vec![0], vec![1], false);
        log.add_message(msg5.clone());
        let msg6 = mock_msg(PbftMessageType::ViewChange, 1, 1, vec![0], vec![1], false);
        log.add_message(msg6.clone());
        let msg7 = mock_msg(PbftMessageType::ViewChange, 1, 2, vec![0], vec![2], false);
        log.add_message(msg7.clone());

        let res3 = log.get_messages_of_type_view(PbftMessageType::ViewChange, 0);
        assert_eq!(1, res3.len());
        assert!(res3.contains(&&msg5));

        let res4 = log.get_messages_of_type_view(PbftMessageType::ViewChange, 1);
        assert_eq!(2, res4.len());
        assert!(res4.contains(&&msg6));
        assert!(res4.contains(&&msg7));

        // Verify get_messages_of_type_seq_view() works
        let msg8 = mock_msg(PbftMessageType::Commit, 0, 1, vec![1], vec![1], false);
        log.add_message(msg8.clone());

        let res5 = log.get_messages_of_type_seq_view(PbftMessageType::Commit, 1, 0);
        assert_eq!(2, res5.len());
        assert!(res5.contains(&&msg2));
        assert!(res5.contains(&&msg8));

        let res6 = log.get_messages_of_type_seq_view(PbftMessageType::Commit, 2, 0);
        assert_eq!(1, res6.len());
        assert!(res6.contains(&&msg3));

        let res7 = log.get_messages_of_type_seq_view(PbftMessageType::Commit, 2, 1);
        assert_eq!(1, res7.len());
        assert!(res7.contains(&&msg4));

        let res8 = log.get_messages_of_type_seq_view(PbftMessageType::PrePrepare, 1, 0);
        assert_eq!(1, res8.len());
        assert!(res8.contains(&&msg1));

        // Verify get_messages_of_type_seq_view_block() works
        let msg9 = mock_msg(PbftMessageType::Commit, 0, 1, vec![0], vec![2], false);
        log.add_message(msg9.clone());

        let res9 = log.get_messages_of_type_seq_view_block(PbftMessageType::Commit, 1, 0, &vec![1]);
        assert_eq!(2, res9.len());
        assert!(res9.contains(&&msg2));
        assert!(res9.contains(&&msg8));

        let res10 =
            log.get_messages_of_type_seq_view_block(PbftMessageType::Commit, 1, 0, &vec![2]);
        assert_eq!(1, res10.len());
        assert!(res10.contains(&&msg9));
    }
}
