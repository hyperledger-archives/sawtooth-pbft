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

use std::collections::{HashSet, VecDeque};
use std::fmt;

use hex;
use itertools::Itertools;

use crate::config::PbftConfig;
use crate::error::PbftError;
use crate::message_type::{ParsedMessage, PbftMessageType};
use crate::protos::pbft_message::{PbftMessageInfo, PbftSeal};
use crate::state::PbftState;
use sawtooth_sdk::consensus::engine::BlockId;

/// Stores a consensus seal along with its associated sequence number and block ID
#[derive(Clone, Eq, Hash, PartialEq)]
struct PbftSealEntry {
    block_id: BlockId,
    seq_num: u64,
    seal: PbftSeal,
}

/// Struct for storing messages that a PbftNode receives
pub struct PbftLog {
    /// Generic messages (BlockNew, PrePrepare, Prepare, Commit)
    messages: HashSet<ParsedMessage>,

    /// Maximum log size, defined from on-chain settings
    max_log_size: u64,

    /// Backlog of messages (from peers) with sender's ID
    backlog: VecDeque<ParsedMessage>,

    /// PBFT consensus seals that are stored in case a view change is needed
    seals: HashSet<PbftSealEntry>,
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
    pub fn new(config: &PbftConfig) -> Self {
        PbftLog {
            messages: HashSet::new(),
            max_log_size: config.max_log_size,
            backlog: VecDeque::new(),
            seals: HashSet::new(),
        }
    }

    /// `check_prepared` predicate
    /// `check_prepared` is true for this node if the following messages are present in its log:
    ///  + A `PrePrepare` message matching the original message (in the current view)
    ///  + `2f + 1` matching `Prepare` messages from different nodes that match
    ///    `PrePrepare` message above (including its own)
    pub fn check_prepared(&self, info: &PbftMessageInfo, f: u64) -> bool {
        match self.get_one_msg(info, &PbftMessageType::PrePrepare) {
            Some(msg) => {
                self.log_has_required_msgs(&PbftMessageType::Prepare, &msg, true, 2 * f + 1)
            }
            None => false,
        }
    }

    /// Checks if the node is ready to enter the `Committing` phase based on the `PbftMessage` received
    ///
    /// `check_committable` is true if for this node:
    ///   + `check_prepared` is true
    ///   + This node has accepted `2f + 1` `Commit` messages, including its own, that match the
    ///     corresponding `PrePrepare` message
    pub fn check_committable(&self, info: &PbftMessageInfo, f: u64) -> bool {
        // Check if Prepared predicate is true
        self.check_prepared(info, f)
            && self.log_has_required_msgs(
                &PbftMessageType::Commit,
                &self
                    .get_one_msg(info, &PbftMessageType::PrePrepare)
                    .unwrap(),
                true,
                2 * f + 1,
            )
    }

    /// Get one message matching the type, view number, and sequence number
    pub fn get_one_msg(
        &self,
        info: &PbftMessageInfo,
        msg_type: &PbftMessageType,
    ) -> Option<&ParsedMessage> {
        let msgs =
            self.get_messages_of_type_seq_view(msg_type, info.get_seq_num(), info.get_view());
        msgs.first().cloned()
    }

    /// Check if the log contains `required` number of messages with type `msg_type` that match the
    /// sequence and view number of the provided `ref_msg`, as well as its block (optional)
    pub fn log_has_required_msgs(
        &self,
        msg_type: &PbftMessageType,
        ref_msg: &ParsedMessage,
        check_block: bool,
        required: u64,
    ) -> bool {
        let msgs = self.get_messages_of_type_seq_view(
            msg_type,
            ref_msg.info().get_seq_num(),
            ref_msg.info().get_view(),
        );

        let msgs = if check_block {
            msgs.iter()
                .filter(|msg| msg.get_block() == ref_msg.get_block())
                .cloned()
                .collect()
        } else {
            msgs
        };

        msgs.len() as u64 >= required
    }

    /// Add a generic PBFT message to the log
    pub fn add_message(&mut self, msg: ParsedMessage, state: &PbftState) -> Result<(), PbftError> {
        // Except for ViewChanges, the message must be for the current view to be accepted
        let msg_type = PbftMessageType::from(msg.info().get_msg_type());
        if msg_type != PbftMessageType::ViewChange && msg.info().get_view() != state.view {
            error!(
                "Got message with mismatched view number; {} != {}",
                msg.info().get_view(),
                state.view,
            );
            return Err(PbftError::ViewMismatch(
                msg.info().get_view() as usize,
                state.view as usize,
            ));
        }

        self.messages.insert(msg);
        trace!("{}", self);

        Ok(())
    }

    /// Add a PBFT consensus seal to the log
    pub fn add_consensus_seal(&mut self, block_id: BlockId, seq_num: u64, seal: PbftSeal) {
        self.seals.insert(PbftSealEntry {
            block_id,
            seq_num,
            seal,
        });
    }

    pub fn get_consensus_seal(&self, seq_num: u64) -> Result<PbftSeal, PbftError> {
        let possible_seals: Vec<_> = self
            .seals
            .iter()
            .filter(|seal| seal.seq_num == seq_num)
            .cloned()
            .collect();

        if possible_seals.len() != 1 {
            error!(
                "There should be only one valid consensus seal for seq number {}",
                seq_num as usize,
            );
            return Err(PbftError::WrongNumSeals(1, possible_seals.len()));
        }

        Ok(possible_seals.first().unwrap().clone().seal)
    }

    /// Obtain all messages from the log that match a given type and sequence_number
    pub fn get_messages_of_type_seq(
        &self,
        msg_type: &PbftMessageType,
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

    /// Obtain all messages from the log that match a given type and view
    pub fn get_messages_of_type_view(
        &self,
        msg_type: &PbftMessageType,
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

    /// Obtain messages from the log that match a given type, sequence number, and view
    pub fn get_messages_of_type_seq_view(
        &self,
        msg_type: &PbftMessageType,
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

    /// Get sufficient messages for the given type and sequence number
    ///
    /// Gets all messages that match the given type and sequence number,
    /// groups them by the view number, filters out view number groups
    /// that don't have enough messages, and then sorts by view number
    /// and returns the highest one found, as an option in case there's
    /// no matching view number groups.
    ///
    /// This is useful in cases where e.g. we have enough messages to
    /// publish for some view number for the current sequence number,
    /// but we've forced a view change before the publishing could happen
    /// and we don't have any/enough messages for the current view num.
    ///
    /// Considers messages from self to not count towards being enough,
    /// as the current usage of this function is building a seal, where
    /// the publishing node's approval is implicit via publishing.
    pub fn get_enough_messages(
        &self,
        msg_type: &PbftMessageType,
        sequence_number: u64,
        minimum: u64,
    ) -> Option<Vec<&ParsedMessage>> {
        self.messages
            .iter()
            .filter_map(|msg| {
                let info = msg.info();
                let same_type = info.get_msg_type() == String::from(msg_type);
                let same_seq = info.get_seq_num() == sequence_number;

                if same_type && same_seq && !msg.from_self {
                    Some((info.get_view(), msg))
                } else {
                    None
                }
            })
            .into_group_map()
            .into_iter()
            .filter(|(_, msgs)| msgs.len() >= minimum as usize)
            .sorted_by_key(|(view, _)| *view)
            .pop()
            .map(|(_, msgs)| msgs)
    }

    /// Garbage collect the log after we've committed a block
    #[allow(clippy::ptr_arg)]
    pub fn garbage_collect(&mut self, current_seq_num: u64, block_id: &BlockId) {
        // If we've reached the max log size, filter out all old messages
        if self.messages.len() as u64 >= self.max_log_size {
            self.messages = self
                .messages
                .iter()
                .filter(|ref msg| {
                    // We need to keep messages from the previous sequence number to build the next
                    // consensus seal
                    msg.info().get_seq_num() >= current_seq_num - 1
                })
                .cloned()
                .collect();
        }

        // Remove all seals except for the one in the block we just committed
        self.seals = self
            .seals
            .iter()
            .filter(|seal| &seal.block_id == block_id)
            .cloned()
            .collect();
    }

    pub fn push_backlog(&mut self, msg: ParsedMessage) {
        self.backlog.push_back(msg);
    }

    pub fn pop_backlog(&mut self) -> Option<ParsedMessage> {
        self.backlog.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::hash::hash_sha256;
    use crate::protos::pbft_message::{PbftBlock, PbftMessage};
    use sawtooth_sdk::consensus::engine::PeerId;

    /// Create a PbftMessage, given its type, view, sequence number, and who it's from
    fn make_msg(
        msg_type: &PbftMessageType,
        view: u64,
        seq_num: u64,
        signer_id: PeerId,
        block_signer_id: PeerId,
    ) -> ParsedMessage {
        let mut info = PbftMessageInfo::new();
        info.set_msg_type(String::from(msg_type));
        info.set_view(view);
        info.set_seq_num(seq_num);
        info.set_signer_id(Vec::<u8>::from(signer_id.clone()));

        let mut pbft_block = PbftBlock::new();
        pbft_block.set_block_id(hash_sha256(
            format!("I'm a block with block num {}", seq_num).as_bytes(),
        ));
        pbft_block.set_signer_id(Vec::<u8>::from(block_signer_id));
        pbft_block.set_block_num(seq_num);

        let mut msg = PbftMessage::new();
        msg.set_info(info);
        msg.set_block(pbft_block);

        ParsedMessage::from_pbft_message(msg)
    }

    /// Obtain the PeerId for node `which`
    fn get_peer_id(cfg: &PbftConfig, which: u64) -> PeerId {
        cfg.peers[which as usize].clone()
    }

    /// Test that adding one message works as expected
    #[test]
    fn one_message() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);
        let state = PbftState::new(vec![], 0, &cfg);

        let msg = make_msg(
            &PbftMessageType::PrePrepare,
            0,
            1,
            get_peer_id(&cfg, 0),
            get_peer_id(&cfg, 0),
        );

        log.add_message(msg.clone(), &state).unwrap();

        let gotten_msgs = log.get_messages_of_type_seq_view(&PbftMessageType::PrePrepare, 1, 0);

        assert_eq!(gotten_msgs.len(), 1);
        assert_eq!(&msg, gotten_msgs[0]);
    }

    /// Test that `check_prepared` and `check_committable` predicates work properly
    #[test]
    fn prepared_committed() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);
        let state = PbftState::new(vec![], 0, &cfg);

        let msg = make_msg(
            &PbftMessageType::BlockNew,
            0,
            1,
            get_peer_id(&cfg, 0),
            get_peer_id(&cfg, 0),
        );
        log.add_message(msg.clone(), &state).unwrap();

        assert!(!log.check_prepared(&msg.info(), 1 as u64));
        assert!(!log.check_committable(&msg.info(), 1 as u64));

        let msg = make_msg(
            &PbftMessageType::PrePrepare,
            0,
            1,
            get_peer_id(&cfg, 0),
            get_peer_id(&cfg, 0),
        );
        log.add_message(msg.clone(), &state).unwrap();
        assert!(!log.check_prepared(&msg.info(), 1 as u64));
        assert!(!log.check_committable(&msg.info(), 1 as u64));

        for peer in 0..4 {
            let msg = make_msg(
                &PbftMessageType::Prepare,
                0,
                1,
                get_peer_id(&cfg, peer),
                get_peer_id(&cfg, 0),
            );

            log.add_message(msg.clone(), &state).unwrap();
            if peer < 2 {
                assert!(!log.check_prepared(&msg.info(), 1 as u64));
                assert!(!log.check_committable(&msg.info(), 1 as u64));
            } else {
                assert!(log.check_prepared(&msg.info(), 1 as u64));
                assert!(!log.check_committable(&msg.info(), 1 as u64));
            }
        }

        for peer in 0..4 {
            let msg = make_msg(
                &PbftMessageType::Commit,
                0,
                1,
                get_peer_id(&cfg, peer),
                get_peer_id(&cfg, 0),
            );

            log.add_message(msg.clone(), &state).unwrap();
            if peer < 2 {
                assert!(!log.check_committable(&msg.info(), 1 as u64));
            } else {
                assert!(log.check_committable(&msg.info(), 1 as u64));
            }
        }
    }

    /// Make sure that log garbage collection works as expected
    /// (All messages up to, but not including, the previous sequence number are deleted)
    #[test]
    fn garbage_collection() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);
        let state = PbftState::new(vec![], 0, &cfg);

        for seq in 1..5 {
            let msg = make_msg(
                &PbftMessageType::BlockNew,
                0,
                seq,
                get_peer_id(&cfg, 0),
                get_peer_id(&cfg, 0),
            );
            log.add_message(msg.clone(), &state).unwrap();

            let msg = make_msg(
                &PbftMessageType::PrePrepare,
                0,
                seq,
                get_peer_id(&cfg, 0),
                get_peer_id(&cfg, 0),
            );
            log.add_message(msg.clone(), &state).unwrap();

            for peer in 0..4 {
                let msg = make_msg(
                    &PbftMessageType::Prepare,
                    0,
                    seq,
                    get_peer_id(&cfg, peer),
                    get_peer_id(&cfg, 0),
                );

                log.add_message(msg.clone(), &state).unwrap();
            }

            for peer in 0..4 {
                let msg = make_msg(
                    &PbftMessageType::Commit,
                    0,
                    seq,
                    get_peer_id(&cfg, peer),
                    get_peer_id(&cfg, 0),
                );

                log.add_message(msg.clone(), &state).unwrap();
            }
        }

        log.max_log_size = 20;
        log.garbage_collect(5, &BlockId::new());

        for old in 1..3 {
            for msg_type in &[
                PbftMessageType::BlockNew,
                PbftMessageType::PrePrepare,
                PbftMessageType::Prepare,
                PbftMessageType::Commit,
            ] {
                assert_eq!(
                    log.get_messages_of_type_seq_view(&msg_type, old, 0).len(),
                    0
                );
            }
        }

        for msg_type in &[PbftMessageType::BlockNew, PbftMessageType::PrePrepare] {
            assert_eq!(log.get_messages_of_type_seq_view(&msg_type, 4, 0).len(), 1);
        }

        for msg_type in &[PbftMessageType::Prepare, PbftMessageType::Commit] {
            assert_eq!(log.get_messages_of_type_seq_view(&msg_type, 4, 0).len(), 4);
        }
    }
}
