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
use sawtooth_sdk::consensus::engine::Block;

use config::PbftConfig;
use error::PbftError;
use message_type::{ParsedMessage, PbftHint, PbftMessageType};
use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

/// The log keeps track of the last stable checkpoint
#[derive(Clone)]
pub struct PbftStableCheckpoint {
    pub seq_num: u64,
    pub checkpoint_messages: Vec<PbftMessage>,
}

/// Struct for storing messages that a PbftNode receives
pub struct PbftLog {
    /// Generic messages (BlockNew, PrePrepare, Prepare, Commit, Checkpoint)
    messages: HashSet<ParsedMessage>,

    /// View change messages
    view_changes: HashSet<PbftViewChange>,

    /// Watermarks (minimum/maximum sequence numbers)
    /// Ensure that log does not get too large
    low_water_mark: u64,
    high_water_mark: u64,

    /// Maximum log size, defined from on-chain settings
    max_log_size: u64,

    /// How many cycles through the algorithm we've done (BlockNew messages)
    cycles: u64,

    /// How many cycles in between checkpoints
    checkpoint_period: u64,

    /// Backlog of messages (from peers) with sender's ID
    backlog: VecDeque<ParsedMessage>,

    /// Backlog of blocks (from BlockNews messages)
    block_backlog: VecDeque<Block>,

    /// The most recent checkpoint that contains proof
    pub latest_stable_checkpoint: Option<PbftStableCheckpoint>,
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_infos: Vec<PbftMessageInfo> = self
            .messages
            .iter()
            .map(|ref msg| msg.info().clone())
            .chain(
                self.view_changes
                    .iter()
                    .map(|ref msg| msg.get_info().clone()),
            ).collect();
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
            }).collect();

        write!(
            f,
            "\nPbftLog ({}, {}):\n{}",
            self.low_water_mark,
            self.high_water_mark,
            string_infos.join("\n")
        )
    }
}

fn check_msg_has_type(pbft_message: &ParsedMessage, check_type: &PbftMessageType) -> bool {
    pbft_message.info().get_msg_type() != String::from(check_type)
}

impl PbftLog {
    pub fn new(config: &PbftConfig) -> Self {
        PbftLog {
            messages: HashSet::new(),
            view_changes: HashSet::new(),
            low_water_mark: 0,
            cycles: 0,
            checkpoint_period: config.checkpoint_period,
            high_water_mark: config.max_log_size,
            max_log_size: config.max_log_size,
            backlog: VecDeque::new(),
            block_backlog: VecDeque::new(),
            latest_stable_checkpoint: None,
        }
    }

    /// `check_prepared` predicate
    /// `check_prepared` is true for this node if the following messages are present in its log:
    ///  + The original `BlockNew` message
    ///  + A `PrePrepare` message matching the original message (in the current view)
    ///  + `2f + 1` matching `Prepare` messages from different nodes that match
    ///    `PrePrepare` message above (including its own)
    pub fn check_prepared(&self, pbft_message: &ParsedMessage, f: u64) -> Result<(), PbftError> {
        if check_msg_has_type(pbft_message, &PbftMessageType::Prepare) {
            return Err(PbftError::NotReadyForMessage);
        }
        let info = pbft_message.info();
        let block_new_msgs = self.check_log_has_one_block_new_msg(info)?;
        let pre_prep_msgs = self.check_log_has_one_pre_prepared_msg(info)?;
        self.check_log_prepare_msgs_match(&block_new_msgs, &pre_prep_msgs, info)?;

        self.check_msg_against_log(&pbft_message, true, 2 * f + 1)?;

        Ok(())
    }

    fn check_log_has_one_block_new_msg(
        &self,
        info: &PbftMessageInfo,
    ) -> Result<Vec<&ParsedMessage>, PbftError> {
        let block_new_msgs = self.get_messages_of_type(
            &PbftMessageType::BlockNew,
            info.get_seq_num(),
            info.get_view(),
        );
        if block_new_msgs.len() != 1 {
            Err(PbftError::WrongNumMessages(
                PbftMessageType::BlockNew,
                1,
                block_new_msgs.len(),
            ))
        } else {
            Ok(block_new_msgs)
        }
    }

    fn check_log_has_one_pre_prepared_msg(
        &self,
        info: &PbftMessageInfo,
    ) -> Result<Vec<&ParsedMessage>, PbftError> {
        let pre_prep_msgs = self.get_messages_of_type(
            &PbftMessageType::PrePrepare,
            info.get_seq_num(),
            info.get_view(),
        );
        if pre_prep_msgs.len() != 1 {
            Err(PbftError::WrongNumMessages(
                PbftMessageType::PrePrepare,
                1,
                pre_prep_msgs.len(),
            ))
        } else {
            Ok(pre_prep_msgs)
        }
    }

    fn check_log_prepare_msgs_match(
        &self,
        block_new_msgs: &[&ParsedMessage],
        pre_prep_msgs: &[&ParsedMessage],
        info: &PbftMessageInfo,
    ) -> Result<(), PbftError> {
        let prep_msgs = self.get_messages_of_type(
            &PbftMessageType::Prepare,
            info.get_seq_num(),
            info.get_view(),
        );
        for prep_msg in prep_msgs {
            // Make sure the contents match
            if (!infos_match(prep_msg.info(), &pre_prep_msgs[0].info())
                && prep_msg.get_block() != pre_prep_msgs[0].get_block())
                || (!infos_match(prep_msg.info(), block_new_msgs[0].info())
                    && prep_msg.get_block() != block_new_msgs[0].get_block())
            {
                return Err(PbftError::MessageMismatch(PbftMessageType::Prepare));
            }
        }
        Ok(())
    }

    /// Checks if the node is ready to enter the `Committing` phase based on the `PbftMessage` received
    ///
    /// `check_committable` is true if for this node:
    ///   + `check_prepared` is true
    ///   + This node has accepted `2f + 1` `Commit` messages, including its own
    pub fn check_committable(&self, pbft_message: &ParsedMessage, f: u64) -> Result<(), PbftError> {
        if check_msg_has_type(pbft_message, &PbftMessageType::Commit) {
            return Err(PbftError::NotReadyForMessage);
        }
        self.check_msg_against_log(&pbft_message, true, 2 * f + 1)?;

        self.check_prepared(&pbft_message.as_msg_type(PbftMessageType::Prepare), f)?;
        Ok(())
    }

    /// Check an incoming message against its counterparts in the message log
    pub fn check_msg_against_log(
        &self,
        message: &ParsedMessage,
        check_match: bool,
        num_cutoff: u64,
    ) -> Result<(), PbftError> {
        let info = message.info();
        let msg_type = PbftMessageType::from(info.get_msg_type());

        let msg_infos: Vec<&PbftMessageInfo> =
            self.get_message_infos(&msg_type, info.get_seq_num(), info.get_view());

        let num_cp_msgs = num_unique_signers(&msg_infos);
        if num_cp_msgs < num_cutoff {
            return Err(PbftError::WrongNumMessages(
                msg_type,
                num_cutoff as usize,
                num_cp_msgs as usize,
            ));
        }

        if check_match {
            let non_matches: usize = msg_infos
                .iter()
                .filter(|&m| !infos_match(message.info(), m))
                .count();
            if non_matches > 0 {
                return Err(PbftError::MessageMismatch(msg_type));
            }
        }
        Ok(())
    }

    /// Add a generic PBFT message to the log
    pub fn add_message(&mut self, msg: ParsedMessage) {
        if msg.info().get_seq_num() < self.high_water_mark
            || msg.info().get_seq_num() >= self.low_water_mark
        {
            // If the message wasn't already in the log, increment cycles
            let msg_type = PbftMessageType::from(msg.info().get_msg_type());
            let inserted = self.messages.insert(msg);
            if msg_type == PbftMessageType::BlockNew && inserted {
                self.cycles += 1;
            }
            trace!("{}", self);
        } else {
            warn!(
                "Not adding message with sequence number {}; outside of log bounds ({}, {})",
                msg.info().get_seq_num(),
                self.low_water_mark,
                self.high_water_mark,
            );
        }
    }

    /// Adds a message the (back)log, based on the given `PbftHint`
    ///
    /// Past messages are added to the general message log
    /// Future messages are added to the backlog of messages to handle at a later time
    /// Present messages are ignored, as they're generally added immediately after
    /// this method is called by the calling code, except for `PrePrepare` messages
    #[allow(ptr_arg)]
    pub fn add_message_with_hint(
        &mut self,
        msg: ParsedMessage,
        hint: &PbftHint,
    ) -> Result<(), PbftError> {
        match hint {
            PbftHint::FutureMessage => {
                self.push_backlog(msg);
                Err(PbftError::NotReadyForMessage)
            }
            PbftHint::PastMessage => {
                self.add_message(msg);
                Err(PbftError::NotReadyForMessage)
            }
            PbftHint::PresentMessage => Ok(()),
        }
    }

    /// Obtain messages from the log that match a given type, sequence number, and view
    pub fn get_messages_of_type(
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
            }).collect()
    }

    /// Obtain message information objects from the log that match a given type, sequence number,
    /// and view
    pub fn get_message_infos(
        &self,
        msg_type: &PbftMessageType,
        sequence_number: u64,
        view: u64,
    ) -> Vec<&PbftMessageInfo> {
        let mut infos = vec![];
        for msg in &self.messages {
            let info = msg.info();
            if info.get_msg_type() == String::from(msg_type)
                && info.get_seq_num() == sequence_number
                && info.get_view() == view
            {
                infos.push(info);
            }
        }
        for msg in &self.view_changes {
            let info = msg.get_info();
            if info.get_msg_type() == String::from(msg_type)
                && info.get_seq_num() == sequence_number
                && info.get_view() == view
            {
                infos.push(info);
            }
        }
        infos
    }

    /// Fix sequence numbers of generic PBFT messages that are defaulted to zero
    /// This is used to fix the `BlockNew` messages in secondary nodes, once they receive a
    /// `PrePrepare` message with the proper sequence number.
    pub fn fix_seq_nums(
        &mut self,
        msg_type: &PbftMessageType,
        new_sequence_number: u64,
        view: u64,
        block: &PbftBlock,
    ) -> usize {
        #[allow(map_clone)]
        let zero_seq_msgs: Vec<ParsedMessage> = self
            .get_messages_of_type(msg_type, 0, view)
            .iter()
            .map(|&msg| msg.clone())
            .collect();

        for m in &zero_seq_msgs {
            self.messages.remove(m);
        }

        let mut fixed_msgs = Vec::<ParsedMessage>::new();
        for mut m in zero_seq_msgs {
            if m.info().get_msg_type() == String::from(msg_type)
                && m.info().get_seq_num() == 0
                && m.get_block().get_block_id() == block.get_block_id()
            {
                let mut info: PbftMessageInfo = m.info().clone();
                let mut new_msg = m.clone();
                info.set_seq_num(new_sequence_number);
                *new_msg.info_mut() = info;
                fixed_msgs.push(new_msg.clone());
            }
        }

        let changed_msgs = fixed_msgs.len();
        for m in fixed_msgs {
            self.messages.insert(m);
        }
        changed_msgs
    }

    /// Add a `ViewChange` message to the log
    pub fn add_view_change(&mut self, vc: PbftViewChange) {
        self.view_changes.insert(vc);
    }

    /// Get the latest stable checkpoint
    pub fn get_latest_checkpoint(&self) -> u64 {
        if let Some(ref cp) = self.latest_stable_checkpoint {
            cp.seq_num
        } else {
            0
        }
    }

    /// Is this node ready for a checkpoint?
    pub fn at_checkpoint(&self) -> bool {
        self.cycles >= self.checkpoint_period
    }

    /// Garbage collect the log, and create a stable checkpoint
    pub fn garbage_collect(&mut self, stable_checkpoint: u64, view: u64) {
        self.low_water_mark = stable_checkpoint;
        self.high_water_mark = self.low_water_mark + self.max_log_size;
        self.cycles = 0;

        // Update the stable checkpoint
        #[allow(map_clone)]
        let cp_msgs: Vec<PbftMessage> = self
            .get_messages_of_type(&PbftMessageType::Checkpoint, stable_checkpoint, view)
            .iter()
            .map(|&cp| cp.get_pbft_message().clone())
            .collect();
        let cp = PbftStableCheckpoint {
            seq_num: stable_checkpoint,
            checkpoint_messages: cp_msgs,
        };
        self.latest_stable_checkpoint = Some(cp);

        // Garbage collect logs, filter out all old messages (up to but not including the
        // checkpoint)
        self.messages = self
            .messages
            .iter()
            .filter(|ref msg| {
                let seq_num = msg.info().get_seq_num();
                seq_num >= self.get_latest_checkpoint() && seq_num > 0
            }).cloned()
            .collect();
        self.view_changes = self
            .view_changes
            .iter()
            .filter(|ref msg| {
                let seq_num = msg.get_info().get_seq_num();
                seq_num >= self.get_latest_checkpoint() && seq_num > 0
            }).cloned()
            .collect();
    }

    pub fn push_backlog(&mut self, msg: ParsedMessage) {
        self.backlog.push_back(msg);
    }

    pub fn pop_backlog(&mut self) -> Option<ParsedMessage> {
        self.backlog.pop_front()
    }

    pub fn push_block_backlog(&mut self, msg: Block) {
        self.block_backlog.push_back(msg);
    }

    pub fn pop_block_backlog(&mut self) -> Option<Block> {
        self.block_backlog.pop_front()
    }
}

// Make sure messages are all from different nodes
fn num_unique_signers(msg_info_list: &[&PbftMessageInfo]) -> u64 {
    let mut received_from: HashSet<&[u8]> = HashSet::new();
    let mut diff_msgs = 0;
    for info in msg_info_list {
        // If the signer is NOT already in the set
        if received_from.insert(info.get_signer_id()) {
            diff_msgs += 1;
        }
    }
    diff_msgs as u64
}

// Check that the views and sequence numbers of two messages match
fn infos_match(m1: &PbftMessageInfo, m2: &PbftMessageInfo) -> bool {
    m1.get_view() == m2.get_view() && m1.get_seq_num() == m2.get_seq_num()
}

#[cfg(test)]
mod tests {
    use super::*;
    use config;
    use hash::hash_sha256;
    use sawtooth_sdk::consensus::engine::PeerId;

    /// Create a PbftMessage, given its type, view, sequence number, and who it's from
    fn make_msg(
        msg_type: &PbftMessageType,
        view: u64,
        seq_num: u64,
        signer_id: PeerId,
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
        pbft_block.set_signer_id(Vec::<u8>::from(signer_id));
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

        let msg = make_msg(&PbftMessageType::PrePrepare, 0, 1, get_peer_id(&cfg, 0));

        log.add_message(msg.clone());

        let gotten_msgs = log.get_messages_of_type(&PbftMessageType::PrePrepare, 1, 0);

        assert_eq!(gotten_msgs.len(), 1);
        assert_eq!(&msg, gotten_msgs[0]);
    }

    /// Test that `check_prepared` and `check_committable` predicates work properly
    #[test]
    fn prepared_committed() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);

        let msg = make_msg(&PbftMessageType::BlockNew, 0, 1, get_peer_id(&cfg, 1));
        log.add_message(msg.clone());

        assert_eq!(log.cycles, 1);
        assert!(log.check_prepared(&msg, 1 as u64).is_err());
        assert!(log.check_committable(&msg, 1 as u64).is_err());

        let msg = make_msg(&PbftMessageType::PrePrepare, 0, 1, get_peer_id(&cfg, 0));
        log.add_message(msg.clone());
        assert!(log.check_prepared(&msg, 1 as u64).is_err());
        assert!(log.check_committable(&msg, 1 as u64).is_err());

        for peer in 0..4 {
            let msg = make_msg(&PbftMessageType::Prepare, 0, 1, get_peer_id(&cfg, peer));

            log.add_message(msg.clone());
            if peer < 2 {
                assert!(log.check_prepared(&msg, 1 as u64).is_err());
                assert!(log.check_committable(&msg, 1 as u64).is_err());
            } else {
                assert!(log.check_prepared(&msg, 1 as u64).is_ok());
                assert!(log.check_committable(&msg, 1 as u64).is_err());
            }
        }

        for peer in 0..4 {
            let msg = make_msg(&PbftMessageType::Commit, 0, 1, get_peer_id(&cfg, peer));

            log.add_message(msg.clone());
            if peer < 2 {
                assert!(log.check_committable(&msg, 1 as u64).is_err());
            } else {
                assert!(log.check_committable(&msg, 1 as u64).is_ok());
            }
        }
    }

    /// Test that sequence number adjustments work as expected
    /// (This is used by secondary nodes to adjust the sequence number of their `BlockNew`, when
    /// they receive a `PrePrepare` from the primary)
    #[test]
    fn fix_seq_nums() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);

        let msg0 = make_msg(&PbftMessageType::BlockNew, 0, 0, get_peer_id(&cfg, 1));
        log.add_message(msg0.clone());

        let msg = make_msg(&PbftMessageType::PrePrepare, 0, 1, get_peer_id(&cfg, 0));
        log.add_message(msg.clone());

        let num_updated = log.fix_seq_nums(&PbftMessageType::BlockNew, 1, 0, msg0.get_block());

        assert_eq!(num_updated, 1);
    }

    /// Make sure that the log doesn't start out checkpointing
    #[test]
    fn checkpoint_basics() {
        let cfg = config::mock_config(4);
        let log = PbftLog::new(&cfg);

        assert_eq!(log.get_latest_checkpoint(), 0);
        assert!(!log.at_checkpoint());
    }

    /// Make sure that log garbage collection works as expected
    /// (All messages up to, but not including, the checkpoint are deleted)
    #[test]
    fn garbage_collection() {
        let cfg = config::mock_config(4);
        let mut log = PbftLog::new(&cfg);

        for seq in 1..5 {
            let msg = make_msg(&PbftMessageType::BlockNew, 0, seq, get_peer_id(&cfg, 1));
            log.add_message(msg.clone());

            let msg = make_msg(&PbftMessageType::PrePrepare, 0, seq, get_peer_id(&cfg, 0));
            log.add_message(msg.clone());

            for peer in 0..4 {
                let msg = make_msg(&PbftMessageType::Prepare, 0, seq, get_peer_id(&cfg, peer));

                log.add_message(msg.clone());
            }

            for peer in 0..4 {
                let msg = make_msg(&PbftMessageType::Commit, 0, seq, get_peer_id(&cfg, peer));

                log.add_message(msg.clone());
            }
        }

        for peer in 0..4 {
            let msg = make_msg(&PbftMessageType::Checkpoint, 0, 4, get_peer_id(&cfg, peer));

            log.add_message(msg.clone());
        }

        log.garbage_collect(4, 0);

        for old in 1..3 {
            for msg_type in &[
                PbftMessageType::BlockNew,
                PbftMessageType::PrePrepare,
                PbftMessageType::Prepare,
                PbftMessageType::Commit,
            ] {
                assert_eq!(log.get_messages_of_type(&msg_type, old, 0).len(), 0);
            }
        }

        for msg_type in &[PbftMessageType::BlockNew, PbftMessageType::PrePrepare] {
            assert_eq!(log.get_messages_of_type(&msg_type, 4, 0).len(), 1);
        }

        for msg_type in &[PbftMessageType::Prepare, PbftMessageType::Commit] {
            assert_eq!(log.get_messages_of_type(&msg_type, 4, 0).len(), 4);
        }
    }
}
