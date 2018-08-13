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

use std::collections::{HashSet, VecDeque};
use std::fmt;

use hex;

use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

use sawtooth_sdk::consensus::engine::{Block, PeerMessage};

use config::PbftConfig;
use error::PbftError;
use message_extensions::PbftGetInfo;
use message_type::PbftMessageType;

// The log keeps track of the last stable checkpoint
#[derive(Clone)]
pub struct PbftStableCheckpoint {
    pub seq_num: u64,
    pub checkpoint_messages: Vec<PbftMessage>,
}

// Struct for storing messages that a PbftNode receives
pub struct PbftLog {
    // Generic messages (BlockNew, PrePrepare, Prepare, Commit, CommitFinal, Checkpoint)
    messages: HashSet<PbftMessage>,

    // View change related messages
    view_changes: HashSet<PbftViewChange>,

    // Watermarks (minimum/maximum sequence numbers)
    // Ensures log does not get too large
    low_water_mark: u64,
    high_water_mark: u64,

    // Maximum log size, defined from on-chain settings
    max_log_size: u64,

    // How many cycles through the algorithm we've done (BlockNew messages)
    cycles: u64,

    // How many cycles in between checkpoints
    checkpoint_period: u64,

    // Backlog of messages (from peers) and blocks (from BlockNews)
    backlog: VecDeque<PeerMessage>,
    block_backlog: VecDeque<Block>,

    // The most recent checkpoint that contains proof
    pub latest_stable_checkpoint: Option<PbftStableCheckpoint>,
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_infos: Vec<PbftMessageInfo> = self
            .messages
            .iter()
            .map(|ref msg| msg.get_info().clone())
            .chain(
                self.view_changes
                    .iter()
                    .map(|ref msg| msg.get_info().clone()),
            )
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

        write!(
            f,
            "\nPbftLog ({}, {}):\n{}",
            self.low_water_mark,
            self.high_water_mark,
            string_infos.join("\n")
        )
    }
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

    // ---------- Methods to check a message against the log ----------
    // "prepared" predicate
    pub fn prepared(&self, deser_msg: &PbftMessage, f: u64) -> Result<(), PbftError> {
        if deser_msg.get_info().get_msg_type() != String::from(&PbftMessageType::Prepare) {
            return Err(PbftError::NotReadyForMessage);
        }
        let info = deser_msg.get_info();
        let block_new_msgs = self.get_messages_of_type(
            &PbftMessageType::BlockNew,
            info.get_seq_num(),
            info.get_view(),
        );
        if block_new_msgs.len() != 1 {
            return Err(PbftError::WrongNumMessages(
                PbftMessageType::BlockNew,
                1,
                block_new_msgs.len(),
            ));
        }

        let pre_prep_msgs = self.get_messages_of_type(
            &PbftMessageType::PrePrepare,
            info.get_seq_num(),
            info.get_view(),
        );
        if pre_prep_msgs.len() != 1 {
            return Err(PbftError::WrongNumMessages(
                PbftMessageType::PrePrepare,
                1,
                pre_prep_msgs.len(),
            ));
        }

        let prep_msgs = self.get_messages_of_type(
            &PbftMessageType::Prepare,
            info.get_seq_num(),
            info.get_view(),
        );
        for prep_msg in &prep_msgs {
            // Make sure the contents match
            if (!infos_match(prep_msg.get_info(), &pre_prep_msgs[0].get_info())
                && prep_msg.get_block() != pre_prep_msgs[0].get_block())
                || (!infos_match(prep_msg.get_info(), block_new_msgs[0].get_info())
                    && prep_msg.get_block() != block_new_msgs[0].get_block())
            {
                return Err(PbftError::MessageMismatch(PbftMessageType::Prepare));
            }
        }

        self.check_msg_against_log(&deser_msg, true, 2 * f + 1)?;

        Ok(())
    }

    // "committed" predicate
    pub fn committed(&self, deser_msg: &PbftMessage, f: u64) -> Result<(), PbftError> {
        if deser_msg.get_info().get_msg_type() != String::from(&PbftMessageType::Commit) {
            return Err(PbftError::NotReadyForMessage);
        }
        self.check_msg_against_log(&deser_msg, true, 2 * f + 1)?;

        let mut prep_msg = deser_msg.clone();
        let mut info = prep_msg.get_info().clone();
        info.set_msg_type(String::from(&PbftMessageType::Prepare));
        prep_msg.set_info(info);
        self.prepared(&prep_msg, f)?;
        Ok(())
    }

    // Check an incoming message against its counterparts in the message log
    pub fn check_msg_against_log<'a, T: PbftGetInfo<'a>>(
        &self,
        message: &'a T,
        check_match: bool,
        num_cutoff: u64,
    ) -> Result<(), PbftError> {
        let msg_type = PbftMessageType::from(message.get_msg_info().get_msg_type());

        let msg_infos: Vec<&PbftMessageInfo> = self.get_message_infos(
            &msg_type,
            message.get_msg_info().get_seq_num(),
            message.get_msg_info().get_view(),
        );

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
                .filter(|&m| !infos_match(message.get_msg_info(), m))
                .count();
            if non_matches > 0 {
                return Err(PbftError::MessageMismatch(msg_type));
            }
        }
        Ok(())
    }

    // Methods for dealing with PbftMessages
    pub fn add_message(&mut self, msg: PbftMessage) {
        if msg.get_info().get_seq_num() < self.high_water_mark
            || msg.get_info().get_seq_num() >= self.low_water_mark
        {
            // If the message wasn't already in the log, increment cycles
            let msg_type = PbftMessageType::from(msg.get_info().get_msg_type());
            let inserted = self.messages.insert(msg);
            if msg_type == PbftMessageType::BlockNew && inserted {
                self.cycles += 1;
            }
            trace!("{}", self);
        } else {
            warn!(
                "Not adding message with sequence number {}; outside of log bounds ({}, {})",
                msg.get_info().get_seq_num(),
                self.low_water_mark,
                self.high_water_mark,
            );
        }
    }

    pub fn get_messages_of_type(
        &self,
        msg_type: &PbftMessageType,
        sequence_number: u64,
        view: u64,
    ) -> Vec<&PbftMessage> {
        self.messages
            .iter()
            .filter(|&msg| {
                let info = (*msg).get_info();
                info.get_msg_type() == String::from(msg_type)
                    && info.get_seq_num() == sequence_number
                    && info.get_view() == view
            })
            .collect()
    }

    pub fn get_message_infos(
        &self,
        msg_type: &PbftMessageType,
        sequence_number: u64,
        view: u64,
    ) -> Vec<&PbftMessageInfo> {
        let mut infos = vec![];
        for msg in &self.messages {
            let info = msg.get_info();
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

    // Fix sequence numbers of generic messages that are defaulted to zero
    pub fn fix_seq_nums(
        &mut self,
        msg_type: &PbftMessageType,
        new_sequence_number: u64,
        view: u64,
        block: &PbftBlock,
    ) -> usize {
        let zero_seq_msgs: Vec<PbftMessage> = self
            .get_messages_of_type(msg_type, 0, view)
            .iter()
            .map(|&msg| msg.clone())
            .collect();

        for m in &zero_seq_msgs {
            self.messages.remove(m);
        }

        let mut fixed_msgs = Vec::<PbftMessage>::new();
        for mut m in zero_seq_msgs {
            if m.get_info().get_msg_type() == String::from(msg_type)
                && m.get_info().get_seq_num() == 0
                && m.get_block().get_block_id() == block.get_block_id()
            {
                let mut info: PbftMessageInfo = m.get_info().clone();
                let mut new_msg = m.clone();
                info.set_seq_num(new_sequence_number);
                new_msg.set_info(info);
                fixed_msgs.push(new_msg.clone());
            }
        }

        let changed_msgs = fixed_msgs.len();
        for m in fixed_msgs {
            self.messages.insert(m);
        }
        changed_msgs
    }

    // Methods for dealing with PbftViewChanges
    pub fn add_view_change(&mut self, vc: PbftViewChange) {
        self.view_changes.insert(vc);
    }

    // Get the latest stable checkpoint
    pub fn get_latest_checkpoint(&self) -> u64 {
        if let Some(ref cp) = self.latest_stable_checkpoint {
            cp.seq_num
        } else {
            0
        }
    }

    // Is this node ready for a checkpoint?
    pub fn at_checkpoint(&self) -> bool {
        self.cycles >= self.checkpoint_period
    }

    // Garbage collect the log, and create a stable checkpoint
    pub fn garbage_collect(&mut self, stable_checkpoint: u64, view: u64) {
        self.low_water_mark = stable_checkpoint;
        self.high_water_mark = self.low_water_mark + self.max_log_size;
        self.cycles = 0;

        // Update the stable checkpoint
        let cp_msgs: Vec<PbftMessage> = self
            .get_messages_of_type(&PbftMessageType::Checkpoint, stable_checkpoint, view)
            .iter()
            .map(|&cp| cp.clone())
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
                let seq_num = msg.get_info().get_seq_num();
                seq_num >= self.get_latest_checkpoint() && seq_num > 0
            })
            .cloned()
            .collect();
        self.view_changes = self
            .view_changes
            .iter()
            .filter(|ref msg| {
                let seq_num = msg.get_info().get_seq_num();
                seq_num >= self.get_latest_checkpoint() && seq_num > 0
            })
            .cloned()
            .collect();
    }

    pub fn push_backlog(&mut self, msg: PeerMessage) {
        self.backlog.push_back(msg);
    }

    pub fn pop_backlog(&mut self) -> Option<PeerMessage> {
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
