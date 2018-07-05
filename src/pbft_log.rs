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

use std::collections::VecDeque;
use std::fmt;

use hex;

use protos::pbft_message::{PbftMessage, PbftMessageInfo, PbftNewView, PbftViewChange};

use sawtooth_sdk::consensus::engine::PeerMessage;

use config::PbftConfig;
use message_type::PbftMessageType;

// TODO: move this somewhere else
// State keeps track of the last stable checkpoint
pub struct PbftStableCheckpoint {
    pub seq_num: u64,
    pub checkpoint_messages: Vec<PbftMessage>,
}

// TODO: Put these somewhere else
pub trait PbftGetInfo<'a> {
    fn get_msg_info(&self) -> &'a PbftMessageInfo;
}

impl<'a> PbftGetInfo<'a> for &'a PbftMessage {
    fn get_msg_info(&self) -> &'a PbftMessageInfo {
        self.get_info()
    }
}

impl<'a> PbftGetInfo<'a> for &'a PbftViewChange {
    fn get_msg_info(&self) -> &'a PbftMessageInfo {
        self.get_info()
    }
}

// Struct for storing messages that a PbftNode receives
pub struct PbftLog {
    // Generic messages (BlockNew, PrePrepare, Prepare, Commit, CommitFinal, Checkpoint)
    messages: Vec<PbftMessage>,

    // View change related messages
    view_changes: Vec<PbftViewChange>,
    new_views: Vec<PbftNewView>,

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

    // Unread messages
    unreads: VecDeque<PeerMessage>,

    // The most recent checkpoint that contains proof
    pub latest_stable_checkpoint: Option<PbftStableCheckpoint>,
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_string_vec: Vec<String> = self.messages
            .iter()
            .map(|msg: &PbftMessage| -> String {
                let info = msg.get_info();
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
            msg_string_vec.join("\n")
        )
    }
}

impl PbftLog {
    pub fn new(config: &PbftConfig) -> Self {
        PbftLog {
            messages: vec![],
            view_changes: vec![],
            new_views: vec![],
            low_water_mark: 0,
            cycles: 0,
            checkpoint_period: config.checkpoint_period,
            high_water_mark: config.max_log_size,
            max_log_size: config.max_log_size,
            unreads: VecDeque::new(),
            latest_stable_checkpoint: None,
        }
    }

    // Methods for dealing with PbftMessages
    pub fn add_message(&mut self, msg: PbftMessage) {
        if msg.get_info().get_seq_num() < self.high_water_mark
            || msg.get_info().get_seq_num() >= self.low_water_mark
        {
            if PbftMessageType::from(msg.get_info().get_msg_type()) == PbftMessageType::BlockNew {
                self.cycles += 1;
            }
            self.messages.push(msg);
            debug!("{}", self);
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
        for msg in self.messages.iter() {
            let info = msg.get_info();
            if info.get_msg_type() == String::from(msg_type)
                && info.get_seq_num() == sequence_number && info.get_view() == view
            {
                infos.push(info);
            }
        }
        for msg in self.view_changes.iter() {
            let info = msg.get_info();
            if info.get_msg_type() == String::from(msg_type)
                && info.get_seq_num() == sequence_number && info.get_view() == view
            {
                infos.push(info);
            }
        }
        infos
    }

    // Fix sequence numbers of generic messages that are defaulted to zero
    pub fn fix_seq_nums(&mut self, msg_type: &PbftMessageType, new_sequence_number: u64) -> usize {
        let mut changed_msgs = 0;
        for m in &mut self.messages {
            let mut info = m.get_info().clone();
            if m.get_info().get_msg_type() == String::from(msg_type)
                && m.get_info().get_seq_num() == 0
            {
                info.set_seq_num(new_sequence_number);
            }
            m.set_info(info);
            changed_msgs += 1;
        }
        changed_msgs
    }

    // Methods for dealing with PbftViewChanges
    pub fn add_view_change(&mut self, vc: PbftViewChange) {
        self.view_changes.push(vc);
    }

    pub fn get_view_change(&self, old_view: u64) -> Vec<&PbftViewChange> {
        self.view_changes
            .iter()
            .filter(|&msg| (*msg).get_info().get_view() == old_view)
            .collect()
    }

    // Methods for dealing with PbftNewViews
    pub fn add_new_view(&mut self, vc: PbftViewChange) {
        self.view_changes.push(vc);
    }

    pub fn get_new_view(&self, sequence_number: u64) -> Vec<&PbftNewView> {
        self.new_views
            .iter()
            .filter(|&msg| (*msg).get_info().get_seq_num() == sequence_number)
            .collect()
    }

    // Is this node ready for a checkpoint?
    pub fn at_checkpoint(&self) -> bool {
        self.cycles > self.checkpoint_period
    }

    // Garbage collect the log, and create a stable checkpoint
    pub fn garbage_collect(&mut self, stable_checkpoint: u64, view: u64) {
        // For now, just update low/high water marks
        self.low_water_mark = stable_checkpoint;
        self.high_water_mark = self.low_water_mark + self.max_log_size;
        self.cycles = 0;

        // Update the stable checkpoint
        let cp_msgs: Vec<PbftMessage> =
            self.get_messages_of_type(&PbftMessageType::Checkpoint, stable_checkpoint, view)
                .iter()
                .map(|&msg| msg.clone())
                .collect();
        let cp = PbftStableCheckpoint {
            seq_num: stable_checkpoint,
            checkpoint_messages: cp_msgs,
        };
        self.latest_stable_checkpoint = Some(cp);
    }

    pub fn push_unread(&mut self, msg: PeerMessage) {
        self.unreads.push_back(msg);
    }

    pub fn pop_unread(&mut self) -> Option<PeerMessage> {
        self.unreads.pop_front()
    }
}
