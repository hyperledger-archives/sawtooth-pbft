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

use std::fmt;

use protos::pbft_message::{PbftMessage, PbftNewView, PbftViewChange};

use hex;

use config::PbftConfig;
use message_type::PbftMessageType;

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
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_string_vec: Vec<String> = self.view_changes
            .iter()
            .map(|msg: &PbftViewChange| -> String {
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
            high_water_mark: config.max_log_size,
            max_log_size: config.max_log_size,
        }
    }

    // Methods for dealing with PbftMessages
    pub fn add_message(&mut self, msg: PbftMessage) {
        if msg.get_info().get_seq_num() < self.high_water_mark
            || msg.get_info().get_seq_num() >= self.low_water_mark
        {
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
    ) -> Vec<&PbftMessage> {
        self.messages
            .iter()
            .filter(|&msg| {
                (*msg).get_info().get_msg_type() == String::from(msg_type)
                    && (*msg).get_info().get_seq_num() == sequence_number
            })
            .collect()
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

    pub fn get_view_change(&self, sequence_number: u64) -> Vec<&PbftViewChange> {
        self.view_changes
            .iter()
            .filter(|&msg| (*msg).get_info().get_seq_num() == sequence_number)
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
}
