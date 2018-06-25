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

use protos::pbft_message::{PbftMessage, PbftNewView, PbftViewChange};
use std::error::Error;
use std::fmt;

use hex;

#[derive(Debug)]
pub struct PbftLogError;

impl Error for PbftLogError {
    // TODO: Fill this out
    fn description(&self) -> &str {
        "Log error"
    }
}

impl fmt::Display for PbftLogError {
    // TODO: Fill this out
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

pub struct PbftLog {
    messages: Vec<PbftMessage>,
    view_changes: Vec<PbftViewChange>,
    new_views: Vec<PbftNewView>,
}

impl fmt::Display for PbftLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg_string_vec: Vec<String> = self.messages
            .iter()
            .map(|msg: &PbftMessage| -> String {
                let info = msg.get_info();
                let block = msg.get_block();
                format!(
                    "    {{ {}, view: {}, seq: {} }}
        block_num: {}
        block_id: {}
        signer: {}",
                    info.get_msg_type(),
                    info.get_view(),
                    info.get_seq_num(),
                    block.get_block_num(),
                    hex::encode(block.get_block_id()),
                    hex::encode(block.get_signer_id()),
                )
            })
            .collect();
        write!(f, "\nPbftLog:\n{}", msg_string_vec.join("\n"))
    }
}

impl PbftLog {
    pub fn new() -> Self {
        PbftLog {
            messages: vec![],
            view_changes: vec![],
            new_views: vec![],
        }
    }

    // Methods for dealing with PbftMessages
    pub fn add_message(&mut self, msg: PbftMessage) -> Result<(), PbftLogError> {
        self.messages.push(msg);
        Ok(())
    }

    pub fn get_messages_of_type(
        &self,
        msg_type: &str,
        sequence_number: u64,
    ) -> Result<Vec<&PbftMessage>, PbftLogError> {
        let msgs: Vec<&PbftMessage> = self.messages
            .iter()
            .filter(|&msg| {
                (*msg).get_info().get_msg_type() == msg_type
                    && (*msg).get_info().get_seq_num() == sequence_number
            })
            .collect();
        Ok(msgs)
    }

    // Methods for dealing with PbftViewChanges
    pub fn add_view_change(&mut self, vc: PbftViewChange) -> Result<(), PbftLogError> {
        self.view_changes.push(vc);
        Ok(())
    }

    pub fn get_view_change(&self, sequence_number: u64) -> Result<Vec<&PbftMessage>, PbftLogError> {
        let msgs: Vec<&PbftMessage> = self.messages
            .iter()
            .filter(|&msg| (*msg).get_info().get_seq_num() == sequence_number)
            .collect();
        Ok(msgs)
    }

    // Methods for dealing with PbftNewViews
    pub fn add_new_view(&mut self, vc: PbftViewChange) -> Result<(), PbftLogError> {
        self.view_changes.push(vc);
        Ok(())
    }

    pub fn get_new_view(&self, sequence_number: u64) -> Result<Vec<&PbftMessage>, PbftLogError> {
        let msgs: Vec<&PbftMessage> = self.messages
            .iter()
            .filter(|&msg| (*msg).get_info().get_seq_num() == sequence_number)
            .collect();
        Ok(msgs)
    }
}
