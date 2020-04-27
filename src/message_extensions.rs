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

//! Extensions for the Protobuf-defined message types

// We know that the property `k1 == k2 ==>  hash(k1) == hash(k2)` holds, since protobuf just compares
// every field in the struct and that's exactly what the implementation of Hash is doing below
#![allow(unknown_lints, clippy::derive_hash_xor_eq)]

use std::fmt;
use std::hash::{Hash, Hasher};

use sawtooth_sdk::consensus::engine::PeerId;
use sawtooth_sdk::messages::consensus::ConsensusPeerMessageHeader;

use crate::message_type::PbftMessageType;
use crate::protos::pbft_message::{
    PbftMessage, PbftMessageInfo, PbftNewView, PbftSeal, PbftSignedVote,
};

impl Eq for PbftMessage {}
impl Eq for PbftSeal {}
impl Eq for PbftNewView {}

impl Hash for PbftMessageInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_msg_type().hash(state);
        self.get_view().hash(state);
        self.get_seq_num().hash(state);
        self.get_signer_id().hash(state);
    }
}

impl Hash for PbftMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_info().hash(state);
        self.get_block_id().hash(state);
    }
}

impl Hash for PbftSeal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_info().hash(state);
        self.get_block_id().hash(state);
        for vote in self.get_commit_votes() {
            vote.hash(state);
        }
    }
}

impl Hash for PbftSignedVote {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_header_bytes().hash(state);
        self.get_header_signature().hash(state);
        self.get_message_bytes().hash(state);
    }
}

impl Hash for PbftNewView {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_info().hash(state);
        self.get_view_changes().hash(state);
    }
}

impl fmt::Display for PbftMessageInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MsgInfo ({} S {} V {} <- {})",
            PbftMessageType::from(self.get_msg_type()),
            self.get_seq_num(),
            self.get_view(),
            &hex::encode(self.get_signer_id()),
        )
    }
}

impl fmt::Display for PbftSeal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let votes = self
            .get_commit_votes()
            .iter()
            .fold(String::new(), |acc, vote| format!("{}{}, ", acc, vote));
        write!(
            f,
            "PbftSeal(info: {}, block_id: {}, votes: {})",
            self.get_info(),
            hex::encode(self.get_block_id()),
            votes,
        )
    }
}

impl fmt::Display for PbftSignedVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PbftSignedVote(header: {:?}, message: {:?}, header_bytes: {}, header_signature: {}, \
             message_bytes: {})",
            protobuf::parse_from_bytes::<ConsensusPeerMessageHeader>(self.get_header_bytes())
                .map_err(|_| fmt::Error)?,
            protobuf::parse_from_bytes::<PbftMessage>(self.get_message_bytes())
                .map_err(|_| fmt::Error)?,
            hex::encode(self.get_header_bytes()),
            hex::encode(self.get_header_signature()),
            hex::encode(self.get_message_bytes()),
        )
    }
}

impl PbftMessageInfo {
    pub fn new_from(msg_type: PbftMessageType, view: u64, seq_num: u64, signer_id: PeerId) -> Self {
        let mut info = PbftMessageInfo::new();
        info.set_msg_type(String::from(msg_type));
        info.set_view(view);
        info.set_seq_num(seq_num);
        info.set_signer_id(signer_id);
        info
    }
}
