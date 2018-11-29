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
#![allow(unknown_lints, derive_hash_xor_eq)]

use std::fmt;
use std::hash::{Hash, Hasher};

use hex;

use message_type::PbftMessageType;
use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

impl Eq for PbftMessage {}
impl Eq for PbftViewChange {}

impl Hash for PbftMessageInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_msg_type().hash(state);
        self.get_view().hash(state);
        self.get_seq_num().hash(state);
        self.get_signer_id().hash(state);
    }
}

impl Hash for PbftBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_block_id().hash(state);
        self.get_block_num().hash(state);
        self.get_summary().hash(state);
        self.get_signer_id().hash(state);
    }
}

impl Hash for PbftMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_info().hash(state);
        self.get_block().hash(state);
    }
}

impl Hash for PbftViewChange {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_info().hash(state);
        for msg in self.get_checkpoint_messages().iter() {
            msg.get_info().hash(state);
            msg.get_block().hash(state);
        }
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
            &hex::encode(self.get_signer_id())[..6],
        )
    }
}
