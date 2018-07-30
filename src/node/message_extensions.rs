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

use std::hash::{Hash, Hasher};

use protos::pbft_message::{PbftMessage, PbftMessageInfo, PbftViewChange};

// All message types that have "info" inside of them
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

impl Eq for PbftMessage {  }
impl Eq for PbftViewChange {  }

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
    }
}

impl Hash for PbftViewChange {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_info().hash(state);
    }
}
