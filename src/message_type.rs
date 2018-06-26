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

// Messages related to PBFT consensus
#[derive(Debug, PartialEq, PartialOrd)]
pub enum PbftMessageType {
    Unset,

    // Basic message types for the multicast protocol
    PrePrepare,
    Prepare,
    Commit,
    CommitFinal,

    // Auxiliary PBFT messages
    BlockNew,
    Checkpoint,
    ViewChange,
    NewView,
}

impl<'a> From<&'a str> for PbftMessageType {
    fn from(s: &'a str) -> Self {
        match s {
            "PrePrepare" => PbftMessageType::PrePrepare,
            "Prepare" => PbftMessageType::Prepare,
            "Commit" => PbftMessageType::Commit,
            "CommitFinal" => PbftMessageType::CommitFinal,
            "BlockNew" => PbftMessageType::BlockNew,
            "ViewChange" => PbftMessageType::ViewChange,
            "NewView" => PbftMessageType::NewView,
            "Checkpoint" => PbftMessageType::Checkpoint,
            _ => {
                warn!("Unhandled multicast message type: {}", s);
                PbftMessageType::Unset
            }
        }
    }
}

impl<'a> From<&'a PbftMessageType> for String {
    fn from(mc_type: &'a PbftMessageType) -> String {
        format!("{:?}", mc_type)
    }
}
