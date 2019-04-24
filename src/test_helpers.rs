/*
 * Copyright 2019 Cargill Incorporated
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

//! Helper functions used by unit tests

use crate::config::PbftConfig;
use crate::message_type::{ParsedMessage, PbftMessageType};
use crate::protos::pbft_message::{PbftMessage, PbftMessageInfo};
use sawtooth_sdk::consensus::engine::{Block, BlockId, PeerId};

/// Create a mock configuration given a number of nodes
pub fn mock_config(num_nodes: u8) -> PbftConfig {
    let mut config = PbftConfig::default();
    config.members = (0..num_nodes).map(|id| vec![id as u8]).collect();
    config
}

/// Create a Block for the given block number
pub fn mock_block(num: u8) -> Block {
    let previous_id = if num == 0 { vec![] } else { vec![num - 1] };

    Block {
        block_id: vec![num],
        previous_id,
        signer_id: PeerId::from(vec![]),
        block_num: num as u64,
        payload: vec![],
        summary: vec![],
    }
}

/// Create a PbftMessage
pub fn mock_msg(
    msg_type: PbftMessageType,
    view: u64,
    seq_num: u64,
    signer_id: PeerId,
    block_id: BlockId,
    from_self: bool,
) -> ParsedMessage {
    let info = PbftMessageInfo::new_from(msg_type, view, seq_num, signer_id);
    let mut msg = PbftMessage::new();
    msg.set_info(info);
    msg.set_block_id(block_id);

    let mut parsed = ParsedMessage::from_pbft_message(msg).expect("Failed to parse PbftMessage");
    parsed.from_self = from_self;
    parsed
}
