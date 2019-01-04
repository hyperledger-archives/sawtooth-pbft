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

//! Handlers for individual message types

use std::convert::From;

use hex;
use sawtooth_sdk::consensus::engine::{Block, PeerId};
use sawtooth_sdk::consensus::service::Service;

use crate::error::PbftError;
use crate::message_type::ParsedMessage;
use crate::message_type::PbftMessageType;
use crate::protos::pbft_message::{PbftBlock, PbftMessageInfo};
use crate::state::{PbftPhase, PbftState};

/// Handle a `Commit` message
///
/// We have received `2f + 1` `Commit` messages so we are ready to commit the block to the chain.
#[allow(clippy::ptr_arg)]
pub fn commit(
    state: &mut PbftState,
    service: &mut Service,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    info!(
        "{}: Committing block {:?}",
        state,
        message.get_block().block_id.clone()
    );

    service
        .commit_block(message.get_block().block_id.clone())
        .map_err(|e| PbftError::InternalError(format!("Failed to commit block: {:?}", e)))?;

    state.switch_phase(PbftPhase::Finished);

    Ok(())
}

/// Create a PbftMessageInfo struct with the desired type, view, sequence number, and signer ID
pub fn make_msg_info(
    msg_type: &PbftMessageType,
    view: u64,
    seq_num: u64,
    signer_id: PeerId,
) -> PbftMessageInfo {
    let mut info = PbftMessageInfo::new();
    info.set_msg_type(String::from(msg_type));
    info.set_view(view);
    info.set_seq_num(seq_num);
    info.set_signer_id(signer_id);
    info
}

/// Make a PbftBlock out of a consensus Block (PBFT doesn't need to use all the information about
/// the block - this keeps blocks lighter weight)
pub fn pbft_block_from_block(block: Block) -> PbftBlock {
    let mut pbft_block = PbftBlock::new();
    pbft_block.set_block_id(block.block_id);
    pbft_block.set_signer_id(block.signer_id);
    pbft_block.set_block_num(block.block_num);
    pbft_block.set_summary(block.summary);
    pbft_block
}
