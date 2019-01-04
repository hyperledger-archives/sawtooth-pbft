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
use crate::message_log::PbftLog;
use crate::message_type::ParsedMessage;
use crate::message_type::PbftMessageType;
use crate::protos::pbft_message::{PbftBlock, PbftMessageInfo};
use crate::state::{PbftPhase, PbftState};

/// Handle a `PrePrepare` message
///
/// A `PrePrepare` message is accepted and added to the log if the following are true:
/// - The message signature is valid (already verified by validator)
/// - The message is from the primary
/// - There is a matching BlockNew message
/// - A `PrePrepare` message does not already exist at this view and sequence number with a
///   different block
/// - The message's view matches the node's current view (handled by message log)
/// - The sequence number is between the low and high watermarks (handled by message log)
pub fn pre_prepare(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    // Check that message is from the current primary
    if PeerId::from(message.info().get_signer_id()) != state.get_primary_id() {
        error!(
            "Got PrePrepare from a secondary node {:?}; ignoring message",
            message.info().get_signer_id()
        );
        return Err(PbftError::NotFromPrimary);
    }

    // Check that there is a matching BlockNew message
    let block_new_exists = msg_log
        .get_messages_of_type_seq(&PbftMessageType::BlockNew, message.info().get_seq_num())
        .iter()
        .any(|block_new_msg| block_new_msg.get_block() == message.get_block());
    if !block_new_exists {
        error!("No matching BlockNew found for PrePrepare {:?}", message);
        return Err(PbftError::NoBlockNew);
    }

    // Check that no `PrePrepare`s already exist with this view and sequence number but a different
    // block
    let mut mismatched_blocks = msg_log
        .get_messages_of_type_seq_view(
            &PbftMessageType::PrePrepare,
            message.info().get_seq_num(),
            message.info().get_view(),
        )
        .iter()
        .filter_map(|existing_msg| {
            let block = existing_msg.get_block().clone();
            if &block != message.get_block() {
                Some(block)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if !mismatched_blocks.is_empty() {
        error!("When checking PrePrepare {:?}, found PrePrepare(s) with same view and seq num but mismatched block(s): {:?}", message, mismatched_blocks);
        mismatched_blocks.push(message.get_block().clone());
        return Err(PbftError::MismatchedBlocks(mismatched_blocks));
    }

    msg_log.add_message(message.clone(), state)?;

    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::hash::hash_sha256;
    use crate::protos::pbft_message::PbftMessage;
    use sawtooth_sdk::consensus::engine::BlockId;

    fn mock_block_id(num: u64) -> BlockId {
        BlockId::from(hash_sha256(
            format!("I'm a block with block num {}", num).as_bytes(),
        ))
    }

    fn mock_block(num: u64) -> Block {
        Block {
            block_id: mock_block_id(num),
            previous_id: mock_block_id(num - 1),
            signer_id: PeerId::from(vec![0]),
            block_num: num,
            payload: vec![],
            summary: vec![],
        }
    }

    fn mock_msg(
        msg_type: &PbftMessageType,
        view: u64,
        seq_num: u64,
        block: Block,
        from: PeerId,
    ) -> ParsedMessage {
        let info = make_msg_info(&msg_type, view, seq_num, from);
        let mut pbft_msg = PbftMessage::new();
        pbft_msg.set_info(info);
        pbft_msg.set_block(pbft_block_from_block(block.clone()));
        ParsedMessage::from_pbft_message(pbft_msg)
    }

    #[test]
    fn test_pre_prepare() {
        let cfg = config::mock_config(4);
        let mut state0 = PbftState::new(vec![0], 0, &cfg);
        let mut state1 = PbftState::new(vec![1], 0, &cfg);
        let mut log0 = PbftLog::new(&cfg);
        let mut log1 = PbftLog::new(&cfg);

        let pre_prep_msg = mock_msg(&PbftMessageType::PrePrepare, 0, 1, mock_block(1), vec![0]);

        assert!(pre_prepare(&mut state0, &mut log0, &pre_prep_msg).is_err());
        assert!(pre_prepare(&mut state1, &mut log1, &pre_prep_msg).is_err());

        // Put the block new in the log
        let block_new0 = mock_msg(&PbftMessageType::BlockNew, 0, 1, mock_block(1), vec![0]);
        log0.add_message(block_new0, &state0).unwrap();
        state0.seq_num = 1;

        let block_new1 = mock_msg(&PbftMessageType::BlockNew, 0, 1, mock_block(1), vec![0]);
        log1.add_message(block_new1, &state1).unwrap();

        assert!(pre_prepare(&mut state0, &mut log0, &pre_prep_msg).is_ok());
        assert!(pre_prepare(&mut state1, &mut log1, &pre_prep_msg).is_ok());

        assert_eq!(state0.seq_num, 1);
        assert_eq!(state1.seq_num, 1);
    }
}
