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

use hex;

use std::collections::HashMap;
use std::convert::From;
use std::error::Error;

use sawtooth_sdk::consensus::engine::{Block, BlockId, PeerId, PeerMessage};
use sawtooth_sdk::consensus::service::Service;

use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

use error::PbftError;
use message_log::PbftLog;
use message_type::{PbftHint, PbftMessageType};
use state::{PbftMode, PbftPhase, PbftState, WorkingBlockOption};

/// Take action based on a `PbftHint`
/// Either push to backlog or add message to log, depending on which type of hint
pub fn action_from_hint(
    msg_log: &mut PbftLog,
    hint: &PbftHint,
    pbft_message: &PbftMessage,
    msg_content: Vec<u8>,
) -> Result<(), PbftError> {
    let msg = PeerMessage {
        message_type: String::from(pbft_message.get_info().get_msg_type()),
        content: msg_content,
    };
    match hint {
        PbftHint::FutureMessage => {
            msg_log.push_backlog(msg);
            Err(PbftError::NotReadyForMessage)
        }
        PbftHint::PastMessage => {
            msg_log.add_message(pbft_message.clone());
            Err(PbftError::NotReadyForMessage)
        }
        PbftHint::PresentMessage => Ok(()),
    }
}

/// Handle a `PrePrepare` message
/// A `PrePrepare` message with this view and sequence number must not already exist in the log. If
/// this node is a primary, make sure there's a corresponding BlockNew message. If this node is a
/// secondary, then it takes the sequence number from this message as its own.
pub fn pre_prepare(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    pbft_message: &PbftMessage,
) -> Result<(), PbftError> {
    let info = pbft_message.get_info();

    if info.get_view() != state.view {
        return Err(PbftError::ViewMismatch(
            info.get_view() as usize,
            state.view as usize,
        ));
    }

    // Immutably borrow msg_log for a bit, in a context
    {
        // Check that this PrePrepare doesn't already exist
        let existing_pre_prep_msgs = msg_log.get_messages_of_type(
            &PbftMessageType::PrePrepare,
            info.get_seq_num(),
            info.get_view(),
        );

        if existing_pre_prep_msgs.len() > 0 {
            return Err(PbftError::MessageExists(PbftMessageType::PrePrepare));
        }
    }

    if state.is_primary() {
        // Check that incoming PrePrepare matches original BlockNew
        let block_new_msgs = msg_log.get_messages_of_type(
            &PbftMessageType::BlockNew,
            info.get_seq_num(),
            info.get_view(),
        );

        if block_new_msgs.len() != 1 {
            return Err(PbftError::WrongNumMessages(
                PbftMessageType::BlockNew,
                1,
                block_new_msgs.len(),
            ));
        }

        if block_new_msgs[0].get_block() != pbft_message.get_block() {
            return Err(PbftError::BlockMismatch(
                block_new_msgs[0].get_block().clone(),
                pbft_message.get_block().clone(),
            ));
        }
    } else {
        // Set this secondary's sequence number from the PrePrepare message
        // (this was originally set by the primary)...
        state.seq_num = info.get_seq_num();

        // ...then update the BlockNew message we received with the correct
        // sequence number
        let num_updated = msg_log.fix_seq_nums(
            &PbftMessageType::BlockNew,
            info.get_seq_num(),
            info.get_view(),
            pbft_message.get_block(),
        );

        debug!(
            "{}: The log updated {} BlockNew messages to seq num {}",
            state,
            num_updated,
            info.get_seq_num()
        );

        if num_updated < 1 {
            return Err(PbftError::WrongNumMessages(
                PbftMessageType::BlockNew,
                1,
                num_updated,
            ));
        }
    }

    // Take the working block from PrePrepare message as our current working block
    state.working_block = WorkingBlockOption::WorkingBlock(pbft_message.get_block().clone());

    Ok(())
}

/// Handle a `Commit` message
/// Once a `2f + 1` `Commit` messages are received, the primary node can commit the block to the
/// chain. If the block in the message isn't the one that belongs on top of the current chain head,
/// then the message gets pushed to the backlog.
pub fn commit(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    mut service: &mut Box<Service>,
    pbft_message: &PbftMessage,
    msg_content: Vec<u8>,
) -> Result<(), PbftError> {
    let working_block = if let WorkingBlockOption::WorkingBlock(ref wb) = state.working_block {
        Ok(wb.clone())
    } else {
        Err(PbftError::NoWorkingBlock)
    }?;

    state.switch_phase(PbftPhase::Finished);

    // Don't commit if we've seen this block already, but go ahead if we somehow
    // skipped a block.
    if pbft_message.get_block().get_block_id() != working_block.get_block_id()
        && pbft_message.get_block().get_block_num() >= working_block.get_block_num()
    {
        warn!(
            "{}: Not committing block {:?}",
            state,
            BlockId::from(pbft_message.get_block().block_id.clone())
        );
        return Err(PbftError::BlockMismatch(
            pbft_message.get_block().clone(),
            working_block.clone(),
        ));
    }

    // Also make sure that we're committing on top of the current chain head
    let head = service
        .get_chain_head()
        .map_err(|e| PbftError::InternalError(e.description().to_string()))?;
    let cur_block = get_block_by_id(
        &mut service,
        BlockId::from(pbft_message.get_block().get_block_id().to_vec()),
    ).ok_or_else(|| PbftError::WrongNumBlocks)?;
    if cur_block.previous_id != head.block_id {
        warn!(
            "{}: Not committing block {:?} but pushing to backlog",
            state,
            BlockId::from(pbft_message.get_block().block_id.clone())
        );
        let msg = PeerMessage {
            message_type: String::from(pbft_message.get_info().get_msg_type()),
            content: msg_content,
        };
        msg_log.push_backlog(msg);
        return Err(PbftError::BlockMismatch(
            pbft_message.get_block().clone(),
            working_block.clone(),
        ));
    }

    info!(
        "{}: Committing block {:?}",
        state,
        BlockId::from(pbft_message.get_block().block_id.clone())
    );

    service
        .commit_block(BlockId::from(pbft_message.get_block().block_id.clone()))
        .map_err(|_| PbftError::InternalError(String::from("Failed to commit block")))?;

    // Previous block is sent to the validator; reset the working block
    state.working_block = WorkingBlockOption::NoWorkingBlock;
    Ok(())
}

/// Decide if this message is a future message, past message, or current message.
/// This function defers action on future and past messages to the individual message handlers,
/// which in turn call `action_from_hint()`, and either push to backlog for future messages, or add
/// to message log for past messages. This usually only makes sense for regular multicast messages
/// (`PrePrepare`, `Prepare`, and `Commit`)
pub fn multicast_hint(state: &PbftState, pbft_message: PbftMessage) -> PbftHint {
    let msg_type = PbftMessageType::from(pbft_message.get_info().get_msg_type());

    if pbft_message.get_info().get_seq_num() > state.seq_num {
        debug!(
            "{}: seq {} > {}, accept all.",
            state,
            pbft_message.get_info().get_seq_num(),
            state.seq_num
        );
        return PbftHint::FutureMessage;
    } else if pbft_message.get_info().get_seq_num() == state.seq_num {
        if state.working_block.is_none() {
            debug!(
                "{}: seq {} == {}, in limbo",
                state,
                pbft_message.get_info().get_seq_num(),
                state.seq_num,
            );
            return PbftHint::PastMessage;
        }
        let expecting_type = state.check_msg_type();
        if msg_type < expecting_type {
            debug!(
                "{}: seq {} == {}, {} < {}, only add to log",
                state, state.seq_num, state.seq_num, msg_type, expecting_type,
            );
            return PbftHint::PastMessage;
        } else if msg_type > expecting_type {
            debug!(
                "{}: seq {} == {}, {} > {}, push to backlog.",
                state, state.seq_num, state.seq_num, msg_type, expecting_type,
            );
            return PbftHint::FutureMessage;
        }
    } else {
        if state.working_block.is_none() {
            debug!(
                "{}: seq {} == {}, in limbo",
                state,
                pbft_message.get_info().get_seq_num(),
                state.seq_num,
            );
            return PbftHint::PastMessage;
        }
        debug!(
            "{}: seq {} < {}, skip but add to log.",
            state,
            pbft_message.get_info().get_seq_num(),
            state.seq_num
        );
        return PbftHint::PastMessage;
    }
    PbftHint::PresentMessage
}

/// Handle a `ViewChange` message
/// Once a node receives `2f + 1` `ViewChange` messages, the node enters view `v + 1` and changes
/// itself into the appropriate role for that view (i.e. if `v = 1` and this is node 1, then this
/// node is now the primary).
pub fn view_change(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    service: &mut Box<Service>,
    vc_message: &PbftViewChange,
) -> Result<(), PbftError> {
    msg_log.check_msg_against_log(&vc_message, true, 2 * state.f + 1)?;

    // Update current view and stop timeout
    state.view = vc_message.get_info().get_view();
    warn!("{}: Updating to view {}", state, state.view);

    // Upgrade this node to primary, if its ID is correct
    if state.get_own_peer_id() == state.get_primary_peer_id() {
        state.upgrade_role();
        warn!("{}: I'm now a primary", state);

        // If we're the new primary, need to clean up the block mess from the view change and
        // initialize a new block.
        if let WorkingBlockOption::WorkingBlock(ref working_block) = state.working_block {
            info!(
                "{}: Ignoring block {}",
                state,
                &hex::encode(working_block.get_block_id())
            );
            service
                .ignore_block(BlockId::from(working_block.get_block_id().to_vec()))
                .unwrap_or_else(|e| error!("Couldn't ignore block: {}", e));
        } else if let WorkingBlockOption::TentativeWorkingBlock(ref block_id) = state.working_block
        {
            info!("{}: Ignoring block {}", state, &hex::encode(block_id));
            service
                .ignore_block(block_id.clone())
                .unwrap_or_else(|e| error!("Couldn't ignore block: {}", e));
        }
        info!("{}: Initializing block", state);
        service
            .initialize_block(None)
            .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
    } else {
        warn!("{}: I'm now a secondary", state);
        state.downgrade_role();
    }
    state.working_block = WorkingBlockOption::NoWorkingBlock;
    state.phase = PbftPhase::NotStarted;
    state.mode = PbftMode::Normal;
    state.timeout.stop();
    warn!(
        "{}: Entered normal mode in new view {} and stopped timeout",
        state, state.view
    );
    Ok(())
}

// There should only be one block with a matching ID
fn get_block_by_id(service: &mut Box<Service>, block_id: BlockId) -> Option<Block> {
    let blocks: Vec<Block> = service
        .get_blocks(vec![block_id.clone()])
        .unwrap_or(HashMap::new())
        .into_iter()
        .map(|(_block_id, block)| block)
        .collect();
    if blocks.len() < 1 {
        None
    } else {
        Some(blocks[0].clone())
    }
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
    info.set_signer_id(Vec::<u8>::from(signer_id));
    info
}

/// Make a PbftBlock out of a consensus Block (PBFT doesn't need to use all the information about
/// the block - this keeps blocks lighter weight)
pub fn pbft_block_from_block(block: Block) -> PbftBlock {
    let mut pbft_block = PbftBlock::new();
    pbft_block.set_block_id(Vec::<u8>::from(block.block_id));
    pbft_block.set_signer_id(Vec::<u8>::from(block.signer_id));
    pbft_block.set_block_num(block.block_num);
    pbft_block.set_summary(block.summary);
    pbft_block
}

#[cfg(test)]
mod tests {
    use super::*;
    use config;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;

    fn mock_peer_id(num: u64) -> PeerId {
        let mut sha = Sha256::new();
        sha.input_str(format!("I'm a peer (number {})", num).as_str());
        PeerId::from(sha.result_str().as_bytes().to_vec())
    }

    fn mock_block_id(num: u64) -> BlockId {
        let mut sha = Sha256::new();
        sha.input_str(format!("I'm a block with block num {}", num).as_str());
        BlockId::from(sha.result_str().as_bytes().to_vec())
    }

    fn mock_block(num: u64) -> Block {
        Block {
            block_id: mock_block_id(num),
            previous_id: mock_block_id(num - 1),
            signer_id: PeerId::from(vec![]),
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
        from: u64,
    ) -> PbftMessage {
        let info = make_msg_info(&msg_type, view, seq_num, mock_peer_id(from));
        let mut pbft_msg = PbftMessage::new();
        pbft_msg.set_info(info);
        pbft_msg.set_block(pbft_block_from_block(block.clone()));
        pbft_msg
    }

    #[test]
    fn test_pre_prepare() {
        let cfg = config::mock_config(4);
        let mut state0 = PbftState::new(0, &cfg);
        let mut state1 = PbftState::new(1, &cfg);
        let mut log0 = PbftLog::new(&cfg);
        let mut log1 = PbftLog::new(&cfg);

        let pre_prep_msg = mock_msg(&PbftMessageType::PrePrepare, 0, 1, mock_block(1), 0);

        assert!(pre_prepare(&mut state0, &mut log0, &pre_prep_msg).is_err());
        assert!(pre_prepare(&mut state1, &mut log1, &pre_prep_msg).is_err());

        // Put the block new in the log
        let block_new0 = mock_msg(&PbftMessageType::BlockNew, 0, 1, mock_block(1), 0);
        log0.add_message(block_new0);
        state0.seq_num = 1;

        let block_new1 = mock_msg(&PbftMessageType::BlockNew, 0, 0, mock_block(1), 0);
        log1.add_message(block_new1);

        assert!(pre_prepare(&mut state0, &mut log0, &pre_prep_msg).is_ok());
        assert!(pre_prepare(&mut state1, &mut log1, &pre_prep_msg).is_ok());

        assert_eq!(state0.seq_num, 1);
        assert_eq!(state1.seq_num, 1);
    }

    #[test]
    fn test_multicast_hint() {
        let cfg = config::mock_config(4);
        let mut state = PbftState::new(0, &cfg);
        state.seq_num = 5;

        // Past (past sequence number)
        let past_msg = mock_msg(&PbftMessageType::Prepare, 0, 1, mock_block(1), 0);
        assert_eq!(multicast_hint(&state, past_msg), PbftHint::PastMessage);

        // Past (current sequence number, past phase)
        state.phase = PbftPhase::Committing;
        state.working_block =
            WorkingBlockOption::WorkingBlock(pbft_block_from_block(mock_block(5)));
        let past_msg = mock_msg(&PbftMessageType::Prepare, 0, 5, mock_block(5), 0);
        assert_eq!(multicast_hint(&state, past_msg), PbftHint::PastMessage);

        // Present
        let present_msg = mock_msg(&PbftMessageType::Commit, 0, 5, mock_block(5), 0);
        assert_eq!(
            multicast_hint(&state, present_msg),
            PbftHint::PresentMessage
        );

        // Future (current sequence number, future phase)
        state.phase = PbftPhase::Preparing;
        let future_msg = mock_msg(&PbftMessageType::Commit, 0, 5, mock_block(5), 0);
        assert_eq!(multicast_hint(&state, future_msg), PbftHint::FutureMessage);

        // Future (future sequence number)
        state.phase = PbftPhase::NotStarted;
        let future_msg = mock_msg(&PbftMessageType::Commit, 0, 15, mock_block(15), 0);
        assert_eq!(multicast_hint(&state, future_msg), PbftHint::FutureMessage);
    }
}
