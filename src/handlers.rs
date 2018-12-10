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
use std::error::Error;

use hex;
use sawtooth_sdk::consensus::engine::{Block, BlockId, PeerId};
use sawtooth_sdk::consensus::service::Service;

use error::PbftError;
use message_log::PbftLog;
use message_type::ParsedMessage;
use message_type::{PbftHint, PbftMessageType};
use protos::pbft_message::{PbftBlock, PbftMessageInfo};
use state::{PbftPhase, PbftState, WorkingBlockOption};

/// Handle a `PrePrepare` message
/// A `PrePrepare` message with this view and sequence number must not already exist in the log.
/// Make sure there's a corresponding BlockNew message.
pub fn pre_prepare(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    let info = message.info();

    check_view_mismatch(state, info)?;

    check_pre_prepare_does_not_exist(msg_log, info)?;

    check_pre_prepare_matches_original_block_new(msg_log, message)?;

    set_current_working_block(state, message);

    state.seq_num = info.get_seq_num();

    Ok(())
}

fn check_view_mismatch(state: &PbftState, info: &PbftMessageInfo) -> Result<(), PbftError> {
    if info.get_view() != state.view {
        Err(PbftError::ViewMismatch(
            info.get_view() as usize,
            state.view as usize,
        ))
    } else {
        Ok(())
    }
}

fn check_pre_prepare_does_not_exist(
    msg_log: &PbftLog,
    info: &PbftMessageInfo,
) -> Result<(), PbftError> {
    // Check that this PrePrepare doesn't already exist
    let existing_pre_prep_msgs = msg_log.get_messages_of_type_seq_view(
        &PbftMessageType::PrePrepare,
        info.get_seq_num(),
        info.get_view(),
    );

    if !existing_pre_prep_msgs.is_empty() {
        return Err(PbftError::MessageExists(PbftMessageType::PrePrepare));
    }

    Ok(())
}

fn check_pre_prepare_matches_original_block_new(
    msg_log: &PbftLog,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    let block_new_msgs =
        msg_log.get_messages_of_type_seq(&PbftMessageType::BlockNew, message.info().get_seq_num());

    if block_new_msgs.len() != 1 {
        return Err(PbftError::WrongNumMessages(
            PbftMessageType::BlockNew,
            1,
            block_new_msgs.len(),
        ));
    }

    if block_new_msgs[0].get_block() != message.get_block() {
        return Err(PbftError::BlockMismatch(
            block_new_msgs[0].get_block().clone(),
            message.get_block().clone(),
        ));
    }

    Ok(())
}

fn set_current_working_block(state: &mut PbftState, message: &ParsedMessage) {
    state.working_block = WorkingBlockOption::WorkingBlock(message.get_block().clone());
}

/// Handle a `Commit` message
/// Once a `2f + 1` `Commit` messages are received, the primary node can commit the block to the
/// chain. If the block in the message isn't the one that belongs on top of the current chain head,
/// then the message gets pushed to the backlog.
#[allow(clippy::ptr_arg)]
pub fn commit(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    service: &mut Service,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    let working_block = clone_working_block(state)?;

    state.switch_phase(PbftPhase::Finished);

    check_if_block_already_seen(state, &working_block, message)?;

    check_if_commiting_with_current_chain_head(state, msg_log, service, message, &working_block)?;

    info!(
        "{}: Committing block {:?}",
        state,
        message.get_block().block_id.clone()
    );

    commit_block_from_message(service, message)?;

    reset_working_block(state);

    Ok(())
}

fn clone_working_block(state: &PbftState) -> Result<PbftBlock, PbftError> {
    if let WorkingBlockOption::WorkingBlock(ref wb) = state.working_block {
        Ok(wb.clone())
    } else {
        Err(PbftError::NoWorkingBlock)
    }
}

fn check_if_block_already_seen(
    state: &PbftState,
    working_block: &PbftBlock,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    let block = message.get_block();
    let block_id = &block.block_id;
    // Don't commit if we've seen this block already, but go ahead if we somehow
    // skipped a block.
    if block_id != &working_block.get_block_id()
        && block.get_block_num() >= working_block.get_block_num()
    {
        warn!("{}: Not committing block {:?}", state, block_id);
        Err(PbftError::BlockMismatch(
            block.clone(),
            working_block.clone(),
        ))
    } else {
        Ok(())
    }
}

#[allow(clippy::ptr_arg)]
fn check_if_commiting_with_current_chain_head(
    state: &mut PbftState,
    msg_log: &mut PbftLog,
    service: &mut Service,
    message: &ParsedMessage,
    working_block: &PbftBlock,
) -> Result<(), PbftError> {
    let block = message.get_block();
    let block_id = block.get_block_id().to_vec();

    let head = service
        .get_chain_head()
        .map_err(|e| PbftError::InternalError(e.description().to_string()))?;

    let cur_block = get_block_by_id(&mut *service, &block_id.to_vec())
        .ok_or_else(|| PbftError::WrongNumBlocks)?;

    if cur_block.previous_id != head.block_id {
        warn!(
            "{}: Not committing block {:?} but pushing to backlog",
            state,
            block_id.clone()
        );
        msg_log.push_backlog(message.clone());
        Err(PbftError::BlockMismatch(
            block.clone(),
            working_block.clone(),
        ))
    } else {
        Ok(())
    }
}

fn commit_block_from_message(
    service: &mut Service,
    message: &ParsedMessage,
) -> Result<(), PbftError> {
    service
        .commit_block(message.get_block().block_id.clone())
        .map_err(|_| PbftError::InternalError(String::from("Failed to commit block")))
}

fn reset_working_block(state: &mut PbftState) {
    state.working_block = WorkingBlockOption::NoWorkingBlock;
}

/// Decide if this message is a future message, past message, or current message.
/// This function defers action on future and past messages to the individual message handlers,
/// which in turn call `action_from_hint()`, and either push to backlog for future messages, or add
/// to message log for past messages. This usually only makes sense for regular multicast messages
/// (`PrePrepare`, `Prepare`, and `Commit`)
pub fn multicast_hint(state: &PbftState, message: &ParsedMessage) -> PbftHint {
    let msg_info = message.info();
    let msg_type = PbftMessageType::from(msg_info.get_msg_type());

    if msg_info.get_seq_num() > state.seq_num {
        debug!(
            "{}: seq {} > {}, accept all.",
            state,
            msg_info.get_seq_num(),
            state.seq_num
        );
        return PbftHint::FutureMessage;
    } else if msg_info.get_seq_num() == state.seq_num {
        if state.working_block.is_none() {
            debug!(
                "{}: seq {} == {}, in limbo",
                state,
                msg_info.get_seq_num(),
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
                msg_info.get_seq_num(),
                state.seq_num,
            );
            return PbftHint::PastMessage;
        }
        debug!(
            "{}: seq {} < {}, skip but add to log.",
            state,
            msg_info.get_seq_num(),
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
    service: &mut Service,
    vc_message: &ParsedMessage,
) -> Result<(), PbftError> {
    if !check_received_enough_view_changes(state, msg_log, vc_message) {
        return Ok(());
    }

    set_current_view_from_msg(state, vc_message);

    // Upgrade this node to primary, if its ID is correct
    if check_is_primary(state) {
        become_primary(state, service)
    } else {
        become_secondary(state)
    }

    state.discard_current_block();

    Ok(())
}

pub fn force_view_change(state: &mut PbftState, service: &mut Service) {
    let next_view = state.view + 1;
    set_current_view(state, next_view);

    // Upgrade this node to primary, if its ID is correct
    if check_is_primary(state) {
        become_primary(state, service)
    } else {
        become_secondary(state)
    }

    state.discard_current_block();
}

fn check_received_enough_view_changes(
    state: &PbftState,
    msg_log: &PbftLog,
    vc_message: &ParsedMessage,
) -> bool {
    msg_log.log_has_required_msgs(
        &PbftMessageType::ViewChange,
        vc_message,
        false,
        2 * state.f + 1,
    )
}

fn set_current_view_from_msg(state: &mut PbftState, vc_message: &ParsedMessage) {
    set_current_view(state, vc_message.info().get_view())
}

fn set_current_view(state: &mut PbftState, view: u64) {
    state.view = view;
    warn!("{}: Updating to view {}", state, state.view);
}

fn check_is_primary(state: &PbftState) -> bool {
    state.id == state.get_primary_id()
}

fn become_primary(state: &mut PbftState, service: &mut Service) {
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
            .ignore_block(working_block.get_block_id().to_vec())
            .unwrap_or_else(|e| error!("Couldn't ignore block: {}", e));
    } else if let WorkingBlockOption::TentativeWorkingBlock(ref block_id) = state.working_block {
        info!("{}: Ignoring block {}", state, &hex::encode(block_id));
        service
            .ignore_block(block_id.clone())
            .unwrap_or_else(|e| error!("Couldn't ignore block: {}", e));
    }
    info!("{}: Initializing block", state);
    service
        .initialize_block(None)
        .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
}

fn become_secondary(state: &mut PbftState) {
    warn!("{}: I'm now a secondary", state);
    state.downgrade_role();
}

#[allow(clippy::ptr_arg)]
// There should only be one block with a matching ID
fn get_block_by_id(service: &mut Service, block_id: &BlockId) -> Option<Block> {
    let blocks: Vec<Block> = service
        .get_blocks(vec![block_id.clone()])
        .unwrap_or_default()
        .into_iter()
        .map(|(_block_id, block)| block)
        .collect();
    if blocks.is_empty() {
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
    use config;
    use hash::hash_sha256;
    use protos::pbft_message::PbftMessage;

    fn mock_block_id(num: u64) -> BlockId {
        BlockId::from(hash_sha256(
            format!("I'm a block with block num {}", num).as_bytes(),
        ))
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
        let mut state0 = PbftState::new(vec![0], &cfg);
        let mut state1 = PbftState::new(vec![1], &cfg);
        let mut log0 = PbftLog::new(&cfg);
        let mut log1 = PbftLog::new(&cfg);

        let pre_prep_msg = mock_msg(&PbftMessageType::PrePrepare, 0, 1, mock_block(1), vec![0]);

        assert!(pre_prepare(&mut state0, &mut log0, &pre_prep_msg).is_err());
        assert!(pre_prepare(&mut state1, &mut log1, &pre_prep_msg).is_err());

        // Put the block new in the log
        let block_new0 = mock_msg(&PbftMessageType::BlockNew, 0, 1, mock_block(1), vec![0]);
        log0.add_message(block_new0, &state0);
        state0.seq_num = 1;

        let block_new1 = mock_msg(&PbftMessageType::BlockNew, 0, 0, mock_block(1), vec![0]);
        log1.add_message(block_new1, &state1);

        assert!(pre_prepare(&mut state0, &mut log0, &pre_prep_msg).is_ok());
        assert!(pre_prepare(&mut state1, &mut log1, &pre_prep_msg).is_ok());

        assert_eq!(state0.seq_num, 1);
        assert_eq!(state1.seq_num, 1);
    }

    #[test]
    fn test_multicast_hint() {
        let cfg = config::mock_config(4);
        let mut state = PbftState::new(vec![0], &cfg);
        state.seq_num = 5;

        // Past (past sequence number)
        let past_msg = mock_msg(&PbftMessageType::Prepare, 0, 1, mock_block(1), vec![0]);
        assert_eq!(multicast_hint(&state, &past_msg), PbftHint::PastMessage);

        // Past (current sequence number, past phase)
        state.phase = PbftPhase::Committing;
        state.working_block =
            WorkingBlockOption::WorkingBlock(pbft_block_from_block(mock_block(5)));
        let past_msg = mock_msg(&PbftMessageType::Prepare, 0, 5, mock_block(5), vec![0]);
        assert_eq!(multicast_hint(&state, &past_msg), PbftHint::PastMessage);

        // Present
        let present_msg = mock_msg(&PbftMessageType::Commit, 0, 5, mock_block(5), vec![0]);
        assert_eq!(
            multicast_hint(&state, &present_msg),
            PbftHint::PresentMessage
        );

        // Future (current sequence number, future phase)
        state.phase = PbftPhase::Preparing;
        let future_msg = mock_msg(&PbftMessageType::Commit, 0, 5, mock_block(5), vec![0]);
        assert_eq!(multicast_hint(&state, &future_msg), PbftHint::FutureMessage);

        // Future (future sequence number)
        state.phase = PbftPhase::NotStarted;
        let future_msg = mock_msg(&PbftMessageType::Commit, 0, 15, mock_block(15), vec![0]);
        assert_eq!(multicast_hint(&state, &future_msg), PbftHint::FutureMessage);
    }
}
