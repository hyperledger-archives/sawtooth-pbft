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

//! The core PBFT algorithm

use std::collections::HashSet;
use std::convert::From;

use itertools::Itertools;
use protobuf::{Message, RepeatedField};
use sawtooth_sdk::consensus::engine::{Block, BlockId, PeerId, PeerInfo};
use sawtooth_sdk::consensus::service::Service;
use sawtooth_sdk::messages::consensus::ConsensusPeerMessageHeader;
use sawtooth_sdk::signing::{create_context, secp256k1::Secp256k1PublicKey};

use crate::config::{get_members_from_settings, PbftConfig};
use crate::error::PbftError;
use crate::hash::verify_sha512;
use crate::message_log::PbftLog;
use crate::message_type::{ParsedMessage, PbftMessageType};
use crate::protos::pbft_message::{
    PbftMessage, PbftMessageInfo, PbftNewView, PbftSeal, PbftSignedVote,
};
use crate::state::{PbftMode, PbftPhase, PbftState};
use crate::timing::{retry_until_ok, Timeout};

/// Contains the core logic of the PBFT node
pub struct PbftNode {
    /// Used for interactions with the validator
    pub service: Box<dyn Service>,

    /// Log of messages this node has received and accepted
    pub msg_log: PbftLog,
}

impl PbftNode {
    /// Construct a new PBFT node
    ///
    /// If the node is the primary on start-up, it initializes a new block on the chain
    pub fn new(
        config: &PbftConfig,
        chain_head: Block,
        connected_peers: Vec<PeerInfo>,
        service: Box<dyn Service>,
        state: &mut PbftState,
    ) -> Self {
        let mut n = PbftNode {
            service,
            msg_log: PbftLog::new(config),
        };

        // Add chain head to log and update state
        n.msg_log.add_validated_block(chain_head.clone());
        state.chain_head = chain_head.block_id.clone();

        // If starting up from a non-genesis block, the node may need to perform some special
        // actions
        if chain_head.block_num > 1 {
            // If starting up with a block that has a consensus seal, update the view to match
            if let Ok(seal) = PbftSeal::parse_from_bytes(&chain_head.payload) {
                state.view = seal.get_info().get_view();
                info!("Updated view to {} on startup", state.view);
            }
            // If connected to any peers already, send bootstrap commit messages to them
            for peer in connected_peers {
                n.broadcast_bootstrap_commit(peer.peer_id, state)
                    .unwrap_or_else(|err| {
                        error!("Failed to broadcast bootstrap commit due to error: {}", err)
                    });
            }
        }

        // Primary initializes a block
        if state.is_primary() {
            n.service.initialize_block(None).unwrap_or_else(|err| {
                error!("Couldn't initialize block on startup due to error: {}", err)
            });
        }
        n
    }

    // ---------- Methods for handling Updates from the Validator ----------

    /// Handle a peer message from another PbftNode
    ///
    /// Handle all messages from other nodes. Such messages include `PrePrepare`, `Prepare`,
    /// `Commit`, `ViewChange`, and `NewView`. Make sure the message is from a PBFT member. If the
    /// node is view changing, ignore all messages that aren't `ViewChange`s or `NewView`s.
    pub fn on_peer_message(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        trace!("{}: Got peer message: {}", state, msg.info());

        // Make sure this message is from a known member of the PBFT network
        if !state.member_ids.contains(&msg.info().signer_id) {
            return Err(PbftError::InvalidMessage(format!(
                "Received message from node ({:?}) that is not a member of the PBFT network",
                hex::encode(msg.info().get_signer_id()),
            )));
        }

        let msg_type = PbftMessageType::from(msg.info().msg_type.as_str());

        // If this node is in the process of a view change, ignore all messages except ViewChanges
        // and NewViews
        if matches!(state.mode, PbftMode::ViewChanging(_))
            && msg_type != PbftMessageType::ViewChange
            && msg_type != PbftMessageType::NewView
        {
            debug!(
                "{}: Node is view changing; ignoring {} message",
                state, msg_type
            );
            return Ok(());
        }

        match msg_type {
            PbftMessageType::PrePrepare => self.handle_pre_prepare(msg, state)?,
            PbftMessageType::Prepare => self.handle_prepare(msg, state)?,
            PbftMessageType::Commit => self.handle_commit(msg, state)?,
            PbftMessageType::ViewChange => self.handle_view_change(&msg, state)?,
            PbftMessageType::NewView => self.handle_new_view(&msg, state)?,
            PbftMessageType::SealRequest => self.handle_seal_request(msg, state)?,
            PbftMessageType::Seal => self.handle_seal_response(&msg, state)?,
            _ => warn!("Received message with unknown type: {:?}", msg_type),
        }

        Ok(())
    }

    /// Handle a `PrePrepare` message
    ///
    /// A `PrePrepare` message is accepted and added to the log if the following are true:
    /// - The message signature is valid (already verified by validator)
    /// - The message is from the primary
    /// - The message's view matches the node's current view
    /// - A `PrePrepare` message does not already exist at this view and sequence number with a
    ///   different block
    ///
    /// Once a `PrePrepare` for the current sequence number is accepted and added to the log, the
    /// node will try to switch to the `Preparing` phase.
    fn handle_pre_prepare(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Check that the message is from the current primary
        if *msg.info().get_signer_id() != state.get_primary_id() {
            warn!(
                "Got PrePrepare from a secondary node {:?}; ignoring message",
                msg.info().get_signer_id()
            );
            return Ok(());
        }

        // Check that the message is for the current view
        if msg.info().get_view() != state.view {
            return Err(PbftError::InvalidMessage(format!(
                "Node is on view {}, but a PrePrepare for view {} was received",
                state.view,
                msg.info().get_view(),
            )));
        }

        // Check that no `PrePrepare`s already exist with this view and sequence number but a
        // different block; if this is violated, the primary is faulty so initiate a view change
        let mismatched_blocks = self
            .msg_log
            .get_messages_of_type_seq_view(
                PbftMessageType::PrePrepare,
                msg.info().get_seq_num(),
                msg.info().get_view(),
            )
            .iter()
            .filter_map(|existing_msg| {
                let block_id = existing_msg.get_block_id();
                if block_id != msg.get_block_id() {
                    Some(block_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if !mismatched_blocks.is_empty() {
            self.start_view_change(state, state.view + 1)?;
            return Err(PbftError::FaultyPrimary(format!(
                "When checking PrePrepare with block {:?}, found PrePrepare(s) with same view and \
                 seq num but mismatched block(s): {:?}",
                hex::encode(&msg.get_block_id()),
                mismatched_blocks,
            )));
        }

        // Add message to the log
        self.msg_log.add_message(msg.clone());

        // If the node is in the PrePreparing phase, this message is for the current sequence
        // number, and the node already has this block: switch to Preparing
        self.try_preparing(msg.get_block_id(), state)
    }

    /// Handle a `Prepare` message
    ///
    /// Once a `Prepare` for the current sequence number is accepted and added to the log, the node
    /// will check if it has the required 2f + 1 `Prepared` messages to move on to the Committing
    /// phase
    fn handle_prepare(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let info = msg.info().clone();
        let block_id = msg.get_block_id();

        // Check that the message is for the current view
        if msg.info().get_view() != state.view {
            return Err(PbftError::InvalidMessage(format!(
                "Node is on view {}, but a Prepare for view {} was received",
                state.view,
                msg.info().get_view(),
            )));
        }

        // The primary is not allowed to send a Prepare; its PrePrepare counts as its "vote"
        if *info.get_signer_id() == state.get_primary_id() {
            self.start_view_change(state, state.view + 1)?;
            return Err(PbftError::FaultyPrimary(format!(
                "Received Prepare from primary at view {}, seq_num {}",
                state.view, state.seq_num
            )));
        }

        self.msg_log.add_message(msg);

        // If this message is for the current sequence number and the node is in the Preparing
        // phase, check if the node is ready to move on to the Committing phase
        if info.get_seq_num() == state.seq_num && state.phase == PbftPhase::Preparing {
            // The node is ready to move on to the Committing phase (i.e. the predicate `prepared`
            // is true) when its log has 2f + 1 Prepare messages from different nodes that match
            // the PrePrepare message received earlier (same view, sequence number, and block)
            let has_matching_pre_prepare =
                self.msg_log
                    .has_pre_prepare(info.get_seq_num(), info.get_view(), &block_id);
            let has_required_prepares = self
                .msg_log
                // Only get Prepares with matching seq_num, view, and block_id
                .get_messages_of_type_seq_view_block(
                    PbftMessageType::Prepare,
                    info.get_seq_num(),
                    info.get_view(),
                    &block_id,
                )
                // Check if there are at least 2f + 1 Prepares
                .len() as u64
                > 2 * state.f;
            if has_matching_pre_prepare && has_required_prepares {
                state.switch_phase(PbftPhase::Committing)?;
                self.broadcast_pbft_message(
                    state.view,
                    state.seq_num,
                    PbftMessageType::Commit,
                    block_id,
                    state,
                )?;
            }
        }

        Ok(())
    }

    /// Handle a `Commit` message
    ///
    /// Once a `Commit` for the current sequence number is accepted and added to the log, the node
    /// will check if it has the required 2f + 1 `Commit` messages to actually commit the block
    fn handle_commit(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let info = msg.info().clone();
        let block_id = msg.get_block_id();

        // Check that the message is for the current view
        if msg.info().get_view() != state.view {
            return Err(PbftError::InvalidMessage(format!(
                "Node is on view {}, but a Commit for view {} was received",
                state.view,
                msg.info().get_view(),
            )));
        }

        self.msg_log.add_message(msg);

        // If this message is for the current sequence number and the node is in the Committing
        // phase, check if the node is ready to commit the block
        if info.get_seq_num() == state.seq_num && state.phase == PbftPhase::Committing {
            // The node is ready to commit the block (i.e. the predicate `committable` is true)
            // when its log has 2f + 1 Commit messages from different nodes that match the
            // PrePrepare message received earlier (same view, sequence number, and block)
            let has_matching_pre_prepare =
                self.msg_log
                    .has_pre_prepare(info.get_seq_num(), info.get_view(), &block_id);
            let has_required_commits = self
                .msg_log
                // Only get Commits with matching seq_num, view, and block_id
                .get_messages_of_type_seq_view_block(
                    PbftMessageType::Commit,
                    info.get_seq_num(),
                    info.get_view(),
                    &block_id,
                )
                // Check if there are at least 2f + 1 Commits
                .len() as u64
                > 2 * state.f;
            if has_matching_pre_prepare && has_required_commits {
                self.service.commit_block(block_id.clone()).map_err(|err| {
                    PbftError::ServiceError(
                        format!("Failed to commit block {:?}", hex::encode(&block_id)),
                        err,
                    )
                })?;
                state.switch_phase(PbftPhase::Finishing(false))?;
                // Stop the commit timeout, since the network has agreed to commit the block
                state.commit_timeout.stop();
            }
        }

        Ok(())
    }

    /// Handle a `ViewChange` message
    ///
    /// When a `ViewChange` is received, check that it isn't outdated and add it to the log. If the
    /// node isn't already view changing but it now has f + 1 ViewChange messages, start view
    /// changing early. If the node is the primary and has 2f view change messages now, broadcast
    /// the NewView message to the rest of the nodes to move to the new view.
    fn handle_view_change(
        &mut self,
        msg: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Ignore old view change messages (already on a view >= the one this message is
        // for or already trying to change to a later view)
        let msg_view = msg.info().get_view();
        if msg_view <= state.view
            || match state.mode {
                PbftMode::ViewChanging(v) => msg_view < v,
                _ => false,
            }
        {
            debug!("Ignoring stale view change message for view {}", msg_view);
            return Ok(());
        }

        self.msg_log.add_message(msg.clone());

        // Even if the node hasn't detected a faulty primary yet, start view changing if there are
        // f + 1 ViewChange messages in the log for this proposed view (but if already view
        // changing, only do this for a later view); this will prevent starting the view change too
        // late
        let is_later_view = match state.mode {
            PbftMode::ViewChanging(v) => msg_view > v,
            PbftMode::Normal => true,
        };
        let start_view_change = self
            .msg_log
            // Only get ViewChanges with matching view
            .get_messages_of_type_view(PbftMessageType::ViewChange, msg_view)
            // Check if there are at least f + 1 ViewChanges
            .len() as u64
            > state.f;
        if is_later_view && start_view_change {
            info!(
                "{}: Received f + 1 ViewChange messages; starting early view change",
                state
            );
            // Can exit early since the node will self-send another ViewChange message here
            return self.start_view_change(state, msg_view);
        }

        let messages = self
            .msg_log
            .get_messages_of_type_view(PbftMessageType::ViewChange, msg_view);

        // If there are 2f + 1 ViewChange messages and the view change timeout is not already
        // started, update the timeout and start it
        if !state.view_change_timeout.is_active() && messages.len() as u64 > state.f * 2 {
            state.view_change_timeout = Timeout::new(
                state
                    .view_change_duration
                    .checked_mul((msg_view - state.view) as u32)
                    .expect("View change timeout has overflowed"),
            );
            state.view_change_timeout.start();
        }

        // If this node is the new primary and the required 2f ViewChange messages (not including
        // the primary's own) are present in the log, broadcast the NewView message
        let messages_from_other_nodes = messages
            .iter()
            .filter(|msg| !msg.from_self)
            .cloned()
            .collect::<Vec<_>>();

        if state.is_primary_at_view(msg_view)
            && messages_from_other_nodes.len() as u64 >= 2 * state.f
        {
            let mut new_view = PbftNewView::new();

            new_view.set_info(PbftMessageInfo::new_from(
                PbftMessageType::NewView,
                msg_view,
                state.seq_num - 1,
                state.id.clone(),
            ));

            new_view.set_view_changes(Self::signed_votes_from_messages(
                messages_from_other_nodes.as_slice(),
            ));

            trace!("Created NewView message: {:?}", new_view);

            self.broadcast_message(ParsedMessage::from_new_view_message(new_view)?, state)?;
        }

        Ok(())
    }

    /// Handle a `NewView` message
    ///
    /// When a `NewView` is received, verify that it is valid; if it is, update the view and the
    /// node's state.
    fn handle_new_view(
        &mut self,
        msg: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let new_view = msg.get_new_view_message();

        match self.verify_new_view(new_view, state) {
            Ok(_) => trace!("NewView passed verification"),
            Err(err) => {
                return Err(PbftError::InvalidMessage(format!(
                    "NewView failed verification - Error was: {}",
                    err
                )));
            }
        }

        // If this node was the primary before, cancel any block that may have been initialized
        if state.is_primary() {
            self.service.cancel_block().unwrap_or_else(|err| {
                info!("Failed to cancel block when becoming secondary: {:?}", err);
            });
        }

        // Update view
        state.view = new_view.get_info().get_view();
        state.view_change_timeout.stop();

        info!("{}: Updated to view {}", state, state.view);

        // Reset state to Normal mode, reset the phase (unless waiting for a BlockCommit) and
        // restart the idle timeout
        state.mode = PbftMode::Normal;
        if !matches!(state.phase, PbftPhase::Finishing(_)) {
            state.phase = PbftPhase::PrePreparing;
        }
        state.idle_timeout.start();

        // Initialize a new block if this node is the new primary
        if state.is_primary() {
            self.service.initialize_block(None).map_err(|err| {
                PbftError::ServiceError("Couldn't initialize block after view change".into(), err)
            })?;
        }

        Ok(())
    }

    /// Handle a `SealRequest` message
    ///
    /// A node is requesting a consensus seal for the last block. If the block was the last one
    /// committed by this node, build the seal and send it to the requesting node; if the block has
    /// not been committed yet but it's the next one to be committed, add the request to the log
    /// and the node will build/send the seal when it's done committing. If this is an older block
    /// (state.seq_num > msg.seq_num + 1) or this node is behind (state.seq_num < msg.seq_num), the
    /// node will not be able to build the requseted seal, so just ignore the message.
    fn handle_seal_request(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        if state.seq_num == msg.info().get_seq_num() + 1 {
            return self.send_seal_response(state, &msg.info().get_signer_id().to_vec());
        } else if state.seq_num == msg.info().get_seq_num() {
            self.msg_log.add_message(msg);
        }
        Ok(())
    }

    /// Handle a `Seal` message
    ///
    /// A node has responded to the seal request by sending a seal for the last block; validate the
    /// seal and commit the block.
    fn handle_seal_response(
        &mut self,
        msg: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let seal = msg.get_seal();

        // If the node has already committed the block, ignore
        if let PbftPhase::Finishing(_) = state.phase {
            return Ok(());
        }

        // Get the previous ID of the block this seal is for so it can be used to verify the seal
        let previous_id = self
            .msg_log
            .get_block_with_id(seal.block_id.as_slice())
            // Make sure the node actually has the block
            .ok_or_else(|| {
                PbftError::InvalidMessage(format!(
                    "Received a seal for a block ({:?}) that the node does not have",
                    hex::encode(&seal.block_id),
                ))
            })
            .and_then(|block| {
                // Make sure the block is at the node's current sequence number
                if block.block_num != state.seq_num {
                    Err(PbftError::InvalidMessage(format!(
                        "Received a seal for block {:?}, but block_num does not match node's \
                         seq_num: {} != {}",
                        hex::encode(&seal.block_id),
                        block.block_num,
                        state.seq_num,
                    )))
                } else {
                    Ok(block.previous_id.clone())
                }
            })?;

        // Verify the seal
        match self.verify_consensus_seal(seal, previous_id, state) {
            Ok(_) => {
                trace!("Consensus seal passed verification");
            }
            Err(err) => {
                return Err(PbftError::InvalidMessage(format!(
                    "Consensus seal failed verification - Error was: {}",
                    err
                )));
            }
        }

        // Catch up
        self.catchup(state, seal, false)
    }

    /// Handle a `BlockNew` update from the Validator
    ///
    /// The validator has received a new block; check if it is a block that should be considered,
    /// add it to the log as an unvalidated block, and instruct the validator to validate it.
    pub fn on_block_new(&mut self, block: Block, state: &mut PbftState) -> Result<(), PbftError> {
        info!(
            "{}: Got BlockNew: {} / {}",
            state,
            block.block_num,
            hex::encode(&block.block_id)
        );
        trace!("Block details: {:?}", block);

        // Only future blocks should be considered since committed blocks are final
        if block.block_num < state.seq_num {
            self.service
                .fail_block(block.block_id.clone())
                .unwrap_or_else(|err| error!("Couldn't fail block due to error: {:?}", err));
            return Err(PbftError::InternalError(format!(
                "Received block {:?} / {:?} that is older than the current sequence number: {:?}",
                block.block_num,
                hex::encode(&block.block_id),
                state.seq_num,
            )));
        }

        // Make sure the node already has the previous block, since the consensus seal can't be
        // verified without it
        let previous_block = self
            .msg_log
            .get_block_with_id(block.previous_id.as_slice())
            .or_else(|| {
                self.msg_log
                    .get_unvalidated_block_with_id(block.previous_id.as_slice())
            });
        if previous_block.is_none() {
            self.service
                .fail_block(block.block_id.clone())
                .unwrap_or_else(|err| error!("Couldn't fail block due to error: {:?}", err));
            return Err(PbftError::InternalError(format!(
                "Received block {:?} / {:?} but node does not have previous block {:?}",
                block.block_num,
                hex::encode(&block.block_id),
                hex::encode(&block.previous_id),
            )));
        }

        // Make sure that the previous block has the previous block number (enforces that blocks
        // are strictly monotically increasing by 1)
        let previous_block = previous_block.expect("Previous block's existence already checked");
        if previous_block.block_num != block.block_num - 1 {
            self.service
                .fail_block(block.block_id.clone())
                .unwrap_or_else(|err| error!("Couldn't fail block due to error: {:?}", err));
            return Err(PbftError::InternalError(format!(
                "Received block {:?} / {:?} but its previous block ({:?} / {:?}) does not have \
                 the previous block_num",
                block.block_num,
                hex::encode(&block.block_id),
                block.block_num - 1,
                hex::encode(&block.previous_id),
            )));
        }

        // Add the currently unvalidated block to the log
        self.msg_log.add_unvalidated_block(block.clone());

        // Have the validator check the block
        self.service
            .check_blocks(vec![block.block_id.clone()])
            .map_err(|err| {
                PbftError::ServiceError(
                    format!(
                        "Failed to check block {:?} / {:?}",
                        block.block_num,
                        hex::encode(&block.block_id),
                    ),
                    err,
                )
            })?;

        Ok(())
    }

    /// Handle a `BlockValid` update from the Validator
    ///
    /// The block has been verified by the validator, so mark it as validated in the log and
    /// attempt to handle the block.
    pub fn on_block_valid(
        &mut self,
        block_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        info!("Got BlockValid: {}", hex::encode(&block_id));

        // Mark block as validated in the log and get the block
        let block = self
            .msg_log
            .block_validated(block_id.clone())
            .ok_or_else(|| {
                PbftError::InvalidMessage(format!(
                    "Received BlockValid message for an unknown block: {}",
                    hex::encode(&block_id)
                ))
            })?;

        self.try_handling_block(block, state)
    }

    /// Validate the block's seal and handle the block. If this is the block the node is waiting
    /// for and this node is the primary, broadcast a PrePrepare; if the node isn't the primary but
    /// it already has the PrePrepare for this block, switch to `Preparing`. If this is a future
    /// block, use it to catch up.
    fn try_handling_block(&mut self, block: Block, state: &mut PbftState) -> Result<(), PbftError> {
        // If the block's number is higher than the current sequence number + 1 (i.e., it is newer
        // than the grandchild of the last committed block), the seal cannot be verified; this is
        // because the settings in a block's grandparent are needed to verify the block's seal, and
        // these settings are only guaranteed to be in the validator's state when the block is
        // committed. If this is a newer block, wait until after the grandparent is committed
        // before validating the seal and handling the block.
        if block.block_num > state.seq_num + 1 {
            return Ok(());
        }

        let seal = self
            .verify_consensus_seal_from_block(&block, state)
            .map_err(|err| {
                self.service
                    .fail_block(block.block_id.clone())
                    .unwrap_or_else(|err| error!("Couldn't fail block due to error: {:?}", err));
                PbftError::InvalidMessage(format!(
                    "Consensus seal failed verification - Error was: {}",
                    err
                ))
            })?;

        // This block's seal can be used to commit the block previous to it (i.e. catch-up) if it's
        // a future block and the node isn't waiting for a commit message for a previous block (if
        // it is waiting for a commit message, catch-up will have to be done after the message is
        // received)
        let is_waiting = matches!(state.phase, PbftPhase::Finishing(_));
        if block.block_num > state.seq_num && !is_waiting {
            self.catchup(state, &seal, true)?;
        } else if block.block_num == state.seq_num {
            if block.signer_id == state.id && state.is_primary() {
                // This is the next block and this node is the primary; broadcast PrePrepare
                // messages
                info!("Broadcasting PrePrepares");
                self.broadcast_pbft_message(
                    state.view,
                    state.seq_num,
                    PbftMessageType::PrePrepare,
                    block.block_id,
                    state,
                )?;
            } else {
                // If the node is in the PrePreparing phase and it already has a PrePrepare for
                // this block: switch to Preparing
                self.try_preparing(block.block_id, state)?;
            }
        }

        Ok(())
    }

    /// Handle a `BlockInvalid` update from the Validator
    ///
    /// The block is invalid, so drop it from the log and fail it.
    pub fn on_block_invalid(&mut self, block_id: BlockId) -> Result<(), PbftError> {
        info!("Got BlockInvalid: {}", hex::encode(&block_id));

        // Drop block from the log
        if !self.msg_log.block_invalidated(block_id.clone()) {
            return Err(PbftError::InvalidMessage(format!(
                "Received BlockInvalid message for an unknown block: {}",
                hex::encode(&block_id)
            )));
        }

        // Fail the block
        self.service
            .fail_block(block_id)
            .unwrap_or_else(|err| error!("Couldn't fail block due to error: {:?}", err));

        Ok(())
    }

    /// Use the given consensus seal to verify and commit the block this node is working on
    fn catchup(
        &mut self,
        state: &mut PbftState,
        seal: &PbftSeal,
        catchup_again: bool,
    ) -> Result<(), PbftError> {
        info!(
            "{}: Attempting to commit block {} using catch-up",
            state, state.seq_num
        );

        let messages = seal
            .get_commit_votes()
            .iter()
            .try_fold(Vec::new(), |mut msgs, vote| {
                msgs.push(ParsedMessage::from_signed_vote(vote)?);
                Ok(msgs)
            })?;

        // Update view if necessary
        let view = messages[0].info().get_view();
        if view != state.view {
            info!("Updating view from {} to {}", state.view, view);
            state.view = view;
        }

        // Add messages to the log
        for message in &messages {
            self.msg_log.add_message(message.clone());
        }

        // Commit the block, stop the idle timeout, and skip straight to Finishing
        self.service
            .commit_block(seal.block_id.clone())
            .map_err(|err| {
                PbftError::ServiceError(
                    format!(
                        "Failed to commit block with catch-up {:?} / {:?}",
                        state.seq_num,
                        hex::encode(&seal.block_id)
                    ),
                    err,
                )
            })?;
        state.idle_timeout.stop();
        state.phase = PbftPhase::Finishing(catchup_again);

        Ok(())
    }

    /// Handle a `BlockCommit` update from the Validator
    ///
    /// A block was sucessfully committed; clean up any uncommitted blocks, update state to be
    /// ready for the next block, make any necessary view and membership changes, garbage collect
    /// the logs, and start a new block if this node is the primary.
    pub fn on_block_commit(
        &mut self,
        block_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        info!("{}: Got BlockCommit for {}", state, hex::encode(&block_id));

        let is_catching_up = matches!(state.phase, PbftPhase::Finishing(true));

        // If there are any blocks in the log at this sequence number other than the one that was
        // just committed, reject them
        let invalid_block_ids = self
            .msg_log
            .get_blocks_with_num(state.seq_num)
            .iter()
            .filter_map(|block| {
                if block.block_id != block_id {
                    Some(block.block_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for id in invalid_block_ids {
            self.service.fail_block(id.clone()).unwrap_or_else(|err| {
                error!(
                    "Couldn't fail block {:?} due to error: {:?}",
                    &hex::encode(id),
                    err
                )
            });
        }

        // Increment sequence number and update state
        state.seq_num += 1;
        state.mode = PbftMode::Normal;
        state.phase = PbftPhase::PrePreparing;
        state.chain_head = block_id.clone();

        // If node(s) are waiting for a seal to commit the last block, send it now
        let requesters = self
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::SealRequest, state.seq_num - 1)
            .iter()
            .map(|req| req.info().get_signer_id().to_vec())
            .collect::<Vec<_>>();

        for req in requesters {
            self.send_seal_response(state, &req).unwrap_or_else(|err| {
                error!("Failed to send seal response due to: {:?}", err);
            });
        }

        // Update membership if necessary
        self.update_membership(block_id.clone(), state);

        // Increment the view if a view change must be forced for fairness
        if state.at_forced_view_change() {
            state.view += 1;
        }

        // Tell the log to garbage collect if it needs to
        self.msg_log.garbage_collect(state.seq_num);

        // If the node already has grandchild(ren) of the block that was just committed, one of
        // them may be used to perform catch-up to commit the next block.
        let grandchildren = self
            .msg_log
            .get_blocks_with_num(state.seq_num + 1)
            .iter()
            .cloned()
            .cloned()
            .collect::<Vec<_>>();
        for block in grandchildren {
            if self.try_handling_block(block, state).is_ok() {
                return Ok(());
            }
        }

        // If the node is catching up but doesn't have a block with a seal to commit the next one,
        // it will need to request the seal to commit the last block. The node doesn't know which
        // block that the network decided to commit, so it can't request the seal for a specific
        // block (puts an empty BlockId in the message)
        if is_catching_up {
            info!(
                "{}: Requesting seal to finish catch-up to block {}",
                state, state.seq_num
            );
            return self.broadcast_pbft_message(
                state.view,
                state.seq_num,
                PbftMessageType::SealRequest,
                BlockId::new(),
                state,
            );
        }

        // Start the idle timeout for the next block
        state.idle_timeout.start();

        // If we already have a block at this sequence number with a valid PrePrepare for it, start
        // Preparing (there may be multiple blocks, but only one will have a valid PrePrepare)
        let block_ids = self
            .msg_log
            .get_blocks_with_num(state.seq_num)
            .iter()
            .map(|block| block.block_id.clone())
            .collect::<Vec<_>>();
        for id in block_ids {
            self.try_preparing(id, state)?;
        }

        // Initialize a new block if this node is the primary and it is not in the process of
        // catching up
        if state.is_primary() {
            info!(
                "{}: Initializing block on top of {}",
                state,
                hex::encode(&block_id)
            );
            self.service
                .initialize_block(Some(block_id))
                .map_err(|err| {
                    PbftError::ServiceError("Couldn't initialize block after commit".into(), err)
                })?;
        }

        Ok(())
    }

    /// Check the on-chain list of members; if it has changed, update members list and return true.
    ///
    /// # Panics
    /// + If the `sawtooth.consensus.pbft.members` setting is unset or invalid
    /// + If the network this node is on does not have enough nodes to be Byzantine fault tolernant
    fn update_membership(&mut self, block_id: BlockId, state: &mut PbftState) {
        // Get list of members from settings (retry until a valid result is received)
        trace!("Getting on-chain list of members to check for membership updates");
        let settings = retry_until_ok(
            state.exponential_retry_base,
            state.exponential_retry_max,
            || {
                self.service.get_settings(
                    block_id.clone(),
                    vec![String::from("sawtooth.consensus.pbft.members")],
                )
            },
        );
        let on_chain_members = get_members_from_settings(&settings);

        if on_chain_members != state.member_ids {
            info!("Updating membership: {:?}", on_chain_members);
            state.member_ids = on_chain_members;
            let f = (state.member_ids.len() - 1) / 3;
            if f == 0 {
                panic!("This network no longer contains enough nodes to be fault tolerant");
            }
            state.f = f as u64;
        }
    }

    /// When the node has a block and a corresponding PrePrepare for its current sequence number,
    /// and it is in the PrePreparing phase, it can enter the Preparing phase and broadcast its
    /// Prepare
    fn try_preparing(&mut self, block_id: BlockId, state: &mut PbftState) -> Result<(), PbftError> {
        if let Some(block) = self.msg_log.get_block_with_id(&block_id) {
            if state.phase == PbftPhase::PrePreparing
                && self.msg_log.has_pre_prepare(state.seq_num, state.view, &block_id)
                // PrePrepare.seq_num == state.seq_num == block.block_num enforces the one-to-one
                // correlation between seq_num and block_num (PrePrepare n should be for block n)
                && block.block_num == state.seq_num
            {
                state.switch_phase(PbftPhase::Preparing)?;

                // Stop idle timeout, since a new block and valid PrePrepare were received in time
                state.idle_timeout.stop();

                // Now start the commit timeout in case the network fails to commit the block
                // within a reasonable amount of time
                state.commit_timeout.start();

                // The primary doesn't broadcast a Prepare; its PrePrepare counts as its "vote"
                if !state.is_primary() {
                    self.broadcast_pbft_message(
                        state.view,
                        state.seq_num,
                        PbftMessageType::Prepare,
                        block_id,
                        state,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Handle a `PeerConnected` update from the Validator
    ///
    /// A peer has just connected to this node. Send a bootstrap commit message if the peer is part
    /// of the network and the node isn't at the genesis block.
    pub fn on_peer_connected(
        &mut self,
        peer_id: PeerId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Ignore if the peer is not a member of the PBFT network or the chain head is block 0
        if !state.member_ids.contains(&peer_id) || state.seq_num == 1 {
            return Ok(());
        }

        self.broadcast_bootstrap_commit(peer_id, state)
    }

    /// When the whole network is starting "fresh" from a non-genesis block, none of the nodes will
    /// have the `Commit` messages necessary to build the consensus seal for the last committed
    /// block (the chain head). To bootstrap the network in this scenario, all nodes will send a
    /// `Commit` message for their chain head whenever one of the PBFT members connects; when
    /// > 2f + 1 nodes have connected and received these `Commit` messages, the nodes will be able
    /// to build a seal using the messages.
    fn broadcast_bootstrap_commit(
        &mut self,
        peer_id: PeerId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // The network must agree on a single view number for the Commit messages, so the view
        // of the chain head's predecessor is used. For block 1 this is view 0; otherwise, it's the
        // view of the block's consensus seal
        let view = if state.seq_num == 2 {
            0
        } else {
            self.msg_log
                .get_block_with_id(&state.chain_head)
                .ok_or_else(|| {
                    PbftError::InternalError(format!(
                        "Node does not have chain head ({:?}) in its log",
                        state.chain_head
                    ))
                })
                .and_then(|block| {
                    PbftSeal::parse_from_bytes(&block.payload).map_err(|err| {
                        PbftError::SerializationError(
                            "Error parsing seal from chain head".into(),
                            err,
                        )
                    })
                })?
                .get_info()
                .get_view()
        };

        // Construct the commit message for the chain head and send it to the connected peer
        let mut commit = PbftMessage::new();
        commit.set_info(PbftMessageInfo::new_from(
            PbftMessageType::Commit,
            view,
            state.seq_num - 1,
            state.id.clone(),
        ));
        commit.set_block_id(state.chain_head.clone());

        let bytes = commit.write_to_bytes().map_err(|err| {
            PbftError::SerializationError("Error writing commit to bytes".into(), err)
        })?;

        self.service
            .send_to(
                &peer_id,
                String::from(PbftMessageType::Commit).as_str(),
                bytes,
            )
            .map_err(|err| {
                PbftError::ServiceError(
                    format!("Failed to send Commit to {:?}", hex::encode(peer_id)),
                    err,
                )
            })
    }

    // ---------- Methods for building & verifying proofs and signed messages from other nodes ----------

    /// Generate a `protobuf::RepeatedField` of signed votes from a list of parsed messages
    fn signed_votes_from_messages(msgs: &[&ParsedMessage]) -> RepeatedField<PbftSignedVote> {
        RepeatedField::from(
            msgs.iter()
                .map(|m| {
                    let mut vote = PbftSignedVote::new();

                    vote.set_header_bytes(m.header_bytes.clone());
                    vote.set_header_signature(m.header_signature.clone());
                    vote.set_message_bytes(m.message_bytes.clone());

                    vote
                })
                .collect::<Vec<_>>(),
        )
    }

    /// Build a consensus seal that proves the last block committed by this node
    fn build_seal(&self, state: &PbftState) -> Result<PbftSeal, PbftError> {
        trace!("{}: Building seal for block {}", state, state.seq_num - 1);

        // The previous block may have been committed in a different view, so the node will need to
        // find the view that contains the required 2f Commit messages for building the seal
        let (block_id, view, messages) = self
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::Commit, state.seq_num - 1)
            .iter()
            // Filter out this node's own messages because self-sent messages aren't signed and
            // therefore can't be included in the seal
            .filter(|msg| !msg.from_self)
            .cloned()
            // Map to ((block_id, view), msg)
            .map(|msg| ((msg.get_block_id(), msg.info().get_view()), msg))
            // Group messages together by block and view
            .into_group_map()
            .into_iter()
            // One and only one block/view should have the required number of messages, since only
            // one block at this sequence number should have been committed and in only one view
            .find_map(|((block_id, view), msgs)| {
                if msgs.len() as u64 >= 2 * state.f {
                    Some((block_id, view, msgs))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                PbftError::InternalError(String::from(
                    "Couldn't find 2f commit messages in the message log for building a seal",
                ))
            })?;

        let mut seal = PbftSeal::new();
        seal.set_info(PbftMessageInfo::new_from(
            PbftMessageType::Seal,
            view,
            state.seq_num - 1,
            state.id.clone(),
        ));
        seal.set_block_id(block_id);
        seal.set_commit_votes(Self::signed_votes_from_messages(messages.as_slice()));

        trace!("Seal created: {:?}", seal);

        Ok(seal)
    }

    /// Verify that a vote matches the expected type, is properly signed, and passes the specified
    /// criteria; if it passes verification, return the signer ID to be used for further
    /// verification
    fn verify_vote<F>(
        vote: &PbftSignedVote,
        expected_type: PbftMessageType,
        validation_criteria: F,
    ) -> Result<PeerId, PbftError>
    where
        F: Fn(&PbftMessage) -> Result<(), PbftError>,
    {
        // Parse the message
        let pbft_message: PbftMessage = Message::parse_from_bytes(vote.get_message_bytes())
            .map_err(|err| {
                PbftError::SerializationError("Error parsing PbftMessage from vote".into(), err)
            })?;
        let header: ConsensusPeerMessageHeader = Message::parse_from_bytes(vote.get_header_bytes())
            .map_err(|err| {
                PbftError::SerializationError("Error parsing header from vote".into(), err)
            })?;

        trace!(
            "Verifying vote with PbftMessage: {:?} and header: {:?}",
            pbft_message,
            header
        );

        // Verify the header's signer matches the PbftMessage's signer
        if header.signer_id != pbft_message.get_info().get_signer_id() {
            return Err(PbftError::InvalidMessage(format!(
                "Received a vote where PbftMessage's signer ID ({:?}) and PeerMessage's signer ID \
                 ({:?}) don't match",
                pbft_message.get_info().get_signer_id(),
                header.signer_id
            )));
        }

        // Verify the message type
        let msg_type = PbftMessageType::from(pbft_message.get_info().get_msg_type());
        if msg_type != expected_type {
            return Err(PbftError::InvalidMessage(format!(
                "Received a {:?} vote, but expected a {:?}",
                msg_type, expected_type
            )));
        }

        // Verify the signature
        let key = Secp256k1PublicKey::from_hex(&hex::encode(&header.signer_id)).map_err(|err| {
            PbftError::SigningError(format!(
                "Couldn't parse public key from signer ID ({:?}) due to error: {:?}",
                header.signer_id, err
            ))
        })?;
        let context = create_context("secp256k1").map_err(|err| {
            PbftError::SigningError(format!("Couldn't create context due to error: {}", err))
        })?;

        match context.verify(
            &hex::encode(vote.get_header_signature()),
            vote.get_header_bytes(),
            &key,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Err(PbftError::SigningError(format!(
                    "Vote ({}) failed signature verification",
                    vote
                )));
            }
            Err(err) => {
                return Err(PbftError::SigningError(format!(
                    "Error while verifying vote signature: {:?}",
                    err
                )));
            }
        }

        verify_sha512(vote.get_message_bytes(), header.get_content_sha512())?;

        // Validate against the specified criteria
        validation_criteria(&pbft_message)?;

        Ok(PeerId::from(pbft_message.get_info().get_signer_id()))
    }

    /// Verify that a NewView messsage is valid
    fn verify_new_view(
        &mut self,
        new_view: &PbftNewView,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Make sure this is for a future view (prevents re-using old NewView messages)
        if new_view.get_info().get_view() <= state.view {
            return Err(PbftError::InvalidMessage(format!(
                "Node is on view {}, but received NewView message for view {}",
                state.view,
                new_view.get_info().get_view(),
            )));
        }

        // Make sure this is from the new primary
        if *new_view.get_info().get_signer_id()
            != state.get_primary_id_at_view(new_view.get_info().get_view())
        {
            return Err(PbftError::InvalidMessage(format!(
                "Received NewView message for view {} that is not from the primary for that view",
                new_view.get_info().get_view()
            )));
        }

        // Verify each individual vote and extract the signer ID from each ViewChange so the IDs
        // can be verified
        let voter_ids =
            new_view
                .get_view_changes()
                .iter()
                .try_fold(HashSet::new(), |mut ids, vote| {
                    Self::verify_vote(vote, PbftMessageType::ViewChange, |msg| {
                        if msg.get_info().get_view() != new_view.get_info().get_view() {
                            return Err(PbftError::InvalidMessage(format!(
                                "ViewChange's view number ({}) doesn't match NewView's view \
                                 number ({})",
                                msg.get_info().get_view(),
                                new_view.get_info().get_view(),
                            )));
                        }
                        Ok(())
                    })
                    .map(|id| ids.insert(id))?;
                    Ok(ids)
                })?;

        // All of the votes must come from PBFT members, and the primary can't explicitly vote
        // itself, since broacasting the NewView is an implicit vote. Check that the votes received
        // are from a subset of "members - primary".
        let peer_ids: HashSet<_> = state
            .member_ids
            .iter()
            .cloned()
            .filter(|pid| pid != &PeerId::from(new_view.get_info().get_signer_id()))
            .collect();

        trace!(
            "Comparing voter IDs ({:?}) with member IDs - primary ({:?})",
            voter_ids,
            peer_ids
        );

        if !voter_ids.is_subset(&peer_ids) {
            return Err(PbftError::InvalidMessage(format!(
                "NewView contains vote(s) from invalid IDs: {:?}",
                voter_ids.difference(&peer_ids).collect::<Vec<_>>()
            )));
        }

        // Check that the NewView contains 2f votes (primary vote is implicit, so total of 2f + 1)
        if (voter_ids.len() as u64) < 2 * state.f {
            return Err(PbftError::InvalidMessage(format!(
                "NewView needs {} votes, but only {} found",
                2 * state.f,
                voter_ids.len()
            )));
        }

        Ok(())
    }

    /// Verify the consensus seal from the current block that proves the previous block and return
    /// the parsed seal
    fn verify_consensus_seal_from_block(
        &mut self,
        block: &Block,
        state: &mut PbftState,
    ) -> Result<PbftSeal, PbftError> {
        // Since block 0 is genesis, block 1 is the first that can be verified with a seal; this
        // means that the node won't see a seal until block 2
        if block.block_num < 2 {
            return Ok(PbftSeal::new());
        }

        // Parse the seal
        if block.payload.is_empty() {
            return Err(PbftError::InvalidMessage(
                "Block published without a seal".into(),
            ));
        }

        let seal: PbftSeal = Message::parse_from_bytes(&block.payload).map_err(|err| {
            PbftError::SerializationError("Error parsing seal for verification".into(), err)
        })?;

        trace!("Parsed seal: {}", seal);

        // Make sure this is the correct seal for the previous block
        if seal.block_id != block.previous_id[..] {
            return Err(PbftError::InvalidMessage(format!(
                "Seal's ID ({}) doesn't match block's previous ID ({})",
                hex::encode(&seal.block_id),
                hex::encode(&block.previous_id)
            )));
        }

        // Get the previous ID of the block this seal is supposed to prove so it can be used to
        // verify the seal
        let proven_block_previous_id = self
            .msg_log
            .get_block_with_id(seal.block_id.as_slice())
            .map(|proven_block| proven_block.previous_id.clone())
            .ok_or_else(|| {
                PbftError::InternalError(format!(
                    "Got seal for block {:?}, but block was not found in the log",
                    seal.block_id,
                ))
            })?;

        // Verify the seal itself
        self.verify_consensus_seal(&seal, proven_block_previous_id, state)?;

        Ok(seal)
    }

    /// Verify the given consenus seal
    ///
    /// # Panics
    /// + If the `sawtooth.consensus.pbft.members` setting is unset or invalid
    fn verify_consensus_seal(
        &mut self,
        seal: &PbftSeal,
        previous_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Verify each individual vote and extract the signer ID from each PbftMessage so the IDs
        // can be verified
        let voter_ids =
            seal.get_commit_votes()
                .iter()
                .try_fold(HashSet::new(), |mut ids, vote| {
                    Self::verify_vote(vote, PbftMessageType::Commit, |msg| {
                        // Make sure all votes are for the right block
                        if msg.block_id != seal.block_id {
                            return Err(PbftError::InvalidMessage(format!(
                                "Commit vote's block ID ({:?}) doesn't match seal's ID ({:?})",
                                msg.block_id, seal.block_id
                            )));
                        }
                        // Make sure all votes are for the right view
                        if msg.get_info().get_view() != seal.get_info().get_view() {
                            return Err(PbftError::InvalidMessage(format!(
                                "Commit vote's view ({:?}) doesn't match seal's view ({:?})",
                                msg.get_info().get_view(),
                                seal.get_info().get_view()
                            )));
                        }
                        // Make sure all votes are for the right sequence number
                        if msg.get_info().get_seq_num() != seal.get_info().get_seq_num() {
                            return Err(PbftError::InvalidMessage(format!(
                                "Commit vote's seq_num ({:?}) doesn't match seal's seq_num ({:?})",
                                msg.get_info().get_seq_num(),
                                seal.get_info().get_seq_num()
                            )));
                        }
                        Ok(())
                    })
                    .map(|id| ids.insert(id))?;
                    Ok(ids)
                })?;

        // All of the votes in a seal must come from PBFT members, and the primary can't explicitly
        // vote itself, since building a consensus seal is an implicit vote. Check that the votes
        // received are from a subset of "members - seal creator". Use the list of members from the
        // block previous to the one this seal verifies, since that represents the state of the
        // network at the time this block was voted on.
        trace!("Getting on-chain list of members to verify seal");
        let settings = retry_until_ok(
            state.exponential_retry_base,
            state.exponential_retry_max,
            || {
                self.service.get_settings(
                    previous_id.clone(),
                    vec![String::from("sawtooth.consensus.pbft.members")],
                )
            },
        );
        let members = get_members_from_settings(&settings);

        // Verify that the seal's signer is a PBFT member
        if !members.contains(&seal.get_info().get_signer_id().to_vec()) {
            return Err(PbftError::InvalidMessage(format!(
                "Consensus seal is signed by an unknown peer: {:?}",
                seal.get_info().get_signer_id()
            )));
        }

        let peer_ids: HashSet<_> = members
            .iter()
            .cloned()
            .filter(|pid| pid.as_slice() != seal.get_info().get_signer_id())
            .collect();

        trace!(
            "Comparing voter IDs ({:?}) with on-chain member IDs - primary ({:?})",
            voter_ids,
            peer_ids
        );

        if !voter_ids.is_subset(&peer_ids) {
            return Err(PbftError::InvalidMessage(format!(
                "Consensus seal contains vote(s) from invalid ID(s): {:?}",
                voter_ids.difference(&peer_ids).collect::<Vec<_>>()
            )));
        }

        // Check that the seal contains 2f votes (primary vote is implicit, so total of 2f + 1)
        if (voter_ids.len() as u64) < 2 * state.f {
            return Err(PbftError::InvalidMessage(format!(
                "Consensus seal needs {} votes, but only {} found",
                2 * state.f,
                voter_ids.len()
            )));
        }

        Ok(())
    }

    // ---------- Methods called in the main engine loop to periodically check and update state ----------

    /// At a regular interval, try to finalize a block when the primary is ready
    pub fn try_publish(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        // Only the primary takes care of this, and we try publishing a block
        // on every engine loop, even if it's not yet ready. This isn't an error,
        // so just return Ok(()).
        if !state.is_primary() || state.phase != PbftPhase::PrePreparing {
            return Ok(());
        }

        trace!("{}: Attempting to summarize block", state);

        match self.service.summarize_block() {
            Ok(_) => {}
            Err(err) => {
                trace!("Couldn't summarize, so not finalizing: {}", err);
                return Ok(());
            }
        }

        // We don't publish a consensus seal at block 1, since we never receive any
        // votes on the genesis block. Leave payload blank for the first block.
        let data = if state.seq_num <= 1 {
            vec![]
        } else {
            self.build_seal(state)?.write_to_bytes().map_err(|err| {
                PbftError::SerializationError("Error writing seal to bytes".into(), err)
            })?
        };

        match self.service.finalize_block(data) {
            Ok(block_id) => {
                info!("{}: Publishing block {}", state, hex::encode(&block_id));
                Ok(())
            }
            Err(err) => Err(PbftError::ServiceError(
                "Couldn't finalize block".into(),
                err,
            )),
        }
    }

    /// Check to see if the idle timeout has expired
    pub fn check_idle_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.idle_timeout.check_expired()
    }

    /// Start the idle timeout
    pub fn start_idle_timeout(&self, state: &mut PbftState) {
        state.idle_timeout.start();
    }

    /// Check to see if the commit timeout has expired
    pub fn check_commit_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.commit_timeout.check_expired()
    }

    /// Start the commit timeout
    pub fn start_commit_timeout(&self, state: &mut PbftState) {
        state.commit_timeout.start();
    }

    /// Check to see if the view change timeout has expired
    pub fn check_view_change_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.view_change_timeout.check_expired()
    }

    // ---------- Methods for communication between nodes ----------

    /// Construct a PbftMessage message and broadcast it to all peers (including self)
    fn broadcast_pbft_message(
        &mut self,
        view: u64,
        seq_num: u64,
        msg_type: PbftMessageType,
        block_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let mut msg = PbftMessage::new();
        msg.set_info(PbftMessageInfo::new_from(
            msg_type,
            view,
            seq_num,
            state.id.clone(),
        ));
        msg.set_block_id(block_id);

        trace!("{}: Created PBFT message: {:?}", state, msg);

        self.broadcast_message(ParsedMessage::from_pbft_message(msg)?, state)
    }

    /// Broadcast the specified message to all of the node's peers, including itself
    fn broadcast_message(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Broadcast to peers
        self.service
            .broadcast(
                String::from(msg.info().get_msg_type()).as_str(),
                msg.message_bytes.clone(),
            )
            .unwrap_or_else(|err| {
                error!(
                    "Couldn't broadcast message ({:?}) due to error: {}",
                    msg, err
                )
            });

        // Send to self
        self.on_peer_message(msg, state)
    }

    /// Build a consensus seal for the last block this node committed and send it to the node that
    /// requested the seal (the `recipient`)
    #[allow(clippy::ptr_arg)]
    fn send_seal_response(
        &mut self,
        state: &PbftState,
        recipient: &PeerId,
    ) -> Result<(), PbftError> {
        let seal = self.build_seal(state).map_err(|err| {
            PbftError::InternalError(format!("Failed to build requested seal due to: {}", err))
        })?;

        let msg_bytes = seal.write_to_bytes().map_err(|err| {
            PbftError::SerializationError("Error writing seal to bytes".into(), err)
        })?;

        // Send the seal to the requester
        self.service
            .send_to(
                recipient,
                String::from(PbftMessageType::Seal).as_str(),
                msg_bytes,
            )
            .map_err(|err| {
                PbftError::ServiceError(
                    format!(
                        "Failed to send requested seal to {:?}",
                        hex::encode(recipient)
                    ),
                    err,
                )
            })
    }

    // ---------- Miscellaneous methods ----------

    /// Start a view change when this node suspects that the primary is faulty
    ///
    /// Update state to reflect that the node is now in the process of this view change, start the
    /// view change timeout, and broadcast a view change message
    ///
    /// # Panics
    /// + If the view change timeout overflows
    pub fn start_view_change(&mut self, state: &mut PbftState, view: u64) -> Result<(), PbftError> {
        // Do not send messages again if we are already in the midst of this or a later view change
        if match state.mode {
            PbftMode::ViewChanging(v) => view <= v,
            _ => false,
        } {
            return Ok(());
        }

        info!("{}: Starting change to view {}", state, view);

        state.mode = PbftMode::ViewChanging(view);

        // Stop the idle and commit timeouts because they are not needed until after the view
        // change
        state.idle_timeout.stop();
        state.commit_timeout.stop();

        // Stop the view change timeout if it is already active (will be restarted when 2f + 1
        // ViewChange messages for the new view are received)
        state.view_change_timeout.stop();

        // Broadcast the view change message
        self.broadcast_pbft_message(
            view,
            state.seq_num - 1,
            PbftMessageType::ViewChange,
            BlockId::new(),
            state,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_handle_update;
    use crate::hash::hash_sha512;
    use crate::message_type::PbftMessageWrapper;
    use crate::protos::pbft_message::PbftMessageInfo;
    use crate::test_helpers::*;
    use sawtooth_sdk::consensus::engine::{Error, PeerId, PeerMessage, Update};
    use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
    use serde_json;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::default::Default;
    use std::rc::Rc;

    /// Turns a series of items into a `Vec<String>` for easily tracking and checking for function
    /// calls to the MockService
    macro_rules! stringify_func_call {
        ( $( $x:expr ),* ) => {
            {
                let mut output = Vec::new();
                $(
                    output.push(format!("{:?}", $x));
                )*
                output
            }
        }
    }

    /// Implementation of the consensus' `Service` trait that's used to mock out interactions with
    /// the Sawtooth validator. The `MockService` will track calls to its methods and supports
    /// configurable return values for some of its methods.
    #[derive(Clone)]
    struct MockService {
        /// A list of function calls, where each function call is a list of the form (func_name,
        /// arg1, arg2, ...)
        calls: Rc<RefCell<Vec<Vec<String>>>>,
        /// For each block ID, the settings value to return when `get_settings` is called
        settings: Rc<RefCell<HashMap<BlockId, HashMap<String, String>>>>,
        /// Determines the return value of the `summarize_block` method
        summarize_block_return_val: Rc<RefCell<Result<Vec<u8>, Error>>>,
    }

    impl MockService {
        /// Create a new `MockService` and set the members setting based on the `PbftConfig`
        fn new(cfg: &PbftConfig) -> Self {
            let members: Vec<_> = cfg.members.iter().map(hex::encode).collect();
            let service = MockService {
                calls: Default::default(),
                settings: Default::default(),
                summarize_block_return_val: Rc::new(RefCell::new(Ok(Default::default()))),
            };
            // Set the default settings
            let mut default_settings = HashMap::new();
            default_settings.insert(
                "sawtooth.consensus.pbft.members".to_string(),
                serde_json::to_string(&members).unwrap(),
            );
            service
                .settings
                .borrow_mut()
                .insert(vec![0], default_settings);

            service
        }

        /// Indicates if the specified method was called
        fn was_called(&self, method_name: &str) -> bool {
            self.calls
                .borrow()
                .iter()
                .any(|call| call[0] == format!("{:?}", method_name))
        }

        /// Indicates if the specified method was called with the given arguments (allows partial
        /// args)
        fn was_called_with_args(&self, call: Vec<String>) -> bool {
            self.calls
                .borrow()
                .iter()
                .any(|logged_call| logged_call.starts_with(&call))
        }

        /// Indicates if the specified method was called with the given arguments only once (allows
        /// partial args)
        fn was_called_with_args_once(&self, call: Vec<String>) -> bool {
            self.calls
                .borrow()
                .iter()
                .filter(|logged_call| logged_call.starts_with(&call))
                .count()
                == 1
        }
    }

    impl Service for MockService {
        fn send_to(
            &mut self,
            peer: &PeerId,
            message_type: &str,
            payload: Vec<u8>,
        ) -> Result<(), Error> {
            self.calls.borrow_mut().push(stringify_func_call!(
                "send_to",
                peer,
                message_type,
                payload
            ));
            Ok(())
        }
        fn broadcast(&mut self, message_type: &str, payload: Vec<u8>) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("broadcast", message_type, payload));
            Ok(())
        }
        fn initialize_block(&mut self, previous_id: Option<BlockId>) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("initialize_block", previous_id));
            Ok(())
        }
        fn summarize_block(&mut self) -> Result<Vec<u8>, Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("summarize_block"));
            self.summarize_block_return_val
                .replace(Ok(Default::default()))
        }
        fn finalize_block(&mut self, data: Vec<u8>) -> Result<BlockId, Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("finalize_block", data));
            Ok(Default::default())
        }
        fn cancel_block(&mut self) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("cancel_block"));
            Ok(())
        }
        fn check_blocks(&mut self, priority: Vec<BlockId>) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("check_blocks", priority));
            Ok(())
        }
        fn commit_block(&mut self, block_id: BlockId) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("commit_block", block_id));
            Ok(())
        }
        fn ignore_block(&mut self, block_id: BlockId) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("ignore_block", block_id));
            Ok(())
        }
        fn fail_block(&mut self, block_id: BlockId) -> Result<(), Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("fail_block", block_id));
            Ok(())
        }
        fn get_blocks(
            &mut self,
            block_ids: Vec<BlockId>,
        ) -> Result<HashMap<BlockId, Block>, Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("get_blocks", block_ids));
            Ok(Default::default())
        }
        fn get_chain_head(&mut self) -> Result<Block, Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("get_chain_head"));
            Ok(Default::default())
        }
        fn get_settings(
            &mut self,
            block_id: BlockId,
            settings: Vec<String>,
        ) -> Result<HashMap<String, String>, Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("get_settings", block_id, settings));
            let settings = self.settings.borrow();
            Ok(settings
                .get(&block_id)
                .unwrap_or_else(|| {
                    // Fall back to defualt settings (in block 0)
                    settings.get(&vec![0]).expect("Default settings not set")
                })
                .clone())
        }
        fn get_state(
            &mut self,
            block_id: BlockId,
            addresses: Vec<String>,
        ) -> Result<HashMap<String, Vec<u8>>, Error> {
            self.calls
                .borrow_mut()
                .push(stringify_func_call!("get_state", block_id, addresses));
            Ok(Default::default())
        }
    }

    struct KeyPair {
        pub_key: Vec<u8>,
        priv_key: Vec<u8>,
    }

    /// Create a list of public/private key pairs for the specified number of nodes
    fn mock_signer_network(size: u8) -> Vec<KeyPair> {
        let context = create_context("secp256k1").expect("Failed to create context");
        (0..size)
            .map(|_| {
                let priv_key = context
                    .new_random_private_key()
                    .expect("Failed to generate new private key");
                let pub_key = context
                    .get_public_key(&*priv_key)
                    .expect("Failed to get public key");
                KeyPair {
                    pub_key: pub_key.as_slice().to_vec(),
                    priv_key: priv_key.as_slice().to_vec(),
                }
            })
            .collect()
    }

    /// Create a mock configuration for the list of signers generated by `mock_signer_network`
    fn mock_config_from_signer_network(keys: &[KeyPair]) -> PbftConfig {
        let mut config = PbftConfig::default();
        config.members = keys
            .iter()
            .map(|key_pair| key_pair.pub_key.clone())
            .collect();
        config
    }

    /// Create a new PbftNode, PbftState, and MockService based on the given config, node ID, and
    /// chain head
    fn mock_node(
        cfg: &PbftConfig,
        node_id: PeerId,
        chain_head: Block,
    ) -> (PbftNode, PbftState, MockService) {
        let mut state = PbftState::new(node_id.clone(), chain_head.block_num, cfg);
        let service = MockService::new(cfg);
        (
            PbftNode::new(
                cfg,
                chain_head.clone(),
                vec![],
                Box::new(service.clone()),
                &mut state,
            ),
            state,
            service,
        )
    }

    /// Create a validly-signed PbftSignedVote
    fn mock_vote(
        msg_type: PbftMessageType,
        view: u64,
        seq_num: u64,
        block_id: BlockId,
        signer: &KeyPair,
    ) -> PbftSignedVote {
        let info = PbftMessageInfo::new_from(msg_type, view, seq_num, signer.pub_key.clone());
        let mut msg = PbftMessage::new();
        msg.set_info(info);
        msg.set_block_id(block_id);
        let msg_bytes = msg
            .write_to_bytes()
            .expect("Failed to write msg to bytes for mock vote");

        let mut header = ConsensusPeerMessageHeader::new();
        header.set_signer_id(signer.pub_key.clone());
        header.set_content_sha512(hash_sha512(&msg_bytes));

        let header_bytes = header
            .write_to_bytes()
            .expect("Failed to write header to bytes");
        let header_signature = hex::decode(
            create_context("secp256k1")
                .expect("Failed to create context")
                .sign(
                    &header_bytes,
                    &Secp256k1PrivateKey::from_hex(&hex::encode(signer.priv_key.clone()))
                        .expect("Failed to create private key from hex"),
                )
                .expect("Failed to sign header"),
        )
        .expect("Failed to decode signed header");

        let mut vote = PbftSignedVote::new();
        vote.set_header_bytes(header_bytes);
        vote.set_header_signature(header_signature);
        vote.set_message_bytes(msg_bytes.to_vec());
        vote
    }

    /// Create a PbftNewView
    fn mock_new_view(
        view: u64,
        seq_num: u64,
        signer: &KeyPair,
        votes: Vec<PbftSignedVote>,
    ) -> PbftNewView {
        let mut new_view = PbftNewView::new();
        new_view.set_info(PbftMessageInfo::new_from(
            PbftMessageType::NewView,
            view,
            seq_num,
            signer.pub_key.clone(),
        ));
        new_view.set_view_changes(RepeatedField::from(votes));
        new_view
    }

    /// Create a PbftSeal
    fn mock_seal(
        view: u64,
        seq_num: u64,
        block_id: BlockId,
        signer: &KeyPair,
        votes: Vec<PbftSignedVote>,
    ) -> PbftSeal {
        let mut seal = PbftSeal::new();
        seal.set_info(PbftMessageInfo::new_from(
            PbftMessageType::Seal,
            view,
            seq_num,
            signer.pub_key.clone(),
        ));
        seal.set_block_id(block_id);
        seal.set_commit_votes(RepeatedField::from(votes));
        seal
    }

    /// This test will verify that when the `PbftNode::new` method is called, it will return a
    /// `PbftNode` after performing the following actions:
    ///
    /// 1. Add the chain head to the log
    /// 2. Set the state's chain head to the block ID of the chain head
    /// 3. If the chain head has a consensus seal, update view to match the seal's
    /// 4. Initialize a new block by calling the `Service::initialize_block` method if the node is
    ///    the primary
    #[test]
    fn test_node_init() {
        // Create chain head with a consensus seal
        let key_pairs = mock_signer_network(3);
        let mut head = mock_block(2);
        head.payload = mock_seal(
            1,
            1,
            vec![1],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 1, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");

        // Verify chain head is added to the log, chain head and view are set, and primary calls
        // Service::initialize_block()
        let (node1, state1, service1) = mock_node(&mock_config(4), vec![1], head.clone());
        assert!(node1.msg_log.get_block_with_id(&head.block_id).is_some());
        assert_eq!(vec![2], state1.chain_head);
        assert_eq!(1, state1.view);
        assert!(service1.was_called_with_args(stringify_func_call!(
            "initialize_block",
            None as Option<BlockId>
        )));

        // Verify non-primary does not call Service::initialize_block()
        let (_, _, service0) = mock_node(&mock_config(4), vec![0], head.clone());
        assert!(!service0.was_called("initialize_block"));
    }

    /// To build a valid consensus seal or a valid `NewView` message, nodes must be able to convert
    /// a series of `ParsedMessage`s into `PbftSignedVote`s that can be included in the protobuf
    /// messages. The `PbftNode::signed_votes_from_messages` method is responsible for constructing
    /// a `RepeatedField` protobuf struct that can be placed directly into the `PbftSeal` and
    /// `PbftNewView` protobuf messages.
    #[test]
    fn test_vote_list_construction() {
        // Create 3 ParsedMessages with different messages, header bytes, and header signatures
        let mut msg1 = mock_msg(PbftMessageType::Commit, 0, 1, vec![0], vec![1], false);
        msg1.header_bytes = vec![0, 1, 2];
        msg1.header_signature = vec![3, 4, 5];
        let mut msg2 = mock_msg(PbftMessageType::Commit, 0, 1, vec![1], vec![1], false);
        msg2.header_bytes = vec![6, 7, 8];
        msg2.header_signature = vec![9, 10, 11];
        let mut msg3 = mock_msg(PbftMessageType::Commit, 0, 1, vec![2], vec![1], false);
        msg3.header_bytes = vec![12, 13, 14];
        msg3.header_signature = vec![15, 16, 17];
        let msgs = vec![&msg1, &msg2, &msg3];

        // Create the PbftSignedVotes
        let votes = PbftNode::signed_votes_from_messages(&msgs).into_vec();

        // Verify that the votes match the original messages
        msgs.iter().zip(votes.iter()).for_each(|(msg, vote)| {
            assert_eq!(msg.message_bytes, vote.message_bytes);
            assert_eq!(msg.header_bytes, vote.header_bytes);
            assert_eq!(msg.header_signature, vote.header_signature);
        });
    }

    /// In order to verify that a consensus seal or a `NewView` is correct, nodes must be able to
    /// verify each of the signed votes that are contained in the seal/`NewView`. `PbftSignedVote`s
    /// are verified by the `PbftNode::verify_vote` method, which takes as arguments the vote
    /// itself, the expected vote type, and a closure that evaluates some arbitrary criteria. The
    /// `verify_vote` method should make sure the vote’s type matches the expected type, the header
    /// is properly signed, the header’s signer matches the message’s signer, the message hash is
    /// correct, and that it meets the criteria specified in the closure.
    ///
    /// This test verifies that the `verify_vote` method works correctly by testing all cases where
    /// it should fail and a case where it should succeed.
    #[test]
    fn test_vote_verification() {
        // Generate a public/private key pair
        let key_pair = mock_signer_network(1).remove(0);

        // Create a validly-signed Commit vote
        let valid_vote = mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pair);

        // Test verification of a valid vote
        assert_eq!(
            key_pair.pub_key,
            PbftNode::verify_vote(&valid_vote, PbftMessageType::Commit, |_| Ok(()))
                .expect("Valid vote was determined to be invalid")
        );

        // Test verification of a vote with invalid type
        assert!(
            PbftNode::verify_vote(&valid_vote, PbftMessageType::ViewChange, |_| Ok(())).is_err()
        );

        // Test verification of a vote that doesn't meet the validation_criteria
        assert!(
            PbftNode::verify_vote(&valid_vote, PbftMessageType::Commit, |_| Err(
                PbftError::InvalidMessage("".into())
            ))
            .is_err()
        );

        // Test verification of a vote with an invalid header signature
        let mut invalid_header_sig = valid_vote.clone();
        invalid_header_sig.set_header_signature(vec![0]);
        assert!(PbftNode::verify_vote(
            &invalid_header_sig,
            PbftMessageType::ViewChange,
            |_| Ok(())
        )
        .is_err());

        // Test verification of a vote with an invalid message hash
        let mut invalid_msg_hash = valid_vote.clone();
        invalid_msg_hash.set_message_bytes(vec![0]);
        assert!(
            PbftNode::verify_vote(&invalid_msg_hash, PbftMessageType::Commit, |_| Ok(())).is_err()
        );

        // Test verification of a vote where the header's signer doesn't match the message's
        // signers (the vote signer didn't create the message)
        let bad_key_pair = mock_signer_network(1).remove(0);

        let other_nodes_message = mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            key_pair.pub_key.clone(),
            vec![1],
            false,
        );

        let mut header = ConsensusPeerMessageHeader::new();
        header.set_signer_id(bad_key_pair.pub_key.clone());
        header.set_content_sha512(hash_sha512(&other_nodes_message.message_bytes));
        let header_bytes = header
            .write_to_bytes()
            .expect("Failed to write header to bytes");
        let header_signature = hex::decode(
            create_context("secp256k1")
                .expect("Failed to create context")
                .sign(
                    &header_bytes,
                    &Secp256k1PrivateKey::from_hex(&hex::encode(bad_key_pair.priv_key.clone()))
                        .expect("Failed to create private key from hex"),
                )
                .expect("Failed to sign header"),
        )
        .expect("Failed to decode signed header");

        let mut mismatched_signer = PbftSignedVote::new();
        mismatched_signer.set_header_bytes(header_bytes);
        mismatched_signer.set_header_signature(header_signature);
        mismatched_signer.set_message_bytes(other_nodes_message.message_bytes.clone());

        assert!(
            PbftNode::verify_vote(&mismatched_signer, PbftMessageType::Commit, |_| Ok(())).is_err()
        );
    }

    /// Nodes must be able to verify `NewView` messages to ensure that view changes are valid. To
    /// do this, nodes use the `PbftNode::verify_new_view` method. A `NewView` message is valid if:
    ///
    /// 1. It is for a future view (should never view change backwards)
    /// 2. It is from the primary for the targeted view
    /// 3. All of the votes are valid `ViewChange` messages as determined by the `verify_vote`
    ///    method and the criteria that each vote’s view must match the `NewView` message’s view
    /// 4. All of the vote’s are from nodes that are members of the network
    /// 5. None of the votes are from the new primary that sent this `NewView` message (the
    ///    `NewView` message is an implicit vote from the new primary, so including its own vote
    ///    would be double-voting)
    /// 6. There are `2f` votes (again, this is really `2f + 1` since the `NewView` message itself
    ///    is an implicit vote)
    ///
    /// This test ensures that the `verify_new_view` method properly checks the validity of
    /// `NewView` messages by checking cases where it should fail and a case where it should
    /// succeed.
    #[test]
    fn test_new_view_verification() {
        // Create signing keys for a new network and instantiate a new node on the network
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, _) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[0].pub_key.clone(),
            mock_block(0),
        );

        // Test verification of a valid NewView
        let valid_msg = mock_new_view(
            1,
            1,
            &key_pairs[1],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::ViewChange, 1, 1, vec![], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node.verify_new_view(&valid_msg, &mut state).is_ok());

        // Test verification of a NewView from a previous view
        let previous_view = mock_new_view(
            0,
            1,
            &key_pairs[1],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::ViewChange, 0, 1, vec![], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node.verify_new_view(&previous_view, &mut state).is_err());

        // Test verification of a NewView that is not from the primary for that view
        let not_from_primary = mock_new_view(
            1,
            1,
            &key_pairs[0],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::ViewChange, 1, 1, vec![], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node.verify_new_view(&not_from_primary, &mut state).is_err());

        // Test verification of a NewView where one of the votes isn't a ViewChange
        let non_view_change_vote = mock_new_view(
            1,
            1,
            &key_pairs[1],
            vec![
                mock_vote(PbftMessageType::ViewChange, 1, 1, vec![], &key_pairs[2]),
                mock_vote(PbftMessageType::Commit, 1, 1, vec![], &key_pairs[3]),
            ],
        );
        assert!(node
            .verify_new_view(&non_view_change_vote, &mut state)
            .is_err());

        // Test verification of a NewView that contains a ViewChange vote for a different view
        let vote_for_different_view = mock_new_view(
            1,
            1,
            &key_pairs[1],
            vec![
                mock_vote(PbftMessageType::ViewChange, 1, 1, vec![], &key_pairs[2]),
                mock_vote(PbftMessageType::ViewChange, 0, 1, vec![], &key_pairs[3]),
            ],
        );
        assert!(node
            .verify_new_view(&vote_for_different_view, &mut state)
            .is_err());

        // Test verification of a NewView that contains a vote from a non-member
        let vote_from_unknown_peer = mock_new_view(
            1,
            1,
            &key_pairs[1],
            vec![
                mock_vote(PbftMessageType::ViewChange, 1, 1, vec![], &key_pairs[2]),
                mock_vote(
                    PbftMessageType::ViewChange,
                    1,
                    1,
                    vec![],
                    &mock_signer_network(1).remove(0),
                ),
            ],
        );
        assert!(node
            .verify_new_view(&vote_from_unknown_peer, &mut state)
            .is_err());

        // Test verification of a NewView that contains a vote from the new primary
        let vote_from_primary = mock_new_view(
            1,
            1,
            &key_pairs[1],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::ViewChange, 1, 1, vec![], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node
            .verify_new_view(&vote_from_primary, &mut state)
            .is_err());

        // Test verification of a NewView that does not contain enough votes
        let insufficient_votes = mock_new_view(
            1,
            1,
            &key_pairs[1],
            vec![mock_vote(
                PbftMessageType::ViewChange,
                1,
                1,
                vec![],
                &key_pairs[2],
            )],
        );
        assert!(node
            .verify_new_view(&insufficient_votes, &mut state)
            .is_err());
    }

    /// Nodes must be able to verify consensus seals to ensure that committed blocks contain valid
    /// seals for future verification and to perform catch-up. To do this, nodes use the
    /// `PbftNode::verify_consensus_seal` method. A consensus seal is valid if:
    ///
    /// 1. All of the votes are valid Commit messages as determined by the `verify_vote` method and
    ///    the criteria that each vote’s:
    ///    a. Block ID must match the consensus seal’s block ID
    ///    b. View must match the consensus seal’s view
    ///    c. Sequence number must match the consensus seal’s sequence number
    /// 2. The seal’s signer (as determined by the seal’s `signer_id`) and all of the vote’s
    ///    signers are nodes that were members of the network at the time the block was voted on
    ///    (this is checked by getting the on-chain list of members for the block previous to the
    ///    one the seal verifies, as specified in the `previous_id` argument to the
    ///    `verify_consensus_seal` method)
    /// 3. None of the votes are from the seal’s signer (producing a seal is an implicit vote from
    ///    the node that constructed it, so including its own vote would be double-voting)
    /// 4. There are `2f` votes (this is really `2f + 1` voters since the consensus seal itself is
    ///    an implicit vote)
    ///
    /// This test ensures that the `verify_consensus_seal` method properly checks the validity of
    /// consensus seals by checking cases where it should fail and a case where it should succeed.
    #[test]
    fn test_consensus_seal_verification() {
        // Create signing keys for a new network and instantiate a new node on the network
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[0].pub_key.clone(),
            mock_block(0),
        );

        // Set the MockService to return a different members list for block_id=[1]
        let mut block_1_settings = HashMap::new();
        block_1_settings.insert(
            "sawtooth.consensus.pbft.members".to_string(),
            serde_json::to_string(
                &vec![
                    key_pairs[0].pub_key.clone(),
                    key_pairs[2].pub_key.clone(),
                    key_pairs[3].pub_key.clone(),
                    mock_signer_network(1).remove(0).pub_key,
                ]
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        service
            .settings
            .borrow_mut()
            .insert(vec![1], block_1_settings);

        // Test verification of a valid seal/previous_id
        let valid_seal = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node
            .verify_consensus_seal(&valid_seal, vec![0], &mut state)
            .is_ok());

        // Test verification of a valid seal that has a vote from a node not in the previous block
        // (using previous_id=[1] gets the list of members set above)
        let vote_not_in_prev_block = mock_seal(
            0,
            2,
            vec![2],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 2, vec![2], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node
            .verify_consensus_seal(&vote_not_in_prev_block, vec![1], &mut state)
            .is_err());

        // Test verification of a seal that contains a vote that is not a Commit
        let vote_not_commit = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[1]),
                mock_vote(PbftMessageType::ViewChange, 0, 1, vec![1], &key_pairs[2]),
            ],
        );
        assert!(node
            .verify_consensus_seal(&vote_not_commit, vec![0], &mut state)
            .is_err());

        // Test verification of a seal that contains a vote for a different block
        let vote_different_block = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[1]),
                mock_vote(PbftMessageType::Commit, 0, 1, vec![2], &key_pairs[2]),
            ],
        );
        assert!(node
            .verify_consensus_seal(&vote_different_block, vec![0], &mut state)
            .is_err());

        // Test verification of a seal that contains a vote from a different view
        let vote_different_view = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[1]),
                mock_vote(PbftMessageType::Commit, 1, 1, vec![1], &key_pairs[2]),
            ],
        );
        assert!(node
            .verify_consensus_seal(&vote_different_view, vec![0], &mut state)
            .is_err());

        // Test verification of a seal that contains a vote from a different sequence number
        let vote_different_seq_num = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[1]),
                mock_vote(PbftMessageType::Commit, 0, 2, vec![1], &key_pairs[2]),
            ],
        );
        assert!(node
            .verify_consensus_seal(&vote_different_seq_num, vec![0], &mut state)
            .is_err());

        // Test verification of a seal that contains a vote from the seal's signer
        let vote_from_signer = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (0..2)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 2, vec![2], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        assert!(node
            .verify_consensus_seal(&vote_from_signer, vec![0], &mut state)
            .is_err());

        // Test verification of a seal that doesn't contain enough votes
        let not_enough_votes = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![mock_vote(
                PbftMessageType::Commit,
                0,
                1,
                vec![1],
                &key_pairs[1],
            )],
        );
        assert!(node
            .verify_consensus_seal(&not_enough_votes, vec![0], &mut state)
            .is_err());
    }

    /// Nodes must be able to extract a consensus seal from a block to verify it for two purposes:
    ///
    /// 1. Ensure that the seal is valid so that it can be used to verify the previous block’s
    ///    commit at a later point
    /// 2. Use the seal to commit the block using the catch-up procedure if the node has fallen
    ///    behind
    ///
    /// A consensus seal is stored as a bytes-encoded `PbftSeal` in the block’s payload field.
    /// Blocks 0 and 1 do not store consensus seals, since block 0 doesn’t have a previous block
    /// and it is not voted on by consensus (so block 1 won’t have a seal for it).
    ///
    /// The consensus seal stored in a block is extracted, verified, and returned by the
    /// `PbftNode::verify_consensus_seal_from_block` method. A block’s consensus seal is deemed
    /// valid if:
    ///
    /// 1. There is actually a parsable consensus seal in the block’s payload field
    /// 2. The seal’s block ID is the same as the block’s previous ID (since the seal should be for
    ///    the block previous to this one)
    /// 3. The seal itself is valid as determined by the `verify_consensus_seal` method, with the
    ///    `previous_id` of the current block’s previous block (the one validated by the seal) used
    ///    as the `previous_id` argument to `verify_consensus_seal`.
    ///
    /// This test ensures that the `verify_consensus_seal_from_block` method properly checks the
    /// validity of blocks’ consensus seals by checking cases where it should fail and a case where
    /// it should succeed.
    #[test]
    fn test_consensus_seal_from_block_verification() {
        // Create signing keys for a new network and instantiate a new node on the network
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, _) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[0].pub_key.clone(),
            mock_block(0),
        );

        // Verify that block 1 need not have a seal
        let block1 = mock_block(1);
        assert!(node
            .verify_consensus_seal_from_block(&block1, &mut state)
            .is_ok());

        // Add block 1 to the node's log so it can be used to verify the seal for block 2
        node.msg_log.add_validated_block(block1);

        // Test verification of a block with an empty payload
        let mut block2 = mock_block(2);
        assert!(node
            .verify_consensus_seal_from_block(&block2, &mut state)
            .is_err());

        // Test verification of a block whose seal doesn't match the block's previous ID (previous
        // ID of block 2 is [1])
        block2.payload = mock_seal(
            0,
            1,
            vec![0],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![0], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        assert!(node
            .verify_consensus_seal_from_block(&block2, &mut state)
            .is_err());

        // Test verification of a block whose seal isn't valid (e.g. doesn't have enough votes)
        block2.payload = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![mock_vote(
                PbftMessageType::Commit,
                0,
                1,
                vec![1],
                &key_pairs[1],
            )],
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        assert!(node
            .verify_consensus_seal_from_block(&block2, &mut state)
            .is_err());

        // Test verification of a block with a valid seal, and make sure the returned seal is the
        // same as the original
        let valid_seal = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        block2.payload = valid_seal
            .write_to_bytes()
            .expect("Failed to write seal to bytes");
        assert_eq!(
            valid_seal,
            node.verify_consensus_seal_from_block(&block2, &mut state)
                .expect("Result should be valid")
        );
    }

    /// To publish a valid block with a verifiable proof for the commit of the previous block,
    /// nodes must be able to build a valid consensus seal for the last block that the node
    /// committed. To build the seal, the node will have to have in its log:
    ///
    /// 1. The previously committed block, which has `block_num = state.seq_num - 1`
    /// `2f + 1` matching Commit messages for the previously committed block (same type, seq_num,
    /// view, and block_id) that are from different nodes (different signer_id’s)
    ///
    /// While the `2f + 1` messages must all have a matching view, they could be from any past view
    /// since the block could have been committed in any past view.
    ///
    /// Consensus seals are built using the `PbftNode::build_seal` method, which checks its log for
    /// `2f` matching Commit messages for the last committed block that are from other nodes
    /// (doesn’t include own vote, since the seal itself is an implicit vote) and also retrieves
    /// the view the block was committed in.
    ///
    /// This test verifies that the `build_seal` method properly produces a consensus seal when it
    /// should, and that it does not produce a seal when it is unable to.
    #[test]
    fn test_consensus_seal_building() {
        // Create signing keys for a new network and instantiate a new node on the network
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, _) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[0].pub_key.clone(),
            mock_block(1),
        );

        // Add a group of messages with signed components to the node's log
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            key_pairs[0].pub_key.clone(),
            vec![1],
            true,
        ));
        node.msg_log.add_message(
            ParsedMessage::from_signed_vote(&mock_vote(
                PbftMessageType::Commit,
                0,
                1,
                vec![1],
                &key_pairs[1],
            ))
            .expect("Failed to parse vote"),
        );
        node.msg_log.add_message(
            ParsedMessage::from_signed_vote(&mock_vote(
                PbftMessageType::Commit,
                0,
                1,
                vec![2],
                &key_pairs[2],
            ))
            .expect("Failed to parse vote"),
        );
        node.msg_log.add_message(
            ParsedMessage::from_signed_vote(&mock_vote(
                PbftMessageType::Commit,
                1,
                1,
                vec![1],
                &key_pairs[2],
            ))
            .expect("Failed to parse vote"),
        );
        node.msg_log.add_message(
            ParsedMessage::from_signed_vote(&mock_vote(
                PbftMessageType::Commit,
                0,
                2,
                vec![1],
                &key_pairs[2],
            ))
            .expect("Failed to parse vote"),
        );
        node.msg_log.add_message(
            ParsedMessage::from_signed_vote(&mock_vote(
                PbftMessageType::Prepare,
                0,
                1,
                vec![1],
                &key_pairs[2],
            ))
            .expect("Failed to parse vote"),
        );

        // Verify that seal cannot be built yet (have 2f matching messages for a block at the last
        // seq_num from different signers, but one is the seal signer's own)
        assert!(node.build_seal(&mut state).is_err());

        // Add another Commit message so there are 2f matching messages from other nodes
        node.msg_log.add_message(
            ParsedMessage::from_signed_vote(&mock_vote(
                PbftMessageType::Commit,
                0,
                1,
                vec![1],
                &key_pairs[2],
            ))
            .expect("Failed to parse vote"),
        );

        // Verify that a valid seal can be built now
        let seal1 = node
            .build_seal(&mut state)
            .expect("Seal building shouldn't fail");
        assert!(node
            .verify_consensus_seal(&seal1, vec![0], &mut state)
            .is_ok());

        // Set the node's view to 2 and verify that a valid seal can still be built when the Commit
        // messages are from a past view
        state.view = 2;
        let seal2 = node
            .build_seal(&mut state)
            .expect("Seal building shouldn't fail");
        assert!(node
            .verify_consensus_seal(&seal2, vec![0], &mut state)
            .is_ok());
    }

    /// The `PbftNode::try_publish` method, which is called at every iteration of the engine’s main
    /// loop, is responsible for determining when a node should finalize a block that it is
    /// building. A node will finalize a block when:
    ///
    /// 1. It is the leader
    /// 2. It is in the PrePreparing phase
    /// 3. A block has been initialized (calls to `summarize_block` will fail if no block is
    ///    initialized)
    /// 4. The block can be summarized successfully (this means the block is ready to be finalized
    ///    from the validator’s perspective)
    ///
    /// The block must be finalized with a valid consensus seal for the previous block in order for
    /// the other nodes to accept it, since the consensus seal is necessary to verify that the
    /// previous block was committed properly.
    ///
    /// This test verifies that the `try_publish` method properly determines when the in-progress
    /// block should be finalized.
    #[test]
    #[allow(unused_must_use)]
    fn test_publishing() {
        // Create a new node on a 4 node network
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(1));

        // Add messages necessary to build a valid seal for block 1
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            vec![0],
            vec![1],
            true,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            vec![1],
            vec![1],
            false,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            vec![2],
            vec![1],
            false,
        ));

        // Update the state to view 1 (so node isn’t primary) and call try_publish(); verify that
        // finalize_block() was not called
        state.view = 1;
        assert!(node.try_publish(&mut state).is_ok());
        assert!(!service.was_called("finalize_block"));

        // Reset the state’s view to 0 and update its phase to Preparing, then call try_publish();
        // verify that finalize_block() was not called
        state.view = 0;
        state.phase = PbftPhase::Preparing;
        assert!(node.try_publish(&mut state).is_ok());
        assert!(!service.was_called("finalize_block"));

        // Reset the state’s phase to PrePreparing and update the mock Service so its
        // summarize_block() method returns an Err result; call try_publish() and verify that
        // finalize_block() was not called
        state.phase = PbftPhase::PrePreparing;
        service
            .summarize_block_return_val
            .replace(Err(Error::BlockNotReady));
        assert!(node.try_publish(&mut state).is_ok());
        assert!(service.was_called("summarize_block"));
        assert!(!service.was_called("finalize_block"));

        // Update the mock Service so its summarize_block() method returns Ok again, then call
        // try_publish() and verify that finalize_block() is called with a seal for block 1
        service
            .summarize_block_return_val
            .replace(Ok(Default::default()));
        assert!(node.try_publish(&mut state).is_ok());
        assert!(service.was_called_with_args(stringify_func_call!(
            "finalize_block",
            node.build_seal(&mut state)
                .expect("Failed to build seal")
                .write_to_bytes()
                .expect("Failed to write seal to bytes")
        )));
    }

    /// As a consensus engine, PBFT must make sure that every block it receives has certain
    /// characteristics to be considered valid:
    ///
    /// 1. The block must not be older than the chain head (since PBFT is non-forking and final, it
    ///    will never go back and commit an old block)
    /// 2. The node must already have the previous block, since it can’t verify the block’s
    ///    consensus seal without it
    /// 3. The block’s previous block must have the previous block number (block number must be
    ///    strictly monotonically increasing by one)
    /// 4. The block's grandparent (it's previous block's previous block) must already be committed
    ///    before the block can be considered.
    /// 5. The block’s consensus seal must be valid as determined by the
    ///    `PbftNode::verify_consensus_seal_from_block` method, since any block that gets committed
    ///    to the chain must contain a valid proof for the block before it (which is required to
    ///    uphold finality, provide external verification, and enable the catch-up procedure)
    ///
    /// Criteria (1-3) are checked immediately when the block is received; if the block does not
    /// meet any of these criteria, it should be failed. Otherwise, if it passes this step, it
    /// should be added to the log as an unvalidated block and its validity should be checked using
    /// the service. If a BlockValid update is received by the node, it should mark the block as
    /// validated, then check criterion (4). If criterion (4) is not met, the block is not failed;
    /// instead, the node should simply skip further handling of the block until the block's
    /// grandparent is committed, at which point the node will evaluate criterion (5) (this will
    /// happen in the call to on_block_commit for the grandparent). Once criterion (4) is met, the
    /// node will check criteria (5); if this criterion is not met, the block should be failed.
    ///
    /// This test ensures that these criteria are enforced when a block is received using the
    /// `PbftNode::on_block_new` method.
    #[test]
    #[allow(unused_must_use)]
    fn test_block_acceptance_and_validation() {
        // Create signing keys for a new network and instantiate a new node on the network with
        // block 3 as the chain head
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[0].pub_key.clone(),
            mock_block(3),
        );

        // Verify old blocks are rejected immediately when they are received
        let mut old_block = mock_block(2);
        old_block.payload = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.on_block_new(old_block, &mut state);
        assert!(service.was_called_with_args(stringify_func_call!("fail_block", vec![2])));
        assert!(node.msg_log.block_validated(vec![2]).is_none());
        assert!(node.msg_log.get_block_with_id(&[2]).is_none());

        // Verify blocks are rejected immediately when node doesn't have previous block
        let mut no_previous_block = mock_block(5);
        no_previous_block.payload = mock_seal(
            0,
            4,
            vec![4],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 4, vec![4], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.on_block_new(no_previous_block.clone(), &mut state);
        assert!(service.was_called_with_args(stringify_func_call!("fail_block", vec![5])));
        assert!(node.msg_log.block_validated(vec![5]).is_none());
        assert!(node.msg_log.get_block_with_id(&[5]).is_none());

        // Verify blocks are rejected immediately when the previous block doesn't have the previous
        // block num
        let mut previous_block_not_previous_num = mock_block(5);
        previous_block_not_previous_num.previous_id = vec![3];
        previous_block_not_previous_num.payload = mock_seal(
            0,
            3,
            vec![3],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 3, vec![3], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.on_block_new(previous_block_not_previous_num.clone(), &mut state);
        // called more than once now
        assert!(!service.was_called_with_args_once(stringify_func_call!("fail_block", vec![5])));
        assert!(node.msg_log.block_validated(vec![5]).is_none());
        assert!(node.msg_log.get_block_with_id(&[5]).is_none());

        // Verify blocks aren't handled before the grandparent block is committed (this block is
        // actually invalid because of its seal, but it won't be failed because it can't properly
        // be verified yet)
        node.msg_log.add_validated_block(mock_block(5));
        let mut invalid_block_but_not_ready = mock_block(6);
        invalid_block_but_not_ready.payload = mock_seal(
            0,
            5,
            vec![5],
            &key_pairs[0],
            vec![mock_vote(
                PbftMessageType::Commit,
                0,
                5,
                vec![5],
                &key_pairs[1],
            )],
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.on_block_new(invalid_block_but_not_ready.clone(), &mut state);
        assert!(service.was_called_with_args(stringify_func_call!("check_blocks", vec![vec![6]])));
        node.on_block_valid(invalid_block_but_not_ready.block_id.clone(), &mut state);
        assert!(!service.was_called_with_args(stringify_func_call!("fail_block", vec![6])));
        assert!(node.msg_log.block_validated(vec![6]).is_none());
        assert!(node.msg_log.get_block_with_id(&[6]).is_some());

        // Verify blocks with invalid seals (e.g. not enough votes) are rejected after the block is
        // validated by the validator
        let mut invalid_seal = mock_block(4);
        invalid_seal.payload = mock_seal(
            0,
            3,
            vec![3],
            &key_pairs[0],
            vec![mock_vote(
                PbftMessageType::Commit,
                0,
                3,
                vec![3],
                &key_pairs[1],
            )],
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.on_block_new(invalid_seal.clone(), &mut state);
        assert!(service.was_called_with_args(stringify_func_call!("check_blocks", vec![vec![4]])));
        node.on_block_valid(invalid_seal.block_id.clone(), &mut state);
        assert!(service.was_called_with_args(stringify_func_call!("fail_block", vec![4])));
        assert!(node.msg_log.block_validated(vec![4]).is_none());
        assert!(node.msg_log.get_block_with_id(&[4]).is_some());

        // Verify valid blocks are accepted and added to the log
        let mut valid_block = mock_block(4);
        valid_block.payload = mock_seal(
            0,
            3,
            vec![3],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 3, vec![3], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.on_block_new(valid_block.clone(), &mut state);
        // called more than once now
        assert!(
            !service.was_called_with_args_once(stringify_func_call!("check_blocks", vec![vec![4]]))
        );
        node.on_block_valid(valid_block.block_id.clone(), &mut state);
        // shouldn't have called fail_block again
        assert!(service.was_called_with_args_once(stringify_func_call!("fail_block", vec![4])));
        assert!(node.msg_log.get_block_with_id(&[4]).is_some());
    }

    /// After receiving a block and checking it using the service, the consensus engine may be
    /// notified that the block is actually invalid. In this case, PBFT should drop the block from
    /// its log and fail the block.
    #[test]
    fn test_invalid_block() {
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));

        // Get a BlockNew and a BlockInvalid
        assert!(node.on_block_new(mock_block(1), &mut state).is_ok());
        assert!(node.on_block_invalid(vec![1]).is_ok());

        // Verify that the blog is no longer in the log and it has been failed
        assert!(node.msg_log.block_validated(vec![1]).is_none());
        assert!(node.msg_log.get_block_with_id(vec![1].as_slice()).is_none());
        assert!(service.was_called_with_args(stringify_func_call!("fail_block", vec![1])));
    }

    /// After a primary creates and publishes a block to the network, it needs to send out a
    /// PrePrepare message to endorse that block as the one for the network to perform consensus on
    /// for that sequence number.
    ///
    /// This action should be performed only by the primary, because only the primary’s PrePrepare
    /// will be accepted by the other nodes in the network. Also, the primary should only broadcast
    /// a PrePrepare message for a block that it created itself; this protects the network from
    /// malicious, non-primary nodes that attempt to create a block and have the legitimate primary
    /// unwittingly broadcast a PrePrepare for it.
    #[test]
    #[allow(unused_must_use)]
    fn test_pre_prepare_broadcasting() {
        // Create a primary node
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));

        // Create a block from a different node and pass it to the primary node; verify that the
        // primary doesn't broadcast a PrePrepare for the block
        let mut different_signer = mock_block(1);
        different_signer.signer_id = vec![1];
        node.on_block_new(different_signer.clone(), &mut state);
        node.on_block_valid(different_signer.block_id, &mut state);
        assert!(!service.was_called("broadcast"));

        // Update the node's view to 1 so it is no longer the primary, and pass a block to it that
        // it created; verify that the node doesn't broadcast a PrePrepare for the block
        state.view = 1;
        let mut own_block = mock_block(1);
        own_block.signer_id = vec![0];
        node.on_block_new(own_block.clone(), &mut state);
        node.on_block_valid(own_block.block_id.clone(), &mut state);
        assert!(!service.was_called("broadcast"));

        // Reset the node's view to 0 so it is primary again and pass its own block to it again;
        // verify that the mock Service’s broadcast method was called with a PrePrepare message for
        // the block at the current view and sequence number
        state.view = 0;
        node.on_block_new(own_block.clone(), &mut state);
        node.on_block_valid(own_block.block_id.clone(), &mut state);
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "PrePrepare",
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![1], false).message_bytes
        )));
    }

    /// Part of validating all PBFT messages is ensuring each message actually originates from the
    /// node that signed. If this is not verified, a malicious node could “spoof” other nodes’
    /// messages and send duplicate votes that seem to be different.
    ///
    /// To make the task of verifying the origin of messages easier, the validator verifies the
    /// signature of each PeerMessage that it sends to the consensus engine. Each PBFT message has
    /// a `signer_id` field that is not verified by the validator, but can be compared with the
    /// `signer_id` of the PeerMessage to conclusively determine if the node that created the PBFT
    /// message is the same as the node that signed that message.
    ///
    /// This verification is performed by the `handle_update` method in `engine.rs`; its
    /// functionality will be tested by supplying a `PeerMessage` where the `signer_id` matches the
    /// contained message’s `signer_id`, as well as supplying a `PeerMessage` where the `signer_id`
    /// does not match the contained message’s `signer_id`.
    #[test]
    fn test_message_signing() {
        let (mut node, mut state, _) = mock_node(&mock_config(4), vec![0], mock_block(0));

        // Call handle_update() with a PeerMessage that has a different signer_id than the PBFT
        // message it contains and verify that the result is Err
        let mut invalid_peer_message = PeerMessage::default();
        invalid_peer_message.header.signer_id = vec![2];
        invalid_peer_message.header.message_type = "PrePrepare".into();
        invalid_peer_message.content =
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![1], vec![1], false).message_bytes;
        assert!(test_handle_update(
            &mut node,
            Ok(Update::PeerMessage(invalid_peer_message, vec![2])),
            &mut state
        )
        .is_err());

        // Call handle_update() with a PeerMessage that has the same signer_id as the PBFT message
        // it contains and verify that the result is Ok
        let mut valid_peer_message = PeerMessage::default();
        valid_peer_message.header.signer_id = vec![1];
        valid_peer_message.header.message_type = "PrePrepare".into();
        valid_peer_message.content =
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![1], vec![1], false).message_bytes;
        assert!(test_handle_update(
            &mut node,
            Ok(Update::PeerMessage(valid_peer_message, vec![1])),
            &mut state
        )
        .is_ok());
    }

    /// A node should ignore all messages that aren’t from known members of the network, but accept
    /// those that are. Messages that originate from unknown nodes should not be treated as valid
    /// messages, since PBFT has closed membership and only a network-accepted list of members are
    /// allowed to participate.
    ///
    /// This test ensures that the node properly identifies messages that come from PBFT members
    /// and those that don’t.
    #[test]
    fn test_message_signer_membership() {
        // Create a new node
        let (mut node, mut state, _) = mock_node(&mock_config(4), vec![0], mock_block(0));

        // Call the node’s on_peer_message() method with a message from a peer that’s not a member
        // of the network; verify that the result is an Err
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![4], vec![1], false),
                &mut state
            )
            .is_err());

        // Call on_peer_message() again with a message from a peer that is a member of the network;
        // verify the result is Ok
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![3], vec![1], false),
                &mut state
            )
            .is_ok());
    }

    /// The primary sends a PrePrepare message after publishing a block to endorse that block as
    /// the one to perform consensus on for the current sequence number. The secondary nodes will
    /// accept this PrePrepare message, add the message to their logs, and begin to perform
    /// consensus on the block (by moving to the Preparing phase) as long as the PrePrepare is
    /// valid. The PrePrepare is valid if:
    ///
    /// 1. It is from the primary for the node’s current view
    /// 2. Its view is the same as the node’s current view
    /// 3. There isn’t an existing PrePrepare for this sequence number and view that is for a
    ///    different block
    ///
    /// This test ensures that all 3 of these conditions are properly checked when a PrePrepare
    /// message is received and passed to the `PbftNode::on_peer_message` method; the node will not
    /// add the message to the log if any of the conditions are violated, but will add the message
    /// to the log if they are all met.
    #[test]
    #[allow(unused_must_use)]
    fn test_pre_prepare_checking() {
        // Create a new node
        let (mut node, mut state, _) = mock_node(&mock_config(4), vec![0], mock_block(0));

        // Verify PrePrepares that are not from the primary are rejected
        node.on_peer_message(
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![1], vec![1], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::PrePrepare, 1)
                .len()
        );

        // Verify PrePrepares that are not for the current view are rejected
        node.on_peer_message(
            mock_msg(PbftMessageType::PrePrepare, 1, 1, vec![0], vec![1], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::PrePrepare, 1)
                .len()
        );

        // Verify that valid PrePrepares are accepted and added to the log
        let valid_pre_prepare =
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![1], false);
        node.on_peer_message(valid_pre_prepare.clone(), &mut state);
        {
            let res1 = node
                .msg_log
                .get_messages_of_type_seq(PbftMessageType::PrePrepare, 1);
            assert_eq!(1, res1.len());
            assert_eq!(&valid_pre_prepare, res1[0]);
        }

        // Verify that another PrePrepare with a mismatched block is rejected
        node.on_peer_message(
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![2], false),
            &mut state,
        );
        let res2 = node
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::PrePrepare, 1);
        assert_eq!(1, res2.len());
        assert_eq!(&valid_pre_prepare, res2[0]);
    }

    /// In the PrePreparing phase, the first phase of the PBFT algorithm, the primary creates and
    /// publishes a block, then endorses that block with a `PrePrepare` message. When a node in the
    /// PrePreparing phase has a valid block and a valid `PrePrepare` message for its current
    /// sequence number, it should:
    ///
    /// 1. Switch to the Preparing phase
    /// 2. Stop the idle timeout (since the primary completed its job of producing a block and
    ///    endorsing it)
    /// 3. Start the commit timeout (as a backup in case something goes wrong and the network gets
    ///    stuck; if so, the timeout will expire and a new view will be started to ensure progress
    ///    will be made)
    /// 4. (Only secondary nodes) Broadcast a `Prepare` message for the primary’s endorsed block
    ///    with the current view and sequence number to all members of the network
    ///
    /// Formally, to complete the PrePreparing phase and perform the above actions for some
    /// sequence number n, the following must be true of the node:
    ///
    /// 1. The node is in the PrePreparing phase (it isn’t already done with PrePreparing)
    /// 2. The node is on sequence number n
    /// 3. The node has a valid block in its log for the sequence number n
    /// 4. The node has a valid `PrePrepare` in its log for the block in (3) (the sequence number
    ///    of the `PrePrepare` must match the block’s block number)
    ///
    /// (1) and (2) are closely related; the only time (2) changes (the sequence number gets
    /// incremented) is when a block gets committed, at which point the phase is set to
    /// PrePreparing (because a block was committed, the node restarts at the beginning phase).
    /// Thus, there are really 3 events that must happen for PrePreparing to be complete:
    ///
    /// 1. The node committed a block for sequence number n - 1, so it is now PrePreparing for
    ///    sequence number n
    /// 2. A valid block for sequence number n is received and added to the log
    /// 3. A valid `PrePrepare` for the block in (2) is received and added to the log
    ///
    /// Typically, these 3 events will happen in order, but this is not always the case; it is
    /// possible, for instance, for a node to receive a block and `PrePrepare` for sequence number
    /// n before block n - 1 is committed.
    ///
    /// There is also an additional check of the `PrePrepare` that is necessary for the
    /// PrePreparing phase to be complete: the `PrePrepare`’s sequence number must be checked to
    /// verify that it matches the block’s block number. This is required to enforce a one-to-one
    /// correlation between a block’s number and sequence number at which the block is committed.
    /// This check must be done here instead of when the `PrePrepare` is received, because the node
    /// may not yet have the block in question when the `PrePrepare` is received.
    ///
    /// This test verifies that the node completes the PrePreparing phase and performs the proper
    /// actions iff the required conditions are true, that these required conditions can be met in
    /// any order, and that the `PrePrepare`’s sequence number matches the block’s block number.
    #[test]
    fn test_pre_preparing_phase() {
        // Create signing keys for a new network and instantiate a new secondary node on the
        // network; verify that it is PrePreparing
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[1].pub_key.clone(),
            mock_block(0),
        );
        assert_eq!(1, state.seq_num);
        assert_eq!(PbftPhase::PrePreparing, state.phase);

        // Create blocks 1-9
        let mut blocks = (1..10).map(|i| {
            let mut block = mock_block(i);
            block.payload = mock_seal(
                0,
                (i - 1).into(),
                vec![i - 1],
                &key_pairs[0],
                (1..3)
                    .map(|j| {
                        mock_vote(
                            PbftMessageType::Commit,
                            0,
                            (i - 1).into(),
                            vec![i - 1],
                            &key_pairs[j],
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .write_to_bytes()
            .expect("Failed to write seal to bytes");
            block
        });

        // Add block 1 so the node can receive block 2
        node.msg_log.add_validated_block(blocks.next().unwrap());

        // Verify order Commit -> Block -> PrePrepare
        // Simulate block 1 commit
        state.phase = PbftPhase::Finishing(false);
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert_eq!(2, state.seq_num);
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        // Receive block 2 (BlockNew and BlockValid)
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![2], &mut state).is_ok());
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        // Receive PrePrepare for block 2
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    2,
                    key_pairs[0].pub_key.clone(),
                    vec![2],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        // Check appropriate actions performed
        assert_eq!(PbftPhase::Preparing, state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Prepare",
            mock_msg(
                PbftMessageType::Prepare,
                0,
                2,
                key_pairs[1].pub_key.clone(),
                vec![2],
                false,
            )
            .message_bytes
        )));

        // Verify order Commit -> PrePrepare -> Block
        // Simulate block 2 commit
        state.phase = PbftPhase::Finishing(false);
        assert!(node.on_block_commit(vec![2], &mut state).is_ok());
        assert_eq!(3, state.seq_num);
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        // Receive PrePrepare for block 3
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    3,
                    key_pairs[0].pub_key.clone(),
                    vec![3],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        // Receive block 3 (BlockNew and BlockValid)
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![3], &mut state).is_ok());
        // Check appropriate actions performed
        assert_eq!(PbftPhase::Preparing, state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Prepare",
            mock_msg(
                PbftMessageType::Prepare,
                0,
                3,
                key_pairs[1].pub_key.clone(),
                vec![3],
                false,
            )
            .message_bytes
        )));

        // Verify order Block -> Commit -> PrePrepare
        // Receive block 4 (BlockNew and BlockValid; set phase to Finishing, otherwise catch-up
        // occurs)
        state.phase = PbftPhase::Finishing(false);
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![4], &mut state).is_ok());
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        // Simulate block 3 commit
        assert!(node.on_block_commit(vec![3], &mut state).is_ok());
        assert_eq!(4, state.seq_num);
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        // Receive PrePrepare for block 4
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    4,
                    key_pairs[0].pub_key.clone(),
                    vec![4],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        // Check appropriate actions performed
        assert_eq!(PbftPhase::Preparing, state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Prepare",
            mock_msg(
                PbftMessageType::Prepare,
                0,
                4,
                key_pairs[1].pub_key.clone(),
                vec![4],
                false,
            )
            .message_bytes
        )));

        // Verify order Block -> PrePrepare -> Commit
        // Receive block 5 (BlockNew and BlockValid; set phase to Finishing, otherwise catch-up
        // occurs)
        state.phase = PbftPhase::Finishing(false);
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![5], &mut state).is_ok());
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        // Receive PrePrepare for block 5 (still Finishing because block 4 has not been committed
        // yet)
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    5,
                    key_pairs[0].pub_key.clone(),
                    vec![5],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        // Simulate block 4 commit
        assert!(node.on_block_commit(vec![4], &mut state).is_ok());
        assert_eq!(5, state.seq_num);
        // Check appropriate actions performed
        assert_eq!(PbftPhase::Preparing, state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Prepare",
            mock_msg(
                PbftMessageType::Prepare,
                0,
                5,
                key_pairs[1].pub_key.clone(),
                vec![5],
                false,
            )
            .message_bytes
        )));

        // Verify order PrePrepare -> Commit -> Block
        // Receive PrePrepare for block 6 (still Preparing because block 5 has not been committed
        // yet)
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    6,
                    key_pairs[0].pub_key.clone(),
                    vec![6],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Preparing, state.phase);
        // Simulate block 5 commit
        state.phase = PbftPhase::Finishing(false);
        assert!(node.on_block_commit(vec![5], &mut state).is_ok());
        assert_eq!(6, state.seq_num);
        // Receive block 6 (BlockNew and BlockValid)
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![6], &mut state).is_ok());
        // Check appropriate actions performed
        assert_eq!(PbftPhase::Preparing, state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Prepare",
            mock_msg(
                PbftMessageType::Prepare,
                0,
                6,
                key_pairs[1].pub_key.clone(),
                vec![6],
                false,
            )
            .message_bytes
        )));

        // Verify order PrePrepare -> Block -> Commit
        // Receive PrePrepare for block 7 (still Preparing because block 6 has not been committed
        // yet)
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    7,
                    key_pairs[0].pub_key.clone(),
                    vec![7],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Preparing, state.phase);
        // Receive block 7 (BlockNew and BlockValid; set phase to Finishing, otherwise catch-up
        // occurs)
        state.phase = PbftPhase::Finishing(false);
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![7], &mut state).is_ok());
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        // Simulate block 6 commit
        assert!(node.on_block_commit(vec![6], &mut state).is_ok());
        assert_eq!(7, state.seq_num);
        // Check appropriate actions performed
        assert_eq!(PbftPhase::Preparing, state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Prepare",
            mock_msg(
                PbftMessageType::Prepare,
                0,
                7,
                key_pairs[1].pub_key.clone(),
                vec![7],
                false,
            )
            .message_bytes
        )));

        // Verify that PrePrepare’s sequence number must match the block’s number
        // Receive blocks 8 and 9 (BlockNew and BlockValid)
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![8], &mut state).is_ok());
        assert!(node
            .on_block_new(blocks.next().unwrap(), &mut state)
            .is_ok());
        assert!(node.on_block_valid(vec![9], &mut state).is_ok());
        // Set the node to PrePreparing at seq_num 8
        state.phase = PbftPhase::PrePreparing;
        state.seq_num = 8;
        // Receive PrePrepare for sequence number 8 but block 9
        assert!(node
            .on_peer_message(
                mock_msg(
                    PbftMessageType::PrePrepare,
                    0,
                    8,
                    key_pairs[0].pub_key.clone(),
                    vec![9],
                    false,
                ),
                &mut state,
            )
            .is_ok());
        // Verify node is still in the PrePreparing phase (PrePrepare.seq_num != Block.block_num)
        assert_eq!(PbftPhase::PrePreparing, state.phase);
    }

    /// In the Preparing phase, which is the first round of consensus that the network performs on
    /// a block, the node will accept valid `Prepare` messages (`Prepare` messages are accepted as
    /// valid as long as they’re for the current view and they’re not from the current primary).
    /// For a node to complete the Preparing phase and move on to the Committing phase, the
    /// following must be true:
    ///
    /// 1. The node is in the Preparing phase
    /// 2. The node has a valid `PrePrepare` for the current view and sequence number
    /// 3. The node has `2f + 1` `Prepare` messages that match the `PrePrepare` (same view,
    ///     sequence number, and block ID) for the node’s current sequence number, all from
    ///     different nodes
    ///
    /// These conditions are checked when the node receives a `Prepare` message; thus, receiving a
    /// `Prepare` message is the trigger for checking whether to move on to the Committing phase.
    /// Normally condition (1) will be met before (2), but this is not always the case; sometimes
    /// the node will receive all the required `Prepare` messages before entering the Preparing
    /// phase. This is not a problem, though, because part of switching from the PrePreparing to
    /// the Preparing phase is broadcasting a `Prepare` message, which also self-sends a `Prepare`
    /// message, so the conditions will be checked and the node will be able to move on to the
    /// Committing phase.
    ///
    /// When the node has completed the `Preparing` phase, it will perform the following actions:
    ///
    /// 1. Switch to the Committing phase
    /// 2. Broadcast a `Commit` message to the whole network
    ///
    /// This test will verify that the node will complete the Preparing phase and perform the above
    /// actions iff the necessary conditions are met.
    #[test]
    #[allow(unused_must_use)]
    fn test_preparing_phase() {
        // Create a new node 1 with a 6 node config and set its phase to Preparing
        let (mut node, mut state, service) = mock_node(&mock_config(6), vec![1], mock_block(0));
        state.phase = PbftPhase::Preparing;

        // Verify that invalid Prepares (from different view or from current primary) are rejected
        node.on_peer_message(
            mock_msg(PbftMessageType::Prepare, 1, 1, vec![2], vec![1], false),
            &mut state,
        );
        node.on_peer_message(
            mock_msg(PbftMessageType::Prepare, 0, 1, vec![0], vec![1], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::Prepare, 1)
                .len()
        );
        // Prepare from primary triggers a view change, so reset mode
        state.mode = PbftMode::Normal;

        // Add two valid Prepares and verify the node is still Preparing (hasn't received enough)
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 1, vec![2], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 1, vec![3], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Preparing, state.phase);

        // Verify Prepares' block IDs must match
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 1, vec![4], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Preparing, state.phase);

        // Verify Prepares must be for current sequence number
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 2, vec![2], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 2, vec![3], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 2, vec![4], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Preparing, state.phase);

        // Verify that there must be a matching PrePrepare (even after 2f + 1 Prepares)
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 1, vec![4], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Preparing, state.phase);

        // Receive the PrePrepare and node's own Prepare; verify node is committing and has
        // broadcasted a valid Commit message
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 1, vec![1], vec![1], true),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Committing, state.phase);
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "Commit",
            mock_msg(PbftMessageType::Commit, 0, 1, vec![1], vec![1], false).message_bytes
        )));

        // Verify transition only happens once, Commit broadcast doesn't happen again
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Prepare, 0, 1, vec![5], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert!(service.was_called_with_args_once(stringify_func_call!(
            "broadcast",
            "Commit",
            mock_msg(PbftMessageType::Commit, 0, 1, vec![1], vec![1], false).message_bytes
        )));
    }

    /// In the Committing phase, which is the second round of consensus that the network performs
    /// on a block, the node will accept valid `Commit` messages (`Commit` messages are accepted as
    /// valid as long as they’re for the current view). For a node to complete the Committing phase
    /// and commit a block, the following must be true:
    ///
    /// 1. The node is in the Committing phase
    /// 2. The node has a valid `PrePrepare` for the current view and sequence number
    /// 3. The node has `2f + 1` `Commit` messages that match the `PrePrepare` (same view, sequence
    ///    number, and block ID) for the node’s current sequence number, all from different nodes
    ///
    /// These conditions are checked when the node receives a `Commit` message; thus, receiving a
    /// `Commit` message is the trigger for checking whether to commit a block and move on to the
    /// Finishing phase. Normally condition (1) will be met before (2), but this is not always the
    /// case; sometimes the node will receive all the required `Commit` messages before entering
    /// the Committing phase. This is not a problem, though, because part of switching from the
    /// Preparing to the Committing phase is broadcasting a `Commit` message, which also self-sends
    /// a `Commit` message, so the conditions will be checked and the node will be able to commit
    /// the block.
    ///
    /// When the node has completed the Committing phase, it will perform the following actions:
    ///
    /// 1. Commit the block
    /// 2. Switch to the Finishing phase
    /// 3. Stop the commit timeout
    ///
    /// This test will verify that the node will complete the Committing phase and perform the
    /// above actions iff the necessary conditions are met.
    #[test]
    #[allow(unused_must_use)]
    fn test_committing_phase() {
        // Create a new node 0 with a 5 node config; set its phase to Committing and start its
        // commit timeout
        let (mut node, mut state, service) = mock_node(&mock_config(5), vec![0], mock_block(0));
        state.phase = PbftPhase::Committing;
        state.commit_timeout.start();

        // Verify that Commits from a different view are rejected
        node.on_peer_message(
            mock_msg(PbftMessageType::Commit, 1, 1, vec![1], vec![1], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::Prepare, 1)
                .len()
        );

        // Add two valid Commits and verify the node is still Committing (hasn't received enough)
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![1], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![2], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Committing, state.phase);

        // Verify Commits' block IDs must match
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![3], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Committing, state.phase);

        // Verify Commits must be for current sequence number
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 2, vec![1], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 2, vec![2], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 2, vec![3], vec![2], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Committing, state.phase);

        // Verify that there must be a matching PrePrepare (even after 2f + 1 Commits)
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![3], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Committing, state.phase);

        // Receive the PrePrepare and node's own Commit; verify node is in the Finishing(false)
        // phase, commit timeout is stopped, and block was committed
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![0], vec![1], true),
                &mut state,
            )
            .is_ok());
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        assert!(!state.commit_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!("commit_block", vec![1])));

        // Verify transition only happens once, block commit doesn't happen again
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::Commit, 0, 1, vec![4], vec![1], false),
                &mut state,
            )
            .is_ok());
        assert!(service.was_called_with_args_once(stringify_func_call!("commit_block", vec![1])));
    }

    /// When a block gets committed through the standard procedure (i.e., not the catch-up
    /// procedure), an iteration of the PBFT algorithm is considered “completed” and the node is
    /// ready to start over again for the next sequence number/block. In order to do this, the node
    /// will have to update its state when a block gets committed and perform some other necessary
    /// actions:
    ///
    /// 1. The sequence number will be incremented by 1
    /// 2. The node’s phase will be reset to PrePreparing
    /// 3. The node’s mode will be set to Normal
    /// 4. The node's chain head will be updated
    /// 5. The idle timeout will be started
    /// 6. The view will be incremented by 1 iff the node is at a forced view change
    /// 7. The primary (and only the primary) will initialize a new block
    ///
    /// (1-5) are necessary for the node to be ready to start the next iteration of the algorithm,
    /// (6) is required to implement the regular view changes RFC, and (7) is a prerequisite for
    /// the primary to be able to publish a block for the next sequence number.
    ///
    /// The validator will send a notification to the PBFT engine when a block gets committed, and
    /// the PBFT engine will handle this notification with the PbftNode::on_block_commit() method.
    #[test]
    fn test_block_commit_update() {
        // Initialize node 0 with a 4 node config and set the node's phase to Finishing(false)
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));
        state.phase = PbftPhase::Finishing(false);

        // Simulate block commit notification for block 1; verify that node properly updates its
        // state and initializes a new block (it's the primary)
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert_eq!(2, state.seq_num);
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        assert_eq!(PbftMode::Normal, state.mode);
        assert_eq!(vec![1], state.chain_head);
        assert_eq!(0, state.view);
        assert!(state.idle_timeout.is_active());
        assert!(
            service.was_called_with_args(stringify_func_call!("initialize_block", Some(vec![1])))
        );

        // Turn off idle timeout and reset phase to Finishing(false)
        state.idle_timeout.stop();
        state.phase = PbftPhase::Finishing(false);

        // Set the node's forced_view_change_interval to 3 and its mode to ViewChanging
        state.forced_view_change_interval = 3;
        state.mode = PbftMode::ViewChanging(1);

        // Simulate block commit notification for block 2; verify that node properly updates its
        // state and does NOT initialize a new block (it's no longer the primary because of a
        // forced view change)
        assert!(node.on_block_commit(vec![2], &mut state).is_ok());
        assert_eq!(3, state.seq_num);
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        assert_eq!(PbftMode::Normal, state.mode);
        assert_eq!(vec![2], state.chain_head);
        assert_eq!(1, state.view);
        assert!(state.idle_timeout.is_active());
        assert!(
            !service.was_called_with_args(stringify_func_call!("initialize_block", Some(vec![2])))
        );
    }

    /// Dynamic membership is an important aspect of any practical distributed system; there must
    /// be a mechanism for adding and removing nodes in the event of new members joining or an
    /// existing member malfunctioning.
    ///
    /// Membership changes in Sawtooth PBFT are dictated by the on-chain setting
    /// `sawtooth.consensus.pbft.members`, which contains a list of the network’s members. When
    /// this on-chain setting is updated in a block and that block gets committed, the PBFT nodes
    /// must update their local lists of members and value of `f` (the maximum number of faulty
    /// nodes) to match the changes.
    ///
    /// This functionality is tested using a mock consensus `Service` that will produce different
    /// values for different `block_id`s. Testing will ensure that the list of members in the
    /// node’s state is updated when the on-chain list changes in any way (either changing which
    /// nodes are present or changing the ordering), and that the value of `f` is updated
    /// accordingly (should panic if it is 0).
    #[test]
    #[should_panic(expected = "This network no longer contains enough nodes to be fault tolerant")]
    #[allow(unused_must_use)]
    fn test_membership_changes() {
        // Initialize a node with a 6 node config
        let (mut node, mut state, service) = mock_node(&mock_config(6), vec![0], mock_block(0));

        // Update the mock Service's get_settings() method to return a members list with an added
        // node at block 1, re-ordered at block 2, and a network that is too small at block 3
        let mut block_1_settings = HashMap::new();
        let block_1_members = vec![
            vec![0],
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
        ];
        block_1_settings.insert(
            "sawtooth.consensus.pbft.members".to_string(),
            serde_json::to_string(&block_1_members.iter().map(hex::encode).collect::<Vec<_>>())
                .unwrap(),
        );
        service
            .settings
            .borrow_mut()
            .insert(vec![1], block_1_settings);
        let mut block_2_settings = HashMap::new();
        let block_2_members = vec![
            vec![1],
            vec![0],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
        ];
        block_2_settings.insert(
            "sawtooth.consensus.pbft.members".to_string(),
            serde_json::to_string(&block_2_members.iter().map(hex::encode).collect::<Vec<_>>())
                .unwrap(),
        );
        service
            .settings
            .borrow_mut()
            .insert(vec![2], block_2_settings);
        let mut block_3_settings = HashMap::new();
        block_3_settings.insert(
            "sawtooth.consensus.pbft.members".to_string(),
            serde_json::to_string(
                &vec![vec![0], vec![1], vec![2]]
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        service
            .settings
            .borrow_mut()
            .insert(vec![3], block_3_settings);

        // Simulate block commit for block 1; verify node's members list is updated properly and f is
        // now 2
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert_eq!(block_1_members, state.member_ids);
        assert_eq!(2, state.f);

        // Simulate block commit for block 2; verify node's members list is updated properly and f is
        // still 2
        assert!(node.on_block_commit(vec![2], &mut state).is_ok());
        assert_eq!(block_2_members, state.member_ids);
        assert_eq!(2, state.f);

        // Simulate block commit for block 3; verify that it panics (not enough members)
        node.on_block_commit(vec![3], &mut state);
    }

    /// To keep memory usage under control, the PBFT log must be garbage-collected periodically.
    /// Every time a block gets committed (the node moves on to the next sequence number), the node
    /// will check if the number of messages in its logs exceeds a certain size; if it does, it
    /// will clean up old messages and blocks.
    ///
    /// The node must always retain the committed block at the previous sequence number as well as
    /// the `Commit` messages for the previous sequence number, because it needs these to produce a
    /// valid consensus seal. Thus, when the log is garbage-collected, all messages and blocks that
    /// are older than the node’s previous sequence number (< node’s sequence number - 1) are
    /// removed from the log.
    #[test]
    fn test_garbage_collection() {
        // Initialize a new node and set the max_log_size field of the node’s log to 2
        let (mut node, mut state, _) = mock_node(&mock_config(4), vec![0], mock_block(0));
        node.msg_log.set_max_log_size(2);

        // Add Block and PrePrepare for sequence numbers 1 and 2
        node.msg_log.add_validated_block(mock_block(1));
        node.msg_log.add_validated_block(mock_block(2));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::PrePrepare,
            0,
            1,
            vec![0],
            vec![1],
            false,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::PrePrepare,
            0,
            2,
            vec![0],
            vec![2],
            false,
        ));

        // Simulate commit of block 1; verify node is now at seq_num 2 and all messages are still
        // in the log since they all have seq_num >= state.seq_num - 1
        state.phase = PbftPhase::Finishing(false);
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert_eq!(2, state.seq_num);
        assert!(node.msg_log.get_block_with_id(&vec![1]).is_some());
        assert!(node.msg_log.get_block_with_id(&vec![2]).is_some());
        assert!(node.msg_log.has_pre_prepare(1, 0, &vec![1]));
        assert!(node.msg_log.has_pre_prepare(2, 0, &vec![2]));

        // Simulate commit of block 2; verify node is now at seq_num 3 and messages for seq_num 2
        // are no longer in the log
        state.phase = PbftPhase::Finishing(false);
        assert!(node.on_block_commit(vec![2], &mut state).is_ok());
        assert_eq!(3, state.seq_num);
        assert!(node.msg_log.get_block_with_id(&vec![1]).is_none());
        assert!(node.msg_log.get_block_with_id(&vec![2]).is_some());
        assert!(!node.msg_log.has_pre_prepare(1, 0, &vec![1]));
        assert!(node.msg_log.has_pre_prepare(2, 0, &vec![2]));
    }

    /// To guarantee liveness in the presence of potentially faulty nodes, PBFT provides the view
    /// changing procedure to move to a new view and institute a new primary. When starting the
    /// view change procedure, a node will need to perform the following actions:
    ///
    /// 1. Update its mode to ViewChanging(v), where `v` is the view number that it is attempting
    ///    to change to
    /// 2. Stop both the idle and commit timeouts, since these are not needed during the view
    ///    change procedure
    /// 3. Stop the view change timeout if it is already started
    /// 4. Broadcast a `ViewChange` message for the new view
    ///
    /// These actions should only be performed once for a particular view change, however; a view
    /// change can be initiated based on multiple conditions, and it’s possible for several of
    /// these situations to be encountered. Therefore, the node must guard itself from broadcasting
    /// a view change message twice for the same view.
    ///
    /// Initiating a view change is handled by the `PbftNode::start_view_change` method. This test
    /// will ensure that the method performs all of the actions listed above and guards itself from
    /// duplicate broadcasting of `ViewChange` messages
    #[test]
    #[allow(unused_must_use)]
    fn test_view_change_starting() {
        // Initialize a new node; start its idle, commit, and view change timeouts
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));
        state.idle_timeout.start();
        state.commit_timeout.start();
        state.view_change_timeout.start();

        // Start a view change for view 1 and verify that the state is updated appropriately
        assert!(node.start_view_change(&mut state, 1).is_ok());
        assert_eq!(PbftMode::ViewChanging(1), state.mode);
        assert!(!state.idle_timeout.is_active());
        assert!(!state.commit_timeout.is_active());
        assert!(!state.view_change_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "ViewChange",
            mock_msg(PbftMessageType::ViewChange, 1, 0, vec![0], vec![], false).message_bytes
        )));

        // Verify ViewChange message can't be broadcasted again for the same view
        node.start_view_change(&mut state, 1);
        assert!(service.was_called_with_args_once(stringify_func_call!(
            "broadcast",
            "ViewChange",
            mock_msg(PbftMessageType::ViewChange, 1, 0, vec![0], vec![], false).message_bytes
        )));

        // Start another view change for view 2 and verify that the state is updated appropriately
        state.idle_timeout.start();
        state.commit_timeout.start();
        state.view_change_timeout.start();
        assert!(node.start_view_change(&mut state, 2).is_ok());
        assert_eq!(PbftMode::ViewChanging(2), state.mode);
        assert!(!state.idle_timeout.is_active());
        assert!(!state.commit_timeout.is_active());
        assert!(!state.view_change_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "ViewChange",
            mock_msg(PbftMessageType::ViewChange, 2, 0, vec![0], vec![], false).message_bytes
        )));
    }

    /// When a node is view changing, it should not accept any messages that are not `ViewChange`s
    /// or `NewView`s. This allows the node to prioritize the view changing procedure and not be
    /// affected by messages not related to view changes.
    #[test]
    #[allow(unused_must_use)]
    fn test_message_ignoring_while_view_changing() {
        // Initialize a new node and set its mode to ViewChanging(1)
        let (mut node, mut state, _) = mock_node(&mock_config(4), vec![0], mock_block(0));
        state.mode = PbftMode::ViewChanging(1);

        // Receive PrePrepare, Prepare, and Commit messages; verify that they are all ignored
        node.on_peer_message(
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![1], vec![1], false),
            &mut state,
        );
        node.on_peer_message(
            mock_msg(PbftMessageType::Prepare, 0, 1, vec![1], vec![1], false),
            &mut state,
        );
        node.on_peer_message(
            mock_msg(PbftMessageType::Commit, 0, 1, vec![1], vec![1], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::PrePrepare, 1)
                .len()
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::Prepare, 1)
                .len()
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::Commit, 1)
                .len()
        );
    }

    /// A view change should be started by a node if any of the following occur:
    ///
    /// 1. The idle timeout expires
    /// 2. The commit timeout expires
    /// 3. The view change timeout expires
    /// 4. A PrePrepare is received from the current primary, but the node already has a PrePrepare
    ///    from the primary at the same view and sequence number but for a different block
    /// 5. A Prepare is received from the current primary
    /// 6. The node receives f + 1 matching ViewChange messages for a future view
    ///
    /// (1) makes sure that a primary does not stall the network indefinitely by never producing a
    /// block or PrePrepare (see https://github.com/hyperledger/sawtooth-rfcs/pull/29 for more
    /// information). In this situation, the targeted view change will be `v + 1`, where `v` is the
    /// node’s current view.
    ///
    /// (2) makes sure that the network does not get stuck forever if something goes wrong; if the
    /// network does get stuck, the timer will eventually time out, the view will change, and the
    /// network’s progress will resume. In this situation, the targeted view change will be
    /// `v + 1`, where `v` is the node’s current view.
    ///
    /// (3) makes sure that the new primary will send a NewView message to complete the view change
    /// within a reasonable amount of time; if it does not, the network will try another view
    /// change. In this situation, the targeted view change will be `v' + 1`, where `v'` is the
    /// view the node was already attempting to change to.
    ///
    /// (4) makes sure that a primary does not endorse more than one block with `PrePrepare`
    /// messages, so the network can agree on a single block to vote on. In this situation, the
    /// targeted view change will be `v + 1`, where `v` is the node’s current view.
    ///
    /// (5) makes sure that the primary does not get a `Prepare` vote, since its PrePrepare counts
    /// as its “vote” for the first round of consensus.
    ///
    /// (6) makes sure that a node does not start view changing too late; when `f + 1` matching
    /// `ViewChange` messages have been received, the node can be sure that at least one non-faulty
    /// node has started a view change, so it can start view changing as well. In this situation,
    /// the targeted view change will be `v`, where `v` is the view specified in the `f + 1`
    /// `ViewChange` messages.
    ///
    /// All of these situations should be tested to ensure that they are triggered when (and only
    /// when) expected, and that the targeted view is correct.
    ///
    /// NOTE: View changes for events (1-3) are not tested here, because they are implemented in
    /// the main engine loop which is difficult to test.
    #[test]
    #[allow(unused_must_use)]
    fn test_view_change_initiation_conditions() {
        // Initialize a new node
        let (mut node, mut state, _) = mock_node(&mock_config(4), vec![1], mock_block(0));

        // Verify receiving two PrePrepares for the same view and sequence number but with
        // different blocks triggers a view change
        node.on_peer_message(
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![1], false),
            &mut state,
        );
        node.on_peer_message(
            mock_msg(PbftMessageType::PrePrepare, 0, 1, vec![0], vec![2], false),
            &mut state,
        );
        assert_eq!(PbftMode::ViewChanging(1), state.mode);

        // Verify receiving a Prepare from the current primary triggers a view change
        state.mode = PbftMode::Normal;
        node.on_peer_message(
            mock_msg(PbftMessageType::Prepare, 0, 1, vec![0], vec![1], false),
            &mut state,
        );
        assert_eq!(PbftMode::ViewChanging(1), state.mode);

        // Verify receiving f + 1 ViewChanges starts the view change early
        state.mode = PbftMode::Normal;
        node.on_peer_message(
            mock_msg(PbftMessageType::ViewChange, 2, 0, vec![2], vec![], false),
            &mut state,
        );
        node.on_peer_message(
            mock_msg(PbftMessageType::ViewChange, 2, 0, vec![3], vec![], false),
            &mut state,
        );
        assert_eq!(PbftMode::ViewChanging(2), state.mode);
    }

    /// To perform a view change, the network votes on the view change by broadcasting `ViewChange`
    /// messages. Nodes will accept these `ViewChange` messages and add them to their logs if they
    /// are valid. To be valid, a `ViewChange` message must follow these rules:
    ///
    /// 1. If the node is already in the midst of a view change for view `v` (it is in mode
    ///    ViewChanging(v)), the `ViewChange` must be for a view >= v.
    /// 2. If the node is not already view changing (it is in Normal mode), the `ViewChange` must
    ///    be for a view greater than the node’s current view.
    ///
    /// These conditions ensure that no old (stale) view change messages are added to the log.
    ///
    /// When a node has `2f + 1` `ViewChange` messages for a view, it will start its view change
    /// timeout to ensure that the new primary produces a `NewView` in a reasonable amount of time.
    /// The appropriate duration of the view change timeout is calculated based on a base duration
    /// (defined by the state object’s `view_change_duration` field) using the formula: `(desired
    /// view number - node’s current view number) * view_change_duration`.
    ///
    /// When the new primary for the view specified in the `ViewChange` message has `2f + 1`
    /// `ViewChange` messages for that view, it will broadcast a `NewView` message to the network.
    /// Only the new primary should broadcast the `NewView` message.
    ///
    /// This test ensures that only non-stale `ViewChange` messages are accepted, nodes start their
    /// view change timeouts with the appropriate duration when `2f + 1` `ViewChange` messages are
    /// received, and that the new primary (and only the new primary) broadcasts a `NewView` when
    /// it has the required messages in its log.
    #[test]
    #[allow(unused_must_use)]
    fn test_view_change_acceptance() {
        // Initialize node 0
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));

        // Verify that a ViewChange message for the node's current view is ignored
        node.on_peer_message(
            mock_msg(PbftMessageType::ViewChange, 0, 0, vec![1], vec![], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_view(PbftMessageType::ViewChange, 0)
                .len()
        );

        // Verify that a ViewChnage for a future view is accepted and added to the log
        let vc1 = mock_msg(PbftMessageType::ViewChange, 1, 0, vec![1], vec![], false);
        assert!(node.on_peer_message(vc1.clone(), &mut state).is_ok());
        assert_eq!(
            &&vc1,
            node.msg_log
                .get_messages_of_type_view(PbftMessageType::ViewChange, 1)
                .get(0)
                .expect("ViewChange should be in log")
        );

        // Verify that a ViewChange message is ignored if the node is already in the process of a
        // view change to a later view
        state.mode = PbftMode::ViewChanging(3);
        node.on_peer_message(
            mock_msg(PbftMessageType::ViewChange, 2, 0, vec![1], vec![], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_view(PbftMessageType::ViewChange, 2)
                .len()
        );

        // Verify NewView is not broadcasted by new primary when there aren't 2f + 1 ViewChanges
        state.mode = PbftMode::ViewChanging(4);
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 4, 0, vec![0], vec![], true),
                &mut state
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 4, 0, vec![1], vec![], false),
                &mut state
            )
            .is_ok());
        assert!(!service.was_called_with_args(stringify_func_call!("broadcast", "NewView")));

        // Verify NewView is broadcasted by new primary when there are 2f + 1 ViewChanges
        node.on_peer_message(
            mock_msg(PbftMessageType::ViewChange, 4, 0, vec![2], vec![], false),
            &mut state,
        );
        assert!(service.was_called_with_args(stringify_func_call!("broadcast", "NewView")));

        // Verify NewView is not broadcasted when node is not the new primary
        state.view_change_timeout.stop();
        state.view = 4;
        state.mode = PbftMode::ViewChanging(5);
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 5, 0, vec![0], vec![], true),
                &mut state
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 5, 0, vec![1], vec![], false),
                &mut state
            )
            .is_ok());
        node.on_peer_message(
            mock_msg(PbftMessageType::ViewChange, 5, 0, vec![3], vec![], false),
            &mut state,
        );
        // Verify broadcast only happened once (for view 4, not this view)
        assert!(service.was_called_with_args_once(stringify_func_call!("broadcast", "NewView")));

        // Verify view change timeout is started
        assert!(state.view_change_timeout.is_active());
        assert_eq!(
            state.view_change_duration,
            state.view_change_timeout.duration()
        );

        // Verify view change timeout uses the appropriate duration, and that it is not started
        // until 2f + 1 ViewChanges are received
        state.view_change_timeout.stop();
        state.mode = PbftMode::ViewChanging(6);
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 6, 0, vec![0], vec![], true),
                &mut state
            )
            .is_ok());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 6, 0, vec![1], vec![], false),
                &mut state
            )
            .is_ok());
        assert!(!state.view_change_timeout.is_active());
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::ViewChange, 6, 0, vec![2], vec![], false),
                &mut state,
            )
            .is_ok());
        assert!(state.view_change_timeout.is_active());
        assert_eq!(
            state
                .view_change_duration
                .checked_mul(2)
                .expect("Couldn't double view change duration"),
            state.view_change_timeout.duration()
        );
    }

    /// When the node that will become primary as the result of a view change has accepted `2f + 1`
    /// matching `ViewChange` messages for the new view, it will construct a `NewView` message that
    /// contains the required `ViewChange` messages and broadcast it to the network. When a node
    /// receives this `NewView` message, it will check that the message is valid (as determined by
    /// the `PbftNode::verify_new_view` method). If the `NewView` message is not valid, it will be
    /// ignored; if it is valid, the node will perform the following actions:
    ///
    /// 1. Update its view to that of the `NewView` message
    /// 2. Stop the view change timeout, since it is no longer needed
    /// 3. Set its phase to PrePreparing, unless it is in the Finishing phase
    /// 4. Set its mode to Normal
    /// 5. Start the idle timeout
    ///
    /// In addition, the node that was previously the primary will cancel any block it may have
    /// initialized, and the new primary node (and only the new primary) will initialize a new
    /// block for the current sequence number.
    ///
    /// Furthermore, `NewView` messages can be for any future view, not just the view after the one
    /// the node is on; they must also be acceptable even if the node is not in the ViewChanging
    /// mode (perhaps because the node missed all of the `ViewChange` messages).
    ///
    /// These actions are necessary to complete the view changing procedure and resume normal
    /// operation of the PBFT network with the new primary.
    #[test]
    #[allow(unused_must_use)]
    fn test_new_view_acceptance() {
        // Create signing keys for a new network and instantiate node 1; set its mode to
        // ViewChanging(1) and start the view change timeout
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[1].pub_key.clone(),
            mock_block(0),
        );
        state.mode = PbftMode::ViewChanging(1);
        state.view_change_timeout.start();

        // Verify that a NewView from a node that isn't the new primary is rejected
        let mut nv1 = PbftNewView::new();
        nv1.set_info(PbftMessageInfo::new_from(
            PbftMessageType::NewView,
            1,
            0,
            key_pairs[0].pub_key.clone(),
        ));
        nv1.set_view_changes(RepeatedField::from(vec![
            mock_vote(PbftMessageType::ViewChange, 1, 0, vec![], &key_pairs[1]),
            mock_vote(PbftMessageType::ViewChange, 1, 0, vec![], &key_pairs[2]),
        ]));
        node.on_peer_message(
            ParsedMessage::from_new_view_message(nv1).expect("Failed to parse nv1"),
            &mut state,
        );
        assert_eq!(PbftMode::ViewChanging(1), state.mode);

        // Verify that a valid NewView from the new primary is accepted and the node updates its
        // state appropriately (node 1 is the new priamry, so it should initialize a block)
        let mut nv2 = PbftNewView::new();
        nv2.set_info(PbftMessageInfo::new_from(
            PbftMessageType::NewView,
            1,
            0,
            key_pairs[1].pub_key.clone(),
        ));
        nv2.set_view_changes(RepeatedField::from(vec![
            mock_vote(PbftMessageType::ViewChange, 1, 0, vec![], &key_pairs[0]),
            mock_vote(PbftMessageType::ViewChange, 1, 0, vec![], &key_pairs[2]),
        ]));
        node.on_peer_message(
            ParsedMessage::from_new_view_message(nv2).expect("Failed to parse nv2"),
            &mut state,
        );
        assert_eq!(1, state.view);
        assert_eq!(PbftPhase::PrePreparing, state.phase);
        assert_eq!(PbftMode::Normal, state.mode);
        assert!(!state.view_change_timeout.is_active());
        assert!(state.idle_timeout.is_active());
        assert!(service.was_called("initialize_block"));

        // Verify that a valid NewView for any future view is accepted and node updates its state
        // appropriately (node 1 is the old primary, so it will cancel any initialized block and it
        // won't init new block again, phase should remain Finishing)
        state.phase = PbftPhase::Finishing(false);
        state.idle_timeout.stop();
        state.view_change_timeout.start();
        let mut nv3 = PbftNewView::new();
        nv3.set_info(PbftMessageInfo::new_from(
            PbftMessageType::NewView,
            3,
            0,
            key_pairs[3].pub_key.clone(),
        ));
        nv3.set_view_changes(RepeatedField::from(vec![
            mock_vote(PbftMessageType::ViewChange, 3, 0, vec![], &key_pairs[0]),
            mock_vote(PbftMessageType::ViewChange, 3, 0, vec![], &key_pairs[1]),
        ]));
        node.on_peer_message(
            ParsedMessage::from_new_view_message(nv3).expect("Failed to parse nv3"),
            &mut state,
        );
        assert_eq!(3, state.view);
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        assert_eq!(PbftMode::Normal, state.mode);
        assert!(!state.view_change_timeout.is_active());
        assert!(state.idle_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!("cancel_block")));
        assert!(service.was_called_with_args_once(stringify_func_call!("initialize_block")));
    }

    /// If a node falls behind, or if a new node is added to an existing network, the node will
    /// need to “catch up” to the rest of the network by committing all of the blocks to get to
    /// that point. The catch-up procedure exists for this purpose.
    ///
    /// To commit a block n using the catch-up procedure, the node must have a valid consensus seal
    /// for block n. With this consensus seal, the node can use the `PbftNode::catchup` method to
    /// perform the following actions:
    ///
    /// 1. Extract all of the votes/messages from the consensus seal and add them to its log, along
    ///    with the signed bytes (header bytes and header signature)
    /// 2. Update the node’s view if the messages in the seal are from a different view
    /// 3. Tell the validator to commit the block that’s verified by the consensus seal
    /// 4. Stop the idle timeout
    /// 5. Update its phase to Finishing
    ///
    /// (1) allows the node to build the seal for the commit block in the future if necessary. (2)
    /// allows the node to keep up with view changes as it catches up. (3) is done to actually
    /// commit the block. (4) is done because the primary that produced this block was not faulty.
    /// (5) prepares the node to receive the commit notification from the validator.
    ///
    /// The `catchup` method assumes that the seal has already been verified.
    ///
    /// This test will verify that the `PbftNode::catchup` method performs the above actions when
    /// it is provided a valid consensus seal.
    #[test]
    fn test_catch_up_commit() {
        // Create signing keys for a new network and instantiate node 1
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[1].pub_key.clone(),
            mock_block(0),
        );

        // Start the node's idle timeout and verify it is active
        state.idle_timeout.start();
        assert!(state.idle_timeout.is_active());

        // Construct a valid consensus seal for block 1 with votes from view 1 and catch up with it
        let votes = (2..4)
            .map(|i| mock_vote(PbftMessageType::Commit, 1, 1, vec![1], &key_pairs[i]))
            .collect::<Vec<_>>();
        let seal = mock_seal(1, 1, vec![1], &key_pairs[0], votes.clone());
        assert!(node.catchup(&mut state, &seal, true).is_ok());

        // Verify catch up was done correctly
        let node_2_vote = node
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::Commit, 1)
            .iter()
            .find(|msg| msg.info().get_signer_id() == key_pairs[2].pub_key.as_slice())
            .cloned()
            .expect("Node2's vote is not in log");
        assert_eq!(votes[0].message_bytes, node_2_vote.message_bytes);
        assert_eq!(votes[0].header_bytes, node_2_vote.header_bytes);
        assert_eq!(votes[0].header_signature, node_2_vote.header_signature);
        let node_3_vote = node
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::Commit, 1)
            .iter()
            .find(|msg| msg.info().get_signer_id() == key_pairs[3].pub_key.as_slice())
            .cloned()
            .expect("Node3's vote is not in log");
        assert_eq!(votes[1].message_bytes, node_3_vote.message_bytes);
        assert_eq!(votes[1].header_bytes, node_3_vote.header_bytes);
        assert_eq!(votes[1].header_signature, node_3_vote.header_signature);
        assert_eq!(1, state.view);
        assert_eq!(PbftPhase::Finishing(true), state.phase);
        assert!(!state.idle_timeout.is_active());
        assert!(service.was_called_with_args(stringify_func_call!("commit_block", vec![1])));
    }

    /// One of the ways that the catch-up procedure is triggered is when the node is on
    /// block/sequence number `n` and it receives a block `n + 1` that has a valid seal for block
    /// `n`. In this situation, the node can use the consensus to go ahead and commit block `n`.
    ///
    /// However, there is one caveat: the node may already have instructed the validator to commit
    /// block `n`, and is just waiting for the confirmation from the validator that the block was
    /// committed. To handle this, the node must check that it is not waiting for the commit
    /// confirmation (it will be in the `Finishing` phase if it is waiting).
    #[test]
    fn test_catch_up_on_new_block() {
        // Create signing keys for a new network and instantiate node 1
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[1].pub_key.clone(),
            mock_block(0),
        );

        // Receive block 1 (BlockNew and BlockValid) and verify that node is still PrePreparing
        // (should not perform catch-up for current block)
        assert!(node.on_block_new(mock_block(1), &mut state).is_ok());
        assert!(node.on_block_valid(vec![1], &mut state).is_ok());
        assert_eq!(PbftPhase::PrePreparing, state.phase);

        // Receive block 2 (BlockNew and BlockValid) and verify that catch up was performed for
        // block 1 (phase is Finishing(true) and Service.commit_block(block1.block_id) was called)
        let mut block2 = mock_block(2);
        block2.payload = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        assert!(node.on_block_new(block2.clone(), &mut state).is_ok());
        assert!(node.on_block_valid(vec![2], &mut state).is_ok());
        assert_eq!(PbftPhase::Finishing(true), state.phase);
        assert!(service.was_called_with_args(stringify_func_call!("commit_block", vec![1])));

        // Receive block 2 again and verify that Service.commit_block was not called again (block
        // was already committed)
        assert!(node.on_block_new(block2, &mut state).is_ok());
        assert!(node.on_block_valid(vec![2], &mut state).is_ok());
        assert!(service.was_called_with_args_once(stringify_func_call!("commit_block")));
    }

    /// When a node that is on block/seq_num `n` receives a block `m` (where `m > n + 1`), it will
    /// not be able to commit block `m - 1` using catch-up right away; instead, it will have to
    /// wait until block `m - 2` is committed before committing block `m - 1`. To commit block
    /// `m - 1` using the catch-up procedure in this scenario: when block `m - 2` is committed, the
    /// node will check if it has a block `m` in its log; if it does, it can perform catch-up to
    /// commit block `m - 1` using the seal in block `m`.
    #[test]
    fn test_catch_up_on_block_commit() {
        // Create signing keys for a new network and instantiate node 1; set node's phase to
        // Finishing(true) and make sure its sequence number is 1
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[1].pub_key.clone(),
            mock_block(0),
        );
        state.phase = PbftPhase::Finishing(true);
        assert_eq!(1, state.seq_num);

        // Add blocks 2 and 3 to the node's log
        let mut block2 = mock_block(2);
        block2.payload = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.msg_log.add_validated_block(block2);

        let mut block3 = mock_block(3);
        block3.payload = mock_seal(
            0,
            2,
            vec![2],
            &key_pairs[0],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 2, vec![2], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.msg_log.add_validated_block(block3);

        // Simulate commit of block 1; verify that node is in the Finishing(true) phase at sequence
        // number 2 and commit_block was called with block 2's ID (committed block 2 using seal in
        // block 3 after committing block 1)
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert_eq!(2, state.seq_num);
        assert_eq!(PbftPhase::Finishing(true), state.phase);
        assert!(service.was_called_with_args(stringify_func_call!("commit_block", vec![2])));
    }

    /// Because the consensus seal for a block `n` is stored in a block `n + 1`, when a node
    /// catches up to the rest of the network, it will not be able to commit the final block
    /// because there is no next block with a consensus seal to use. In this scenario, the node
    /// that is catching up will broadcast a request to the whole network for the final block’s
    /// seal. This request will happen when the node committed block `n` using catch-up (as
    /// indicated by the bool stored in the `Finishing` value of the node’s phase), but it does not
    /// have a block `n + 2` to commit block `n + 1`; it will not happen if the node did not commit
    /// block `n` using catch-up.
    #[test]
    fn test_final_block_seal_request() {
        // Initialize a node and set its phase to Finishing(true) to simulate having committed
        // block 1 using the catch up procedure
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));
        state.phase = PbftPhase::Finishing(true);

        // Recieve BlockCommit notification for block 1 and verify that the node broadcasted a
        // SealRequest message for sequence number 2
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert!(service.was_called_with_args(stringify_func_call!(
            "broadcast",
            "SealRequest",
            mock_msg(PbftMessageType::SealRequest, 0, 2, vec![0], vec![], false).message_bytes
        )));
    }

    /// When a node requests a consensus seal for a block `n` by broadcasting a `SealRequest`
    /// message, the other nodes in the network will need to receive this message and, if they have
    /// committed block `n` and are now on sequence number `n + 1`, reply to that node with a valid
    /// seal for block `n`.
    ///
    /// If a node is on sequence number `n + 1` when it receives a `SealRequest` for block `n`, it
    /// can build the seal and send it right away. However, if the node is currently on sequence
    /// number `n` (it has not committed block `n` yet), it will not be able to build the seal
    /// right away; in this case, it will add the request to its message log, wait until the block
    /// is committed (node will now be on `seq_num` `n + 1`), then check the log for a
    /// `SealRequest` for block `n` and if there is one, it will build the seal and send it. If the
    /// receiving node is on any sequence number other than `n` or `n + 1`, it should simply ignore
    /// the request (if it’s behind, it also needs to catch up; if it’s too far ahead, it won’t be
    /// able to build the seal).
    #[test]
    #[allow(unused_must_use)]
    fn test_seal_request_handling() {
        // Initialize a node and set its sequence number to 2
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));
        state.seq_num = 2;

        // Add messages needed to build seal for block 1
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            vec![0],
            vec![1],
            true,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            vec![1],
            vec![1],
            false,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            1,
            vec![2],
            vec![1],
            false,
        ));

        // Receive a SealRequest for sequence number 2 and verify that a seal is sent to the node
        // that requested it
        assert!(node
            .on_peer_message(
                mock_msg(PbftMessageType::SealRequest, 0, 1, vec![3], vec![], false),
                &mut state
            )
            .is_ok());
        assert!(service.was_called_with_args(stringify_func_call!(
            "send_to",
            &vec![3],
            "Seal",
            node.build_seal(&mut state)
                .expect("Failed to build seal")
                .write_to_bytes()
                .expect("Failed to write seal to bytes")
        )));

        // Add messages needed to build seal for block 2
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            2,
            vec![0],
            vec![2],
            true,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            2,
            vec![1],
            vec![2],
            false,
        ));
        node.msg_log.add_message(mock_msg(
            PbftMessageType::Commit,
            0,
            2,
            vec![2],
            vec![2],
            false,
        ));

        // Verify SealRequests for old or future sequence numbers are ignored
        node.on_peer_message(
            mock_msg(PbftMessageType::SealRequest, 0, 0, vec![3], vec![], false),
            &mut state,
        );
        node.on_peer_message(
            mock_msg(PbftMessageType::SealRequest, 0, 3, vec![3], vec![], false),
            &mut state,
        );
        assert_eq!(
            0,
            node.msg_log
                .get_messages_of_type_view(PbftMessageType::SealRequest, 0)
                .len()
        );
        assert!(service.was_called_with_args_once(stringify_func_call!(
            "send_to",
            &vec![3],
            "Seal"
        )));

        // Verify SealRequest for node's current sequence number gets added to the log
        let seq_num_2_req = mock_msg(PbftMessageType::SealRequest, 0, 2, vec![3], vec![], false);
        node.on_peer_message(seq_num_2_req.clone(), &mut state);
        assert_eq!(
            &&seq_num_2_req,
            node.msg_log
                .get_messages_of_type_seq(PbftMessageType::SealRequest, 2)
                .first()
                .expect("SealRequest not in log")
        );

        // Simulate committing block 2 and verify that the node sends a seal for block 2 to the
        // node that requested it
        assert!(node.on_block_commit(vec![2], &mut state).is_ok());
        assert_eq!(3, state.seq_num);
        assert!(service.was_called_with_args(stringify_func_call!(
            "send_to",
            &vec![3],
            "Seal",
            node.build_seal(&mut state)
                .expect("Failed to build seal")
                .write_to_bytes()
                .expect("Failed to write seal to bytes")
        )));
    }

    /// When a node that is catching up has requested the consensus seal for the final block and
    /// another node has replied with the seal, the requesting node will need to handle the seal
    /// message. This handling includes validating the message according to the following criteria:
    ///
    /// 1. The node has the block that this seal is for in its log
    /// 2. The block is for the current sequence number
    /// 3. The consensus seal itself is valid (as determined by the
    ///    `PbftNode::verify_consensus_seal` method)
    ///
    /// (1) and (2) ensure that the node can and should actually commit the block the seal is for:
    /// if the node doesn’t have that block or the block isn’t for the node’s current sequence
    /// number, it will not be able to commit it at the current sequence number. (3) validates the
    /// seal itself to make sure it is correct.
    ///
    /// In addition to these criteria, the node should only commit the block using the seal once;
    /// because the node requests the seal from all nodes in the network, it will receive a seal
    /// from most (if not all) of the other nodes. To prevent trying to commit the same block each
    /// time, the node must check if it is in the Finishing phase to determine whether or not it
    /// has already instructed the validator to commit the block.
    #[test]
    #[allow(unused_must_use)]
    fn test_seal_reply_handling() {
        // Create signing keys for a new network and instantiate node 1
        let key_pairs = mock_signer_network(4);
        let (mut node, mut state, service) = mock_node(
            &mock_config_from_signer_network(&key_pairs),
            key_pairs[1].pub_key.clone(),
            mock_block(0),
        );

        // Receive a seal for block 1 and verify that the node doesn't use it for catch up (node
        // doesn't have the block yet)
        let seal1 = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        let seal_msg1 = ParsedMessage {
            from_self: false,
            header_bytes: vec![],
            header_signature: vec![],
            message: PbftMessageWrapper::Seal(seal1.clone()),
            message_bytes: seal1
                .write_to_bytes()
                .expect("Failed to write seal1 to bytes"),
        };
        node.on_peer_message(seal_msg1.clone(), &mut state);
        assert_eq!(PbftPhase::PrePreparing, state.phase);

        // Add blocks 1 and 2 to the node's log
        node.msg_log.add_validated_block(mock_block(1));
        node.msg_log.add_validated_block(mock_block(2));

        // Receive a seal for block 2 and verify that the node doesn't use it for catch up (not for
        // current sequence number)
        let seal2 = mock_seal(
            0,
            2,
            vec![2],
            &key_pairs[0],
            (2..4)
                .map(|i| mock_vote(PbftMessageType::Commit, 0, 2, vec![2], &key_pairs[i]))
                .collect::<Vec<_>>(),
        );
        let seal_msg2 = ParsedMessage {
            from_self: false,
            header_bytes: vec![],
            header_signature: vec![],
            message: PbftMessageWrapper::Seal(seal2.clone()),
            message_bytes: seal2
                .write_to_bytes()
                .expect("Failed to write seal2 to bytes"),
        };
        node.on_peer_message(seal_msg2, &mut state);
        assert_eq!(PbftPhase::PrePreparing, state.phase);

        // Verify that an invalid seal (e.g. vote from seal signer) is rejected
        let invalid_seal1 = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[0],
            vec![
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[0]),
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[2]),
            ],
        );
        let invalid_seal_msg1 = ParsedMessage {
            from_self: false,
            header_bytes: vec![],
            header_signature: vec![],
            message: PbftMessageWrapper::Seal(invalid_seal1.clone()),
            message_bytes: invalid_seal1
                .write_to_bytes()
                .expect("Failed to write seal1 to bytes"),
        };
        node.on_peer_message(invalid_seal_msg1, &mut state);
        assert_eq!(PbftPhase::PrePreparing, state.phase);

        // Verify that a valid seal for block one is accepted and used to perform a catch up commit
        // of block 1
        assert!(node.on_peer_message(seal_msg1, &mut state).is_ok());
        assert_eq!(PbftPhase::Finishing(false), state.phase);
        assert!(service.was_called_with_args(stringify_func_call!("commit_block", vec![1])));

        // Verify that a duplicate seal won't result in another commit_block call
        let extra_seal1 = mock_seal(
            0,
            1,
            vec![1],
            &key_pairs[2],
            vec![
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[0]),
                mock_vote(PbftMessageType::Commit, 0, 1, vec![1], &key_pairs[3]),
            ],
        );
        let extra_seal_msg1 = ParsedMessage {
            from_self: false,
            header_bytes: vec![],
            header_signature: vec![],
            message: PbftMessageWrapper::Seal(extra_seal1.clone()),
            message_bytes: extra_seal1
                .write_to_bytes()
                .expect("Failed to write seal1 to bytes"),
        };
        assert!(node.on_peer_message(extra_seal_msg1, &mut state).is_ok());
        assert!(service.was_called_with_args_once(stringify_func_call!("commit_block", vec![1])));
    }

    /// When the whole network is starting "fresh" from a non-genesis block, none of the nodes will
    /// have the `Commit` messages necessary to build the consensus seal for the last committed
    /// block (the chain head). To bootstrap the network in this scenario, all nodes will send a
    /// `Commit` message for their chain head whenever one of the PBFT members connects; when
    /// > 2f + 1 nodes have connected and received these `Commit` messages, the nodes will be able
    /// to build a seal using the messages.
    #[test]
    #[allow(unused_must_use)]
    fn test_broadcast_bootstrap_commit() {
        // Initialize a node
        let (mut node, mut state, service) = mock_node(&mock_config(4), vec![0], mock_block(0));
        assert_eq!(1, state.seq_num);

        // Verify commit isn't broadcast when chain head is block 0 (no seal needed for block)
        node.on_peer_connected(vec![1], &mut state);
        assert!(!service.was_called("send_to"));

        // Simulate committing block 1
        node.msg_log.add_validated_block(mock_block(1));
        assert!(node.on_block_commit(vec![1], &mut state).is_ok());
        assert_eq!(2, state.seq_num);
        assert_eq!(vec![1], state.chain_head);

        // Verify peer connections from non-members are ignored
        node.on_peer_connected(vec![4], &mut state);
        assert!(!service.was_called("send_to"));

        // Verify that a Commit with view 0 is sent when chain head is block 1
        assert!(node.on_peer_connected(vec![1], &mut state).is_ok());
        assert!(service.was_called_with_args(stringify_func_call!(
            "send_to",
            vec![1],
            "Commit",
            mock_msg(PbftMessageType::Commit, 0, 1, vec![0], vec![1], false).message_bytes
        )));

        // Simulate committing block 2 (with seal for block 1)
        let key_pairs = mock_signer_network(3);
        let mut block2 = mock_block(2);
        block2.payload = mock_seal(
            1,
            1,
            vec![1],
            &key_pairs[0],
            (1..3)
                .map(|i| mock_vote(PbftMessageType::Commit, 1, 1, vec![1], &key_pairs[i]))
                .collect::<Vec<_>>(),
        )
        .write_to_bytes()
        .expect("Failed to write seal to bytes");
        node.msg_log.add_validated_block(block2);
        assert!(node.on_block_commit(vec![2], &mut state).is_ok());
        assert_eq!(3, state.seq_num);
        assert_eq!(vec![2], state.chain_head);

        // Verify that a Commit with view 1 (same as consensus seal in block 2) is sent
        assert!(node.on_peer_connected(vec![2], &mut state).is_ok());
        assert!(service.was_called_with_args(stringify_func_call!(
            "send_to",
            vec![2],
            "Commit",
            mock_msg(PbftMessageType::Commit, 1, 2, vec![0], vec![2], false).message_bytes
        )));

        // Verify Commit messages are sent to all peers that are already connected on node startup
        let peers = vec![PeerInfo { peer_id: vec![2] }, PeerInfo { peer_id: vec![3] }];
        let mut state2 = PbftState::new(vec![1], 2, &mock_config(4));
        let service2 = MockService::new(&mock_config(4));
        let _node2 = PbftNode::new(
            &mock_config(4),
            mock_block(2),
            peers,
            Box::new(service2.clone()),
            &mut state2,
        );
        assert!(service2.was_called_with_args(stringify_func_call!(
            "send_to",
            vec![2],
            "Commit",
            mock_msg(PbftMessageType::Commit, 0, 2, vec![1], vec![2], false).message_bytes
        )));
        assert!(service2.was_called_with_args(stringify_func_call!(
            "send_to",
            vec![3],
            "Commit",
            mock_msg(PbftMessageType::Commit, 0, 2, vec![1], vec![2], false).message_bytes
        )));
    }
}
