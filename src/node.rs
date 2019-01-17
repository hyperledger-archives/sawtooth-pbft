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

use hex;
use itertools::Itertools;
use protobuf::{Message, RepeatedField};
use sawtooth_sdk::consensus::engine::{Block, BlockId, PeerId};
use sawtooth_sdk::consensus::service::Service;
use sawtooth_sdk::messages::consensus::ConsensusPeerMessageHeader;
use sawtooth_sdk::signing::{create_context, secp256k1::Secp256k1PublicKey};

use crate::config::{get_peers_from_settings, PbftConfig};
use crate::error::PbftError;
use crate::hash::verify_sha512;
use crate::message_log::PbftLog;
use crate::message_type::{ParsedMessage, PbftMessageType};
use crate::protos::pbft_message::{
    PbftBlock, PbftMessage, PbftMessageInfo, PbftNewView, PbftSeal, PbftSignedVote,
};
use crate::state::{PbftMode, PbftPhase, PbftState};
use crate::timing::Timeout;

/// Contains the core logic of the PBFT node
pub struct PbftNode {
    /// Used for interactions with the validator
    pub service: Box<Service>,

    /// Log of messages this node has received and accepted
    pub msg_log: PbftLog,
}

impl PbftNode {
    /// Construct a new PBFT node
    ///
    /// If the node is the primary on start-up, it initializes a new block on the chain
    pub fn new(config: &PbftConfig, service: Box<Service>, is_primary: bool) -> Self {
        let mut n = PbftNode {
            service,
            msg_log: PbftLog::new(config),
        };

        // Primary initializes a block
        if is_primary {
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
    /// `Commit`, `ViewChange`, and `NewView`. If the node is view changing, ignore all messages
    /// that aren't `ViewChange`s or `NewView`s.
    pub fn on_peer_message(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        debug!("{}: Got peer message: {}", state, msg.info());

        let msg_type = PbftMessageType::from(msg.info().msg_type.as_str());

        // If this node is in the process of a view change, ignore all messages except ViewChanges
        // and NewViews
        if match state.mode {
            PbftMode::ViewChanging(_) => true,
            _ => false,
        } && msg_type != PbftMessageType::ViewChange
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
            _ => warn!("Received message with unknown type: {:?}", msg_type),
        }

        Ok(())
    }

    /// Handle a `PrePrepare` message
    ///
    /// A `PrePrepare` message is accepted and added to the log if the following are true:
    /// - The message signature is valid (already verified by validator)
    /// - The message is from the primary
    /// - There is a matching BlockNew message
    /// - A `PrePrepare` message does not already exist at this view and sequence number with a
    ///   different block
    /// - The message's view matches the node's current view (handled by message log)
    ///
    /// Once a `PrePrepare` for the current sequence number is accepted and added to the log, the
    /// node node will instruct the validator to validate the block
    fn handle_pre_prepare(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Check that the message is from the current primary
        if PeerId::from(msg.info().get_signer_id()) != state.get_primary_id() {
            warn!(
                "Got PrePrepare from a secondary node {:?}; ignoring message",
                msg.info().get_signer_id()
            );
            return Ok(());
        }

        // Check that there is a matching BlockNew message; if not, add the PrePrepare to the
        // backlog because we can't perform consensus until the validator has this block
        let block_new_exists = self
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::BlockNew, msg.info().get_seq_num())
            .iter()
            .any(|block_new_msg| block_new_msg.get_block() == msg.get_block());
        if !block_new_exists {
            debug!("No matching BlockNew found for PrePrepare; pushing to backlog");
            self.msg_log.push_backlog(msg);
            return Ok(());
        }

        // Check that no `PrePrepare`s already exist with this view and sequence number but a
        // different block; if this is violated, the primary is faulty so initiate a view change
        let mut mismatched_blocks = self
            .msg_log
            .get_messages_of_type_seq_view(
                PbftMessageType::PrePrepare,
                msg.info().get_seq_num(),
                msg.info().get_view(),
            )
            .iter()
            .filter_map(|existing_msg| {
                let block = existing_msg.get_block().clone();
                if &block != msg.get_block() {
                    Some(block)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if !mismatched_blocks.is_empty() {
            mismatched_blocks.push(msg.get_block().clone());
            mismatched_blocks.iter().for_each(|block| {
                self.service
                    .fail_block(block.get_block_id().to_vec())
                    .unwrap_or_else(|err| {
                        error!("Couldn't fail block {:?} due to error: {:?}", block, err)
                    });
            });
            self.start_view_change(state, state.view + 1)?;
            return Err(PbftError::FaultyPrimary(format!(
                "When checking PrePrepare with block {:?}, found PrePrepare(s) with same view and \
                 seq num but mismatched block(s): {:?}",
                msg.get_block(),
                mismatched_blocks,
            )));
        }

        // Add message to the log
        self.msg_log.add_message(msg.clone(), state)?;

        // If this message is for the current sequence number and the node is in the PrePreparing
        // phase, switch to Preparing
        if msg.info().get_seq_num() == state.seq_num && state.phase == PbftPhase::PrePreparing {
            state.switch_phase(PbftPhase::Preparing)?;

            // We can also stop the view change timer, since we received a new block and a
            // valid PrePrepare in time
            state.faulty_primary_timeout.stop();

            self._broadcast_pbft_message(
                state.seq_num,
                PbftMessageType::Prepare,
                msg.get_block().clone(),
                state,
            )?;
        }

        Ok(())
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
        let block = msg.get_block().clone();

        self.msg_log.add_message(msg, state)?;

        // If this message is for the current sequence number and the node is in the Preparing
        // phase, check if the node is ready to move on to the Committing phase
        if info.get_seq_num() == state.seq_num && state.phase == PbftPhase::Preparing {
            // The node is ready to move on to the Committing phase (i.e. the predicate `prepared`
            // is true) when its log has 2f + 1 Prepare messages from different nodes that match
            // the PrePrepare message received earlier (same view, sequence number, and block)
            if let Some(pre_prep) = self
                .msg_log
                .get_first_msg(&info, PbftMessageType::PrePrepare)
            {
                if self.msg_log.log_has_required_msgs(
                    PbftMessageType::Prepare,
                    &pre_prep,
                    true,
                    2 * state.f + 1,
                ) {
                    state.switch_phase(PbftPhase::Committing)?;
                    self._broadcast_pbft_message(
                        state.seq_num,
                        PbftMessageType::Commit,
                        block,
                        state,
                    )?;
                }
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
        let block = msg.get_block().clone();

        self.msg_log.add_message(msg, state)?;

        // If this message is for the current sequence number and the node is in the Committing
        // phase, check if the node is ready to commit the block
        if info.get_seq_num() == state.seq_num && state.phase == PbftPhase::Committing {
            // The node is ready to commit the block (i.e. the predicate `committable` is true)
            // when its log has 2f + 1 Commit messages from different nodes that match the
            // PrePrepare message received earlier (same view, sequence number, and block)
            if let Some(pre_prep) = self
                .msg_log
                .get_first_msg(&info, PbftMessageType::PrePrepare)
            {
                if self.msg_log.log_has_required_msgs(
                    PbftMessageType::Commit,
                    &pre_prep,
                    true,
                    2 * state.f + 1,
                ) {
                    self.service
                        .commit_block(block.block_id.clone())
                        .map_err(|err| {
                            PbftError::ServiceError(
                                format!(
                                    "Failed to commit block {:?} / {:?}",
                                    block.block_num,
                                    hex::encode(&block.block_id[..3])
                                ),
                                err,
                            )
                        })?;
                    state.switch_phase(PbftPhase::Finished)?;
                }
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

        self.msg_log.add_message(msg.clone(), state)?;

        // Even if the node hasn't detected a faulty primary yet, start view changing if there are
        // f + 1 ViewChange messages in the log for this proposed view (but if already view
        // changing, only do this for a later view); this will prevent starting the view change too
        // late
        if match state.mode {
            PbftMode::ViewChanging(v) => msg_view > v,
            PbftMode::Normal => true,
        } && self.msg_log.log_has_required_msgs(
            PbftMessageType::ViewChange,
            msg,
            false,
            state.f + 1,
        ) {
            warn!(
                "{}: Received f + 1 ViewChange messages; starting early view change",
                state
            );
            self.start_view_change(state, msg_view)?;
        }

        // If this node is the new primary and the required 2f ViewChange messages (not including
        // the primary's own) are present in the log, broadcast the NewView message
        let messages = self
            .msg_log
            .get_messages_of_type_view(PbftMessageType::ViewChange, msg_view)
            .iter()
            .cloned()
            .filter(|msg| !msg.from_self)
            .collect::<Vec<_>>();

        if state.is_primary_at_view(msg_view) && messages.len() as u64 >= 2 * state.f {
            let mut new_view = PbftNewView::new();

            new_view.set_info(PbftMessageInfo::new_from(
                PbftMessageType::NewView,
                msg_view,
                state.seq_num - 1,
                state.id.clone(),
            ));

            new_view.set_view_changes(Self::signed_votes_from_messages(messages.as_slice()));

            trace!("Created NewView message: {:?}", new_view);

            let msg_bytes = new_view.write_to_bytes().map_err(|err| {
                PbftError::SerializationError("Error writing NewView to bytes".into(), err)
            })?;

            self._broadcast_message(PbftMessageType::NewView, msg_bytes, state)?;
        }

        Ok(())
    }

    /// Handle a `NewView` message
    ///
    /// When a `NewView` is received, first check that the node is expecting it and verify that it
    /// is valid. If the NewView is invalid, start a new view change for the next view; if the
    /// NewView is valid, update the view and the node's state.
    fn handle_new_view(
        &mut self,
        msg: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let new_view = msg.get_new_view_message();

        // Make sure this is a NewView that the node is expecting; if this isn't enforced, a faulty
        // node could send an invalid NewView message to arbitrarily initiate a view change across
        // the network
        if match state.mode {
            PbftMode::ViewChanging(v) => v != new_view.get_info().get_view(),
            _ => true,
        } {
            warn!(
                "Received NewView message ({:?}) for a view that this node is not changing to",
                new_view.get_info().get_view(),
            );
            return Ok(());
        }

        match self.verify_new_view(new_view, state) {
            Err(PbftError::NotFromPrimary) => {
                // Not the new primary that's faulty, so no need to do a new view change,
                // just don't proceed any further
                warn!(
                    "Got NewView message ({:?}) from node that is not primary for new view",
                    new_view,
                );
                return Ok(());
            }
            Err(err) => {
                if let PbftMode::ViewChanging(v) = state.mode {
                    self.start_view_change(state, v + 1)?;
                    return Err(PbftError::FaultyPrimary(format!(
                        "NewView failed verification; starting new view change to view {} - \
                         Error was: {}",
                        v + 1,
                        err
                    )));
                }
            }
            Ok(_) => {
                debug!("NewView passed verification");
            }
        }

        // Update view
        state.view = new_view.get_info().get_view();
        state.view_change_timeout.stop();
        state.reset_to_start();

        info!("{}: Updated to view {}", state, state.view);

        // Initialize a new block if necessary
        if state.is_primary() && state.working_block.is_none() {
            self.service.initialize_block(None).map_err(|err| {
                PbftError::ServiceError("Couldn't initialize block after view change".into(), err)
            })?;
        }

        Ok(())
    }

    /// Handle a `BlockNew` update from the Validator
    ///
    /// The validator has received a new block; verify the block's consensus seal and add the
    /// BlockNew to the message log. If this is the block we are waiting for: set it as the working
    /// block and broadcast a PrePrepare if this node is the primary. If this is the block after
    /// the one this node is working on, use it to catch up.
    pub fn on_block_new(&mut self, block: Block, state: &mut PbftState) -> Result<(), PbftError> {
        info!("{}: Got BlockNew: {}", state, block.block_num);
        debug!("Block details: {:?}", block);

        if block.block_num < state.seq_num {
            debug!(
                "Ignoring block ({}) that's older than current sequence number ({}).",
                block.block_num, state.seq_num
            );
            return Ok(());
        }

        match self.verify_consensus_seal(&block, state) {
            Ok(_) => {
                debug!("Consensus seal passed verification");
            }
            Err(err) => {
                self.service
                    .fail_block(block.block_id)
                    .unwrap_or_else(|err| error!("Couldn't fail block due to error: {:?}", err));
                return Err(PbftError::FaultyPrimary(format!(
                    "Consensus seal failed verification - Error was: {}",
                    err
                )));
            }
        }

        // Create PBFT message for BlockNew and add it to the log
        let mut msg = PbftMessage::new();
        msg.set_info(PbftMessageInfo::new_from(
            PbftMessageType::BlockNew,
            state.view,
            block.block_num,
            state.id.clone(),
        ));

        let pbft_block = PbftBlock::from(block.clone());
        msg.set_block(pbft_block.clone());

        self.msg_log
            .add_message(ParsedMessage::from_pbft_message(msg.clone()), state)?;

        // This block's seal can be used to commit the next block (i.e. catch-up) if it's the block
        // after the one this node is waiting for and the node hasn't already told the validator to
        // commit the block it's waiting for
        if block.block_num == state.seq_num + 1 && state.phase != PbftPhase::Finished {
            self.catchup(state, &block)?;
        } else if block.block_num == state.seq_num {
            // This is the block we're waiting for, so we update state
            state.working_block = Some(msg.get_block().clone());

            debug!("Working block set to {:?}", state.working_block);

            // Send PrePrepare messages if we're the primary
            if block.signer_id == state.id && state.is_primary() {
                debug!("Broadcasting PrePrepares");
                let s = state.seq_num;
                self._broadcast_pbft_message(s, PbftMessageType::PrePrepare, pbft_block, state)?;
            }
        }

        Ok(())
    }

    /// Use the given block's consensus seal to verify and commit the block this node is working on
    fn catchup(&mut self, state: &mut PbftState, block: &Block) -> Result<(), PbftError> {
        info!(
            "{}: Attempting to commit block {} using catch-up",
            state, state.seq_num
        );

        match state.working_block {
            Some(ref working_block) => {
                let block_num_matches = block.block_num == working_block.get_block_num() + 1;
                let block_id_matches = block.previous_id == working_block.get_block_id();

                if !block_num_matches || !block_id_matches {
                    return Err(PbftError::InternalError(format!(
                        "Cancelling catch-up because block ({:?}) does not match working block \
                         ({:?})",
                        block, working_block
                    )));
                }
            }
            None => {
                return Err(PbftError::InternalError(format!(
                    "Cancelling catch-up because node does not have block {}",
                    state.seq_num
                )));
            }
        }

        // Parse messages from the seal
        let seal: PbftSeal = protobuf::parse_from_bytes(&block.payload).map_err(|err| {
            PbftError::SerializationError("Error parsing seal for catch-up".into(), err)
        })?;

        let messages =
            seal.get_previous_commit_votes()
                .iter()
                .try_fold(Vec::new(), |mut msgs, v| {
                    msgs.push(ParsedMessage::from_pbft_message(
                        protobuf::parse_from_bytes(&v.get_message_bytes()).map_err(|err| {
                            PbftError::SerializationError("Error parsing commit vote".into(), err)
                        })?,
                    ));
                    Ok(msgs)
                })?;

        // Update view if necessary
        let view = messages[0].info().get_view();
        if view > state.view {
            info!("Updating view from {} to {}", state.view, view);
            state.view = view;
        }

        // Add messages to the log
        for message in &messages {
            self.msg_log.add_message(message.clone(), state)?;
        }

        // Commit the new block using one of the parsed messages and skip straight to Finished
        self.service
            .commit_block(messages[0].get_block().block_id.clone())
            .map_err(|err| {
                PbftError::ServiceError(
                    format!(
                        "Failed to commit block with catch-up {:?} / {:?}",
                        messages[0].get_block().block_num,
                        hex::encode(&messages[0].get_block().block_id[..3])
                    ),
                    err,
                )
            })?;
        state.phase = PbftPhase::Finished;

        // Call on_block_commit right away so we're ready to catch up again if necessary
        self.on_block_commit(BlockId::from(messages[0].get_block().get_block_id()), state)
    }

    /// Handle a `BlockCommit` update from the Validator
    ///
    /// A block was sucessfully committed; update state to be ready for the next block, make any
    /// necessary view and membership changes, garbage collect the logs, and start a new block if
    /// this node is the primary.
    pub fn on_block_commit(
        &mut self,
        block_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        info!(
            "{}: Got BlockCommit for {:?}",
            state,
            hex::encode(&block_id[..3])
        );

        let is_working_block = match state.working_block {
            Some(ref block) => BlockId::from(block.get_block_id()) == block_id,
            None => false,
        };

        // Ignore this BlockCommit if the node isn't waiting for it
        if state.phase != PbftPhase::Finished || !is_working_block {
            return Ok(());
        }

        // Update state to be ready for next block
        state.switch_phase(PbftPhase::PrePreparing)?;
        state.seq_num += 1;

        // If the node already has a BlockNew for the next block, make it the working block;
        // otherwise just set the working block to None
        state.working_block = self
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::BlockNew, state.seq_num)
            .first()
            .map(|msg| msg.get_block().clone());

        // Increment the view if a view change must be forced for fairness or if membership has
        // changed
        if state.at_forced_view_change() || self.update_membership(block_id.clone(), state) {
            state.view += 1;
        }

        // Tell the log to garbage collect if it needs to
        self.msg_log.garbage_collect(state.seq_num);

        // Restart the faulty primary timeout for the next block
        state.faulty_primary_timeout.start();

        if state.is_primary() && state.working_block.is_none() {
            info!("{}: Initializing block on top of {:?}", state, block_id);
            self.service
                .initialize_block(Some(block_id))
                .map_err(|err| {
                    PbftError::ServiceError("Couldn't initialize block after commit".into(), err)
                })?;
        }

        Ok(())
    }

    /// Check the on-chain list of peers; if it has changed, update peers list and return true.
    ///
    /// # Panics
    /// + If the node is unable to query the validator for on-chain settings
    /// + If the `sawtooth.consensus.pbft.peers` setting is unset or invalid
    /// + If the network this node is on does not have enough nodes to be Byzantine fault tolernant
    fn update_membership(&mut self, block_id: BlockId, state: &mut PbftState) -> bool {
        // Get list of peers from settings
        let settings = self
            .service
            .get_settings(
                block_id,
                vec![String::from("sawtooth.consensus.pbft.peers")],
            )
            .expect("Couldn't load settings to check for membership updates");
        let peers = get_peers_from_settings(&settings);
        let new_peers_set: HashSet<PeerId> = peers.iter().cloned().collect();

        // Check if membership has changed
        let old_peers_set: HashSet<PeerId> = state.peer_ids.iter().cloned().collect();

        if new_peers_set != old_peers_set {
            state.peer_ids = peers;
            let f = (state.peer_ids.len() - 1) / 3;
            if f == 0 {
                panic!("This network no longer contains enough nodes to be fault tolerant");
            }
            state.f = f as u64;
            return true;
        }

        false
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

    /// Build a consensus seal to be put in the block that matches the `summary` and proves the
    /// last block committed by this node
    fn build_seal(&mut self, state: &PbftState, summary: Vec<u8>) -> Result<Vec<u8>, PbftError> {
        debug!("{}: Building seal for block {}", state, state.seq_num - 1);

        // The previous block may have been committed in a different view, so the node will need
        // find the view that contains the required 2f Commit messages for building the seal
        let messages = self
            .msg_log
            .get_messages_of_type_seq(PbftMessageType::Commit, state.seq_num - 1)
            .iter()
            // Filter out this node's own messages because self-sent messages aren't signed and
            // therefore can't be included in the seal
            .filter(|msg| !msg.from_self)
            .cloned()
            // Map to (view, msg) pairs
            .map(|msg| (msg.info().get_view(), msg))
            // Group messages together by view
            .into_group_map()
            .into_iter()
            // One and only one view should have the required number of messages, since the block
            // at this sequence number should only have been committed once and therefore in only
            // one view
            .find_map(|(_view, msgs)| {
                if msgs.len() as u64 >= 2 * state.f {
                    Some(msgs)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                PbftError::InternalError(String::from(
                    "Couldn't find 2f commit messages in the message log for building a seal!",
                ))
            })?;

        let mut seal = PbftSeal::new();

        seal.set_summary(summary);
        seal.set_previous_id(BlockId::from(messages[0].get_block().get_block_id()));
        seal.set_previous_commit_votes(Self::signed_votes_from_messages(messages.as_slice()));

        debug!("Seal created: {:?}", seal);

        seal.write_to_bytes()
            .map_err(|err| PbftError::SerializationError("Error writing seal to bytes".into(), err))
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
        let pbft_message: PbftMessage = protobuf::parse_from_bytes(&vote.get_message_bytes())
            .map_err(|err| {
                PbftError::SerializationError("Error parsing PbftMessage from vote".into(), err)
            })?;
        let header: ConsensusPeerMessageHeader =
            protobuf::parse_from_bytes(&vote.get_header_bytes()).map_err(|err| {
                PbftError::SerializationError("Error parsing header from vote".into(), err)
            })?;

        trace!(
            "Verifying vote with PbftMessage: {:?} and header: {:?}",
            pbft_message,
            header
        );

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
                    "Vote ({:?}) failed signature verification",
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
        // Make sure this is from the new primary
        if PeerId::from(new_view.get_info().get_signer_id())
            != state.get_primary_id_at_view(new_view.get_info().get_view())
        {
            return Err(PbftError::NotFromPrimary);
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
                    .and_then(|id| Ok(ids.insert(id)))?;
                    Ok(ids)
                })?;

        // All of the votes must come from known peers, and the primary can't explicitly vote
        // itself, since broacasting the NewView is an implicit vote. Check that the votes received
        // are from a subset of "peers - primary".
        let peer_ids: HashSet<_> = state
            .peer_ids
            .iter()
            .cloned()
            .filter(|pid| pid != &PeerId::from(new_view.get_info().get_signer_id()))
            .collect();

        debug!(
            "Comparing voter IDs ({:?}) with peer IDs - primary ({:?})",
            voter_ids, peer_ids
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

    /// Verify the consensus seal from the current block that proves the previous block
    ///
    /// # Panics
    /// + If the node is unable to query the validator for on-chain settings
    /// + If the `sawtooth.consensus.pbft.peers` setting is unset or invalid
    fn verify_consensus_seal(
        &mut self,
        block: &Block,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Since block 0 is genesis, block 1 is the first that can be verified with a seal; this
        // means that the node won't see a seal until block 2
        if block.block_num < 2 {
            return Ok(());
        }

        if block.payload.is_empty() {
            return Err(PbftError::InvalidMessage(
                "Block published without a seal".into(),
            ));
        }

        let seal: PbftSeal = protobuf::parse_from_bytes(&block.payload).map_err(|err| {
            PbftError::SerializationError("Error parsing seal for verification".into(), err)
        })?;

        debug!("Parsed seal: {:?}", seal);

        if seal.previous_id != &block.previous_id[..] {
            return Err(PbftError::InvalidMessage(format!(
                "Seal's previous ID ({}) doesn't match block's previous ID ({})",
                hex::encode(&seal.previous_id[..3]),
                hex::encode(&block.previous_id[..3])
            )));
        }

        if seal.summary != &block.summary[..] {
            return Err(PbftError::InvalidMessage(format!(
                "Seal's summary ({:?}) doesn't match block's summary ({:?})",
                seal.summary, block.summary
            )));
        }

        // Verify each individual vote and extract the signer ID from each PbftMessage so the IDs
        // can be verified
        let voter_ids =
            seal.get_previous_commit_votes()
                .iter()
                .try_fold(HashSet::new(), |mut ids, vote| {
                    Self::verify_vote(vote, PbftMessageType::Commit, |msg| {
                        if msg.get_block().block_id != seal.previous_id {
                            return Err(PbftError::InvalidMessage(format!(
                                "Commit vote's block ID ({:?}) doesn't match seal's previous ID \
                                 ({:?})",
                                msg.get_block().block_id,
                                seal.previous_id
                            )));
                        }
                        Ok(())
                    })
                    .and_then(|id| Ok(ids.insert(id)))?;
                    Ok(ids)
                })?;

        // All of the votes must come from known peers, and the primary can't explicitly vote
        // itself, since publishing a block is an implicit vote. Check that the votes received are
        // from a subset of "peers - primary". Use the list of peers from the block this seal
        // verifies, since it may have changed.
        let settings = self
            .service
            .get_settings(
                block.previous_id.clone(),
                vec![String::from("sawtooth.consensus.pbft.peers")],
            )
            .expect("Couldn't load settings to verify list of votes in consensus seal");
        let peers = get_peers_from_settings(&settings);

        let peer_ids: HashSet<_> = peers
            .iter()
            .cloned()
            .filter(|pid| pid != &block.signer_id)
            .collect();

        debug!(
            "Comparing voter IDs ({:?}) with on-chain peer IDs - primary ({:?})",
            voter_ids, peer_ids
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

        debug!("{}: Attempting to summarize block", state);

        let summary = match self.service.summarize_block() {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!("Couldn't summarize, so not finalizing: {}", err);
                return Ok(());
            }
        };

        // We don't publish a consensus seal at block 1, since we never receive any
        // votes on the genesis block. Leave payload blank for the first block.
        let data = if state.seq_num <= 1 {
            vec![]
        } else {
            self.build_seal(state, summary)?
        };

        match self.service.finalize_block(data) {
            Ok(block_id) => {
                info!("{}: Publishing block {:?}", state, block_id);
                Ok(())
            }
            Err(err) => Err(PbftError::ServiceError(
                "Couldn't finalize block".into(),
                err,
            )),
        }
    }

    /// Check to see if the faulty primary timeout has expired
    pub fn check_faulty_primary_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.faulty_primary_timeout.check_expired()
    }

    /// Start the faulty primary timeout
    pub fn start_faulty_primary_timeout(&self, state: &mut PbftState) {
        state.faulty_primary_timeout.start();
    }

    /// Check to see if the view change timeout has expired
    pub fn check_view_change_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.view_change_timeout.check_expired()
    }

    /// Retry messages from the `PrePrepare` backlog
    pub fn retry_backlog(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        if let Some(msg) = self.msg_log.pop_backlog() {
            debug!("{}: Popped PrePrepare ({:?}) from backlog", state, msg);
            self.on_peer_message(msg, state)
        } else {
            Ok(())
        }
    }

    // ---------- Methods for communication between nodes ----------

    /// Construct the message bytes and broadcast the message to all of this node's peers and
    /// itself
    fn _broadcast_pbft_message(
        &mut self,
        seq_num: u64,
        msg_type: PbftMessageType,
        block: PbftBlock,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let mut msg = PbftMessage::new();
        msg.set_info(PbftMessageInfo::new_from(
            msg_type,
            state.view,
            seq_num,
            state.id.clone(),
        ));
        msg.set_block(block);

        trace!("{}: Created PBFT message: {:?}", state, msg);

        self._broadcast_message(msg_type, msg.write_to_bytes().unwrap_or_default(), state)
    }

    /// Broadcast the specified message to all of the node's peers, including itself
    #[cfg(not(test))]
    fn _broadcast_message(
        &mut self,
        msg_type: PbftMessageType,
        msg: Vec<u8>,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        trace!("{}: Broadcasting {:?}", state, msg_type);

        // Broadcast to peers
        self.service
            .broadcast(String::from(msg_type).as_str(), msg.clone())
            .unwrap_or_else(|err| {
                error!(
                    "Couldn't broadcast message ({:?}) due to error: {}",
                    msg, err
                )
            });

        // Send to self
        let parsed_message = ParsedMessage::from_bytes(msg, msg_type)?;

        self.on_peer_message(parsed_message, state)
    }

    /// Disabled self-sending (used for testing)
    #[cfg(test)]
    fn _broadcast_message(
        &mut self,
        _msg_type: PbftMessageType,
        _msg: Vec<u8>,
        _state: &mut PbftState,
    ) -> Result<(), PbftError> {
        return Ok(());
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

        // Stop the faulty primary timeout because it is not needed until after the view change
        state.faulty_primary_timeout.stop();

        // Update the view change timeout and start it
        state.view_change_timeout = Timeout::new(
            state
                .view_change_duration
                .checked_mul((view - state.view) as u32)
                .expect("View change timeout has overflowed"),
        );
        state.view_change_timeout.start();

        // Broadcast the view change message
        let mut vc_msg = PbftMessage::new();
        vc_msg.set_info(PbftMessageInfo::new_from(
            PbftMessageType::ViewChange,
            view,
            state.seq_num - 1,
            state.id.clone(),
        ));

        trace!("Created view change message: {:?}", vc_msg);

        let msg_bytes = vc_msg.write_to_bytes().map_err(|err| {
            PbftError::SerializationError("Error writing ViewChange to bytes".into(), err)
        })?;

        self._broadcast_message(PbftMessageType::ViewChange, msg_bytes, state)
    }
}

/// NOTE: Testing the PbftNode is a bit strange. Due to missing functionality in the Service,
/// a node calling `broadcast()` doesn't include sending a message to itself. In order to get around
/// this, `on_peer_message()` is called, which sometimes causes unintended side effects when
/// testing. Self-sending has been disabled (see `broadcast()` method) for testing purposes.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::mock_config;
    use crate::hash::{hash_sha256, hash_sha512};
    use crate::protos::pbft_message::PbftMessageInfo;
    use sawtooth_sdk::consensus::engine::{Error, PeerId};
    use sawtooth_sdk::messages::consensus::ConsensusPeerMessageHeader;
    use serde_json;
    use std::collections::HashMap;
    use std::default::Default;
    use std::fs::{remove_file, File};
    use std::io::prelude::*;

    const BLOCK_FILE: &str = "target/blocks.txt";

    /// Mock service to roughly keep track of the blockchain
    pub struct MockService {
        pub chain: Vec<BlockId>,
    }

    impl MockService {
        /// Serialize the chain into JSON, and write to a file
        fn write_chain(&self) {
            let mut block_file = File::create(BLOCK_FILE).unwrap();
            let block_bytes: Vec<Vec<u8>> = self
                .chain
                .iter()
                .map(|block: &BlockId| -> Vec<u8> { Vec::<u8>::from(block.clone()) })
                .collect();

            let ser_blocks = serde_json::to_string(&block_bytes).unwrap();
            block_file.write_all(&ser_blocks.into_bytes()).unwrap();
        }
    }

    impl Service for MockService {
        fn send_to(
            &mut self,
            _peer: &PeerId,
            _message_type: &str,
            _payload: Vec<u8>,
        ) -> Result<(), Error> {
            Ok(())
        }
        fn broadcast(&mut self, _message_type: &str, _payload: Vec<u8>) -> Result<(), Error> {
            Ok(())
        }
        fn initialize_block(&mut self, _previous_id: Option<BlockId>) -> Result<(), Error> {
            Ok(())
        }
        fn summarize_block(&mut self) -> Result<Vec<u8>, Error> {
            Ok(Default::default())
        }
        fn finalize_block(&mut self, _data: Vec<u8>) -> Result<BlockId, Error> {
            Ok(Default::default())
        }
        fn cancel_block(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn check_blocks(&mut self, _priority: Vec<BlockId>) -> Result<(), Error> {
            Ok(())
        }
        fn commit_block(&mut self, block_id: BlockId) -> Result<(), Error> {
            self.chain.push(block_id);
            self.write_chain();
            Ok(())
        }
        fn ignore_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
            Ok(())
        }
        fn fail_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
            Ok(())
        }
        fn get_blocks(
            &mut self,
            block_ids: Vec<BlockId>,
        ) -> Result<HashMap<BlockId, Block>, Error> {
            let mut res = HashMap::new();
            for id in &block_ids {
                let index = self
                    .chain
                    .iter()
                    .position(|val| val == id)
                    .unwrap_or(self.chain.len());
                res.insert(id.clone(), mock_block(index as u64));
            }
            Ok(res)
        }
        fn get_chain_head(&mut self) -> Result<Block, Error> {
            let prev_num = self.chain.len().checked_sub(2).unwrap_or(0);
            Ok(Block {
                block_id: self.chain.last().unwrap().clone(),
                previous_id: self.chain.get(prev_num).unwrap().clone(),
                signer_id: PeerId::from(vec![]),
                block_num: self.chain.len().checked_sub(1).unwrap_or(0) as u64,
                payload: vec![],
                summary: vec![],
            })
        }
        fn get_settings(
            &mut self,
            _block_id: BlockId,
            _settings: Vec<String>,
        ) -> Result<HashMap<String, String>, Error> {
            let mut settings: HashMap<String, String> = Default::default();
            settings.insert(
                "sawtooth.consensus.pbft.peers".to_string(),
                "[\"00\", \"01\", \"02\", \"03\"]".to_string(),
            );
            Ok(settings)
        }
        fn get_state(
            &mut self,
            _block_id: BlockId,
            _addresses: Vec<String>,
        ) -> Result<HashMap<String, Vec<u8>>, Error> {
            Ok(Default::default())
        }
    }

    /// Create a node, based on a given ID
    fn mock_node(node_id: PeerId) -> PbftNode {
        let service: Box<MockService> = Box::new(MockService {
            // Create genesis block (but with actual ID)
            chain: vec![mock_block_id(0)],
        });
        let cfg = mock_config(4);
        PbftNode::new(&cfg, service, node_id == vec![0])
    }

    /// Create a deterministic BlockId hash based on a block number
    fn mock_block_id(num: u64) -> BlockId {
        BlockId::from(hash_sha256(
            format!("I'm a block with block num {}", num).as_bytes(),
        ))
    }

    /// Create a mock Block, including only the BlockId, the BlockId of the previous block, and the
    /// block number
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

    /// Creates a block with a valid consensus seal for the previous block
    fn mock_block_with_seal(num: u64, node: &mut PbftNode, state: &mut PbftState) -> Block {
        let head = mock_block(num - 1);
        let mut block = mock_block(num);
        block.summary = vec![1, 2, 3];
        let context = create_context("secp256k1").unwrap();

        for i in 0..3 {
            let mut info = PbftMessageInfo::new();
            info.set_msg_type("Commit".into());
            info.set_view(0);
            info.set_seq_num(num - 1);
            info.set_signer_id(vec![i]);

            let mut block = PbftBlock::new();
            block.set_block_id(head.block_id.clone());

            let mut msg = PbftMessage::new();
            msg.set_info(info);
            msg.set_block(block);

            let mut message = ParsedMessage::from_pbft_message(msg);

            let key = context.new_random_private_key().unwrap();
            let pub_key = context.get_public_key(&*key).unwrap();
            let mut header = ConsensusPeerMessageHeader::new();

            header.set_signer_id(pub_key.as_slice().to_vec());
            header.set_content_sha512(hash_sha512(&message.message_bytes));

            let header_bytes = header.write_to_bytes().unwrap();
            let header_signature =
                hex::decode(context.sign(&header_bytes, &*key).unwrap()).unwrap();

            message.from_self = false;
            message.header_bytes = header_bytes;
            message.header_signature = header_signature;

            node.msg_log.add_message(message, state).unwrap();
        }

        block.payload = node.build_seal(state, vec![1, 2, 3]).unwrap();

        block
    }

    /// Create a signed ViewChange message
    fn mock_view_change(view: u64, seq_num: u64, peer: PeerId, from_self: bool) -> ParsedMessage {
        let context = create_context("secp256k1").unwrap();
        let key = context.new_random_private_key().unwrap();
        let pub_key = context.get_public_key(&*key).unwrap();

        let mut vc_msg = PbftMessage::new();
        let info = PbftMessageInfo::new_from(PbftMessageType::ViewChange, view, seq_num, peer);
        vc_msg.set_info(info);

        let mut message = ParsedMessage::from_pbft_message(vc_msg);
        let mut header = ConsensusPeerMessageHeader::new();
        header.set_signer_id(pub_key.as_slice().to_vec());
        header.set_content_sha512(hash_sha512(&message.message_bytes));
        let header_bytes = header.write_to_bytes().unwrap();
        let header_signature = hex::decode(context.sign(&header_bytes, &*key).unwrap()).unwrap();
        message.from_self = from_self;
        message.header_bytes = header_bytes;
        message.header_signature = header_signature;

        message
    }

    /// Create a mock serialized PbftMessage
    fn mock_msg(
        msg_type: PbftMessageType,
        view: u64,
        seq_num: u64,
        block: Block,
        from: PeerId,
    ) -> ParsedMessage {
        let info = PbftMessageInfo::new_from(msg_type, view, seq_num, from);

        let mut pbft_msg = PbftMessage::new();
        pbft_msg.set_info(info);
        pbft_msg.set_block(PbftBlock::from(block));

        ParsedMessage::from_pbft_message(pbft_msg)
    }

    fn panic_with_err(e: PbftError) {
        panic!("{}", e);
    }

    /// Make sure that receiving a `BlockNew` update works as expected for block #1
    #[test]
    fn block_new_initial() {
        // NOTE: Special case for primary node
        let mut node0 = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], 0, &cfg);
        node0.on_block_new(mock_block(1), &mut state0).unwrap();
        assert_eq!(state0.phase, PbftPhase::PrePreparing);
        assert_eq!(state0.seq_num, 1);
        assert_eq!(state0.working_block, Some(PbftBlock::from(mock_block(1))));

        // Try the next block
        let mut node1 = mock_node(vec![1]);
        let mut state1 = PbftState::new(vec![], 0, &cfg);
        node1
            .on_block_new(mock_block(1), &mut state1)
            .unwrap_or_else(panic_with_err);
        assert_eq!(state1.phase, PbftPhase::PrePreparing);
        assert_eq!(state1.working_block, Some(PbftBlock::from(mock_block(1))));
    }

    #[test]
    fn block_new_first_10_blocks() {
        let mut node = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state = PbftState::new(vec![0], 0, &cfg);

        let block_0_id = mock_block_id(0);

        // Assert starting state
        let head = node.service.get_chain_head().unwrap();
        assert_eq!(head.block_num, 0);
        assert_eq!(head.block_id, block_0_id);
        assert_eq!(head.previous_id, block_0_id);

        assert_eq!(state.id, vec![0]);
        assert_eq!(state.view, 0);
        assert_eq!(state.phase, PbftPhase::PrePreparing);
        assert_eq!(state.mode, PbftMode::Normal);
        assert_eq!(state.peer_ids, (0..4).map(|i| vec![i]).collect::<Vec<_>>());
        assert_eq!(state.f, 1);
        assert_eq!(state.forced_view_change_period, 30);
        assert_eq!(state.working_block, None);
        assert!(state.is_primary());

        // Handle the first block and assert resulting state
        node.on_block_new(mock_block(1), &mut state).unwrap();

        let head = node.service.get_chain_head().unwrap();
        assert_eq!(head.block_num, 0);
        assert_eq!(head.block_id, block_0_id);
        assert_eq!(head.previous_id, block_0_id);

        assert_eq!(state.id, vec![0]);
        assert_eq!(state.seq_num, 1);
        assert_eq!(state.view, 0);
        assert_eq!(state.phase, PbftPhase::PrePreparing);
        assert_eq!(state.mode, PbftMode::Normal);
        assert_eq!(state.peer_ids, (0..4).map(|i| vec![i]).collect::<Vec<_>>());
        assert_eq!(state.f, 1);
        assert_eq!(state.forced_view_change_period, 30);
        assert_eq!(state.working_block, Some(PbftBlock::from(mock_block(1))));
        assert!(state.is_primary());

        state.seq_num += 1;

        // Handle the rest of the blocks
        for i in 2..10 {
            assert_eq!(state.seq_num, i);
            let block = mock_block_with_seal(i, &mut node, &mut state);
            node.on_block_new(block.clone(), &mut state).unwrap();

            assert_eq!(state.id, vec![0]);
            assert_eq!(state.view, 0);
            assert_eq!(state.phase, PbftPhase::PrePreparing);
            assert_eq!(state.mode, PbftMode::Normal);
            assert_eq!(state.peer_ids, (0..4).map(|i| vec![i]).collect::<Vec<_>>());
            assert_eq!(state.f, 1);
            assert_eq!(state.forced_view_change_period, 30);
            assert_eq!(state.working_block, Some(PbftBlock::from(block)));
            assert!(state.is_primary());

            state.seq_num += 1;
        }
    }

    /// Make sure that `BlockNew` properly checks the consensus seal.
    #[test]
    fn block_new_consensus() {
        let cfg = mock_config(4);
        let mut node = mock_node(vec![1]);
        let mut state = PbftState::new(vec![], 0, &cfg);
        state.seq_num = 7;
        let head = mock_block(6);
        let mut block = mock_block(7);
        block.summary = vec![1, 2, 3];
        let context = create_context("secp256k1").unwrap();

        for i in 0..3 {
            let mut info = PbftMessageInfo::new();
            info.set_msg_type("Commit".into());
            info.set_view(0);
            info.set_seq_num(6);
            info.set_signer_id(vec![i]);

            let mut block = PbftBlock::new();
            block.set_block_id(head.block_id.clone());

            let mut msg = PbftMessage::new();
            msg.set_info(info);
            msg.set_block(block);

            let mut message = ParsedMessage::from_pbft_message(msg);

            let key = context.new_random_private_key().unwrap();
            let pub_key = context.get_public_key(&*key).unwrap();
            let mut header = ConsensusPeerMessageHeader::new();

            header.set_signer_id(pub_key.as_slice().to_vec());
            header.set_content_sha512(hash_sha512(&message.message_bytes));

            let header_bytes = header.write_to_bytes().unwrap();
            let header_signature =
                hex::decode(context.sign(&header_bytes, &*key).unwrap()).unwrap();

            message.from_self = false;
            message.header_bytes = header_bytes;
            message.header_signature = header_signature;

            node.msg_log.add_message(message, &state).unwrap();
        }

        let seal = node.build_seal(&state, vec![1, 2, 3]).unwrap();
        block.payload = seal;

        node.on_block_new(block, &mut state).unwrap();
    }

    /// Make sure that a valid `PrePrepare` is accepted
    #[test]
    fn test_pre_prepare() {
        let cfg = mock_config(4);
        let mut node0 = mock_node(vec![0]);
        let mut state0 = PbftState::new(vec![0], 0, &cfg);

        // Add BlockNew to log
        let block_new = mock_msg(PbftMessageType::BlockNew, 0, 1, mock_block(1), vec![0]);
        node0
            .msg_log
            .add_message(block_new, &state0)
            .unwrap_or_else(panic_with_err);

        // Add PrePrepare to log
        let valid_msg = mock_msg(PbftMessageType::PrePrepare, 0, 1, mock_block(1), vec![0]);
        node0
            .handle_pre_prepare(valid_msg.clone(), &mut state0)
            .unwrap_or_else(panic_with_err);

        // Verify it worked
        assert!(node0.msg_log.log_has_required_msgs(
            PbftMessageType::PrePrepare,
            &valid_msg,
            true,
            1
        ));
        assert_eq!(state0.phase, PbftPhase::Preparing);
    }

    /// Make sure that receiving a `BlockCommit` update works as expected
    #[test]
    fn block_commit() {
        let mut node = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], 0, &cfg);
        state0.phase = PbftPhase::Finished;
        state0.working_block = Some(PbftBlock::from(mock_block(1)));
        assert_eq!(state0.seq_num, 1);
        assert!(node.on_block_commit(mock_block_id(1), &mut state0).is_ok());
        assert_eq!(state0.phase, PbftPhase::PrePreparing);
        assert_eq!(state0.working_block, None);
        assert_eq!(state0.seq_num, 2);
    }

    /// Test the multicast protocol (`PrePrepare` => `Prepare` => `Commit`)
    #[test]
    fn multicast_protocol() {
        let cfg = mock_config(4);

        // Make sure BlockNew is in the log
        let mut node1 = mock_node(vec![1]);
        let mut state1 = PbftState::new(vec![], 0, &cfg);
        let block = mock_block(1);
        node1
            .on_block_new(block.clone(), &mut state1)
            .unwrap_or_else(panic_with_err);

        // Receive a PrePrepare
        let msg = mock_msg(PbftMessageType::PrePrepare, 0, 1, block.clone(), vec![0]);
        node1
            .on_peer_message(msg, &mut state1)
            .unwrap_or_else(panic_with_err);

        assert_eq!(state1.phase, PbftPhase::Preparing);
        assert_eq!(state1.seq_num, 1);
        if let Some(ref blk) = state1.working_block {
            assert_eq!(BlockId::from(blk.clone().block_id), mock_block_id(1));
        } else {
            panic!("Wrong WorkingBlockOption");
        }

        // Receive 3 `Prepare` messages
        for peer in 0..3 {
            assert_eq!(state1.phase, PbftPhase::Preparing);
            let msg = mock_msg(PbftMessageType::Prepare, 0, 1, block.clone(), vec![peer]);
            node1
                .on_peer_message(msg, &mut state1)
                .unwrap_or_else(panic_with_err);
        }

        // Receive 3 `Commit` messages
        for peer in 0..3 {
            assert_eq!(state1.phase, PbftPhase::Committing);
            let msg = mock_msg(PbftMessageType::Commit, 0, 1, block.clone(), vec![peer]);
            node1
                .on_peer_message(msg, &mut state1)
                .unwrap_or_else(panic_with_err);
        }
        assert_eq!(state1.phase, PbftPhase::Finished);

        // Spoof the `commit_blocks()` call
        assert!(node1.on_block_commit(mock_block_id(1), &mut state1).is_ok());
        assert_eq!(state1.phase, PbftPhase::PrePreparing);

        // Make sure the block was actually committed
        let mut f = File::open(BLOCK_FILE).unwrap();
        let mut buffer = String::new();
        f.read_to_string(&mut buffer).unwrap();
        let deser: Vec<Vec<u8>> = serde_json::from_str(&buffer).unwrap();
        let blocks: Vec<BlockId> = deser
            .iter()
            .filter(|&block| !block.is_empty())
            .map(|ref block| BlockId::from(block.clone().clone()))
            .collect();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1], mock_block_id(1));

        remove_file(BLOCK_FILE).unwrap();
    }

    /// Test that view changes work as expected, and that nodes take the proper roles after a view
    /// change
    #[test]
    fn view_change() {
        let mut node1 = mock_node(vec![1]);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(vec![1], 0, &cfg);

        assert!(!state1.is_primary());

        // Receive 3 `ViewChange` messages
        for peer in 0..3 {
            // It takes f + 1 `ViewChange` messages to trigger a view change, if it wasn't started
            // by `start_view_change()`
            if peer < 2 {
                assert_eq!(state1.mode, PbftMode::Normal);
            } else {
                assert_eq!(state1.mode, PbftMode::ViewChanging(1));
            }

            node1
                .on_peer_message(mock_view_change(1, 0, vec![peer], peer == 1), &mut state1)
                .unwrap_or_else(panic_with_err);
        }

        // Receive `NewView` message
        let msgs: Vec<&ParsedMessage> = node1
            .msg_log
            .get_messages_of_type_view(PbftMessageType::ViewChange, 1)
            .iter()
            .cloned()
            .filter(|msg| !msg.from_self)
            .collect::<Vec<_>>();
        let mut new_view = PbftNewView::new();
        new_view.set_info(PbftMessageInfo::new_from(
            PbftMessageType::NewView,
            1,
            0,
            vec![1],
        ));
        new_view.set_view_changes(PbftNode::signed_votes_from_messages(msgs.as_slice()));

        node1
            .on_peer_message(ParsedMessage::from_new_view_message(new_view), &mut state1)
            .unwrap_or_else(panic_with_err);

        assert!(state1.is_primary());
        assert_eq!(state1.view, 1);
    }

    /// Make sure that view changes start correctly
    #[test]
    fn start_view_change() {
        let mut node1 = mock_node(vec![1]);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(vec![], 0, &cfg);
        assert_eq!(state1.mode, PbftMode::Normal);

        let new_view = state1.view + 1;
        node1
            .start_view_change(&mut state1, new_view)
            .unwrap_or_else(panic_with_err);

        assert_eq!(state1.mode, PbftMode::ViewChanging(1));
    }

    /// Test that try_publish adds in the consensus seal
    #[test]
    fn try_publish() {
        let mut node0 = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], 0, &cfg);
        let block0 = mock_block(1);
        let pbft_block0 = PbftBlock::from(block0);

        for i in 0..3 {
            let mut info = PbftMessageInfo::new();
            info.set_msg_type("Commit".into());
            info.set_view(0);
            info.set_seq_num(0);
            info.set_signer_id(vec![i]);

            let mut msg = PbftMessage::new();
            msg.set_info(info);
            node0
                .msg_log
                .add_message(ParsedMessage::from_pbft_message(msg), &state0)
                .unwrap();
        }

        state0.phase = PbftPhase::PrePreparing;
        state0.working_block = Some(pbft_block0.clone());

        node0.try_publish(&mut state0).unwrap();
    }
}
