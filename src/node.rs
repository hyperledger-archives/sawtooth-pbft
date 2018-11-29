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
use std::error::Error;

use hex;
use protobuf::{Message, ProtobufError, RepeatedField};
use sawtooth_sdk::consensus::engine::{Block, BlockId, Error as EngineError, PeerId};
use sawtooth_sdk::consensus::service::Service;
use sawtooth_sdk::messages::consensus::ConsensusPeerMessageHeader;
use sawtooth_sdk::signing::{create_context, secp256k1::Secp256k1PublicKey};

use config::{get_peers_from_settings, PbftConfig};
use error::PbftError;
use handlers;
use hash::verify_sha512;
use message_log::{PbftLog, PbftStableCheckpoint};
use message_type::{ParsedMessage, PbftHint, PbftMessageType};
use protos::pbft_message::{
    PbftBlock, PbftMessage, PbftMessageInfo, PbftSeal, PbftSignedCommitVote, PbftViewChange,
};
use state::{PbftMode, PbftPhase, PbftState, WorkingBlockOption};

/// Contains all of the components for operating a PBFT node.
pub struct PbftNode {
    /// Used for interactions with the validator
    pub service: Box<Service>,

    /// Messages this node has received
    pub msg_log: PbftLog,
}

impl PbftNode {
    /// Construct a new PBFT node.
    /// After the node is created, if the node is primary, it initializes a new block on the chain.
    pub fn new(config: &PbftConfig, service: Box<Service>, is_primary: bool) -> Self {
        let mut n = PbftNode {
            service,
            msg_log: PbftLog::new(config),
        };

        // Primary initializes a block
        if is_primary {
            n.service
                .initialize_block(None)
                .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
        }
        n
    }

    // ---------- Methods for handling Updates from the validator ----------

    /// Handle a peer message from another PbftNode
    /// This method handles all messages from other nodes. Such messages may include `PrePrepare`,
    /// `Prepare`, `Commit`, `Checkpoint`, or `ViewChange`. If a node receives a type of message
    /// before it is ready to do so, the message is pushed into a backlog queue.
    #[allow(needless_pass_by_value)]
    pub fn on_peer_message(
        &mut self,
        msg: ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        info!("{}: Got peer message: {}", state, msg.info());

        let msg_type = PbftMessageType::from(msg.info().msg_type.as_str());

        // Handle a multicast protocol message
        let multicast_hint = if msg_type.is_multicast() {
            handlers::multicast_hint(state, &msg)
        } else {
            PbftHint::PresentMessage
        };

        match msg_type {
            PbftMessageType::PrePrepare => {
                if !ignore_hint_pre_prepare(state, &msg) {
                    self.msg_log
                        .add_message_with_hint(msg.clone(), &multicast_hint)?;
                }

                handlers::pre_prepare(state, &mut self.msg_log, &msg)?;

                // NOTE: Putting log add here is necessary because on_peer_message gets
                // called again inside of _broadcast_pbft_message
                self.msg_log.add_message(msg.clone());
                state.switch_phase(PbftPhase::Preparing);

                self.broadcast_pre_prepare(&msg, state)?;
            }

            PbftMessageType::Prepare => {
                self.msg_log
                    .add_message_with_hint(msg.clone(), &multicast_hint)?;

                self.msg_log.add_message(msg.clone());

                self.msg_log.check_prepared(&msg, state.f)?;

                self.check_blocks_if_not_checking(&msg, state)?;
            }

            PbftMessageType::Commit => {
                self.msg_log
                    .add_message_with_hint(msg.clone(), &multicast_hint)?;

                self.msg_log.add_message(msg.clone());

                self.msg_log.check_committable(&msg, state.f)?;

                self.commit_block_if_committing(&msg, state)?;
            }

            PbftMessageType::Checkpoint => {
                if self.check_if_stale_checkpoint(&msg, state)? {
                    return Ok(());
                }

                if !self.check_if_checkpoint_started(&msg, state) {
                    return Ok(());
                }

                // Add message to the log
                self.msg_log.add_message(msg.clone());

                if check_if_secondary(state) {
                    self.start_checkpointing_and_forward(&msg, state)?;
                }

                self.garbage_collect_if_stable_checkpoint(&msg, state)?;
            }

            PbftMessageType::ViewChange => {
                let vc_message = msg.get_view_change_message();
                let info = msg.info();
                debug!(
                    "{}: Received ViewChange message from Node {:?} (v {}, seq {})",
                    state,
                    PeerId::from(info.get_signer_id()),
                    info.get_view(),
                    info.get_seq_num(),
                );

                self.msg_log.add_view_change(vc_message.clone());

                if self.propose_view_change_if_enough_messages(&msg, state)? {
                    return Ok(());
                }

                handlers::view_change(state, &mut self.msg_log, &mut *self.service, &msg)?;
            }

            _ => warn!("Message type not implemented"),
        }
        Ok(())
    }

    fn broadcast_pre_prepare(
        &mut self,
        pbft_message: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        info!(
            "{}: PrePrepare, sequence number {}",
            state,
            pbft_message.info().get_seq_num()
        );

        self._broadcast_pbft_message(
            pbft_message.info().get_seq_num(),
            &PbftMessageType::Prepare,
            (*pbft_message.get_block()).clone(),
            state,
        )
    }

    fn check_blocks_if_not_checking(
        &mut self,
        pbft_message: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        if state.phase != PbftPhase::Checking {
            state.switch_phase(PbftPhase::Checking);
            debug!("{}: Checking blocks", state);
            self.service
                .check_blocks(vec![pbft_message.get_block().clone().block_id])
                .map_err(|_| PbftError::InternalError(String::from("Failed to check blocks")))?
        }
        Ok(())
    }

    #[allow(ptr_arg)]
    fn commit_block_if_committing(
        &mut self,
        msg: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        if state.phase == PbftPhase::Committing {
            handlers::commit(state, &mut self.msg_log, &mut *self.service, msg)
        } else {
            debug!(
                "{}: Already committed block {:?}",
                state,
                msg.get_block().block_id
            );
            Ok(())
        }
    }

    fn check_if_stale_checkpoint(
        &mut self,
        pbft_message: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<bool, PbftError> {
        debug!(
            "{}: Received Checkpoint message from {:?}",
            state,
            PeerId::from(pbft_message.info().get_signer_id())
        );

        if self.msg_log.get_latest_checkpoint() >= pbft_message.info().get_seq_num() {
            debug!(
                "{}: Already at a stable checkpoint with this sequence number or past it!",
                state
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[allow(ptr_arg)]
    fn check_if_checkpoint_started(&mut self, msg: &ParsedMessage, state: &mut PbftState) -> bool {
        // Not ready to receive checkpoint yet; only acceptable in NotStarted
        if state.phase != PbftPhase::NotStarted {
            self.msg_log.push_backlog(msg.clone());
            debug!("{}: Not in NotStarted; not handling checkpoint yet", state);
            false
        } else {
            true
        }
    }

    fn start_checkpointing_and_forward(
        &mut self,
        pbft_message: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        state.pre_checkpoint_mode = state.mode;
        state.mode = PbftMode::Checkpointing;
        self._broadcast_pbft_message(
            pbft_message.info().get_seq_num(),
            &PbftMessageType::Checkpoint,
            PbftBlock::new(),
            state,
        )
    }

    fn garbage_collect_if_stable_checkpoint(
        &mut self,
        pbft_message: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        if state.mode == PbftMode::Checkpointing {
            self.msg_log
                .check_msg_against_log(pbft_message, true, 2 * state.f + 1)?;
            warn!(
                "{}: Reached stable checkpoint (seq num {}); garbage collecting logs",
                state,
                pbft_message.info().get_seq_num()
            );
            self.msg_log.garbage_collect(
                pbft_message.info().get_seq_num(),
                pbft_message.info().get_view(),
            );

            state.mode = state.pre_checkpoint_mode;
        }
        Ok(())
    }

    fn propose_view_change_if_enough_messages(
        &mut self,
        message: &ParsedMessage,
        state: &mut PbftState,
    ) -> Result<bool, PbftError> {
        if state.mode != PbftMode::ViewChanging {
            // Even if our own timer hasn't expired, still do a ViewChange if we've received
            // f + 1 VC messages to prevent being late to the new view party
            if self
                .msg_log
                .check_msg_against_log(message, true, state.f + 1)
                .is_ok()
                && message.info().get_view() > state.view
            {
                warn!("{}: Starting ViewChange from a ViewChange message", state);
                self.propose_view_change(state)?;
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    /// Verifies an individual consensus vote
    ///
    /// Returns the signer ID of the wrapped PbftMessage, for use in further verification
    fn verify_consensus_vote(
        vote: &PbftSignedCommitVote,
        seal: &PbftSeal,
    ) -> Result<Vec<u8>, PbftError> {
        let message: PbftMessage = protobuf::parse_from_bytes(&vote.get_message_bytes())
            .map_err(PbftError::SerializationError)?;

        if message.get_block().block_id != seal.previous_id {
            return Err(PbftError::InternalError(format!(
                "PbftMessage block ID ({:?}) doesn't match seal's previous id ({:?})!",
                message.get_block().get_block_id(),
                seal.previous_id
            )));
        }

        let header: ConsensusPeerMessageHeader =
            protobuf::parse_from_bytes(&vote.get_header_bytes())
                .map_err(PbftError::SerializationError)?;

        let key = Secp256k1PublicKey::from_hex(&hex::encode(&header.signer_id)).unwrap();

        let context = create_context("secp256k1")
            .map_err(|err| PbftError::InternalError(format!("Couldn't create context: {}", err)))?;

        match context.verify(
            &hex::encode(vote.get_header_signature()),
            vote.get_header_bytes(),
            &key,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Err(PbftError::InternalError(
                    "Header failed verification!".into(),
                ))
            }
            Err(err) => {
                return Err(PbftError::InternalError(format!(
                    "Error while verifying header: {:?}",
                    err
                )))
            }
        }

        verify_sha512(vote.get_message_bytes(), header.get_content_sha512())?;

        Ok(message.get_info().get_signer_id().to_vec())
    }

    /// Verifies the consensus seal from the current block, for the previous block
    fn verify_consensus_seal(
        &mut self,
        block: &Block,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // We don't publish a consensus seal until block 1, so we don't verify it
        // until block 2
        if block.block_num < 2 {
            return Ok(());
        }

        if block.payload.is_empty() {
            return Err(PbftError::InternalError(
                "Got empty payload for non-genesis block!".into(),
            ));
        }

        let seal: PbftSeal =
            protobuf::parse_from_bytes(&block.payload).map_err(PbftError::SerializationError)?;

        if seal.previous_id != &block.previous_id[..] {
            return Err(PbftError::InternalError(format!(
                "Consensus seal failed verification. Seal's previous ID `{}` doesn't match block's previous ID `{}`",
                hex::encode(&seal.previous_id[..3]), hex::encode(&block.previous_id[..3])
            )));
        }

        if seal.summary != &block.summary[..] {
            return Err(PbftError::InternalError(format!(
                "Consensus seal failed verification. Seal's summary {:?} doesn't match block's summary {:?}",
                seal.summary, block.summary
            )));
        }

        // Verify each individual vote, and extract the signer ID from each PbftMessage that
        // it contains, so that we can do some sanity checks on those IDs.
        let voter_ids =
            seal.get_previous_commit_votes()
                .iter()
                .try_fold(HashSet::new(), |mut ids, v| {
                    Self::verify_consensus_vote(v, &seal).and_then(|vid| Ok(ids.insert(vid)))?;
                    Ok(ids)
                })?;

        // All of the votes must come from known peers, and the primary can't explicitly
        // vote itself, since publishing a block is an implicit vote. Check that the votes
        // we've received are a subset of "peers - primary". We need to use the list of
        // peers from the block we're verifying the seal for, since it may have changed.
        let settings = self
            .service
            .get_settings(
                block.previous_id.clone(),
                vec![String::from("sawtooth.consensus.pbft.peers")],
            ).expect("Failed to get settings");
        let peers = get_peers_from_settings(&settings);

        let peer_ids: HashSet<_> = peers
            .iter()
            .cloned()
            .filter_map(|pid| {
                if pid == block.signer_id {
                    None
                } else {
                    Some(pid)
                }
            }).collect();

        if !voter_ids.is_subset(&peer_ids) {
            return Err(PbftError::InternalError(format!(
                "Got unexpected vote IDs: {:?}",
                voter_ids.difference(&peer_ids).collect::<Vec<_>>()
            )));
        }

        // Check that we've received 2f votes, since the primary vote is implicit
        if voter_ids.len() < 2 * state.f as usize {
            return Err(PbftError::InternalError(format!(
                "Need {} votes, only found {}!",
                2 * state.f,
                voter_ids.len()
            )));
        }

        Ok(())
    }

    /// Attempts to catch this node up with its peers, if necessary
    ///
    /// Returns true if catching up was required, and false otherwise
    fn try_catchup(
        &mut self,
        state: &mut PbftState,
        block: &Block,
        msg: PbftMessage,
    ) -> Result<bool, PbftError> {
        // Don't catch up if we're the primary, since we're the ones who publish.
        // Also don't catch up from block 0 -> 1, since there's no consensus seal.
        if state.is_primary() || block.block_num < 2 {
            return Ok(false);
        }

        // If we've got a (Tentative)WorkingBlock, and the new block is immediately
        // subsequent to it, then we're able to catch up. Otherwise, return false
        // to signify that no catching up occurred.
        match state.working_block.clone() {
            WorkingBlockOption::WorkingBlock(wb) => {
                let block_num_matches = block.block_num == wb.get_block_num() + 1;
                let block_id_matches = block.previous_id == wb.get_block_id();

                if !block_num_matches || !block_id_matches {
                    debug!(
                        "Block didn't match for catchup, skipping: {} {}",
                        block_num_matches, block_id_matches
                    );
                    return Ok(false);
                } else {
                    debug!("Catching up from working block");
                }
            }
            WorkingBlockOption::TentativeWorkingBlock(bid) => {
                if block.previous_id == bid {
                    // If we've got a tentative working block, replace it with a regular working block
                    debug!("Catching up from tentative working block");
                    state.working_block = WorkingBlockOption::WorkingBlock(msg.get_block().clone());
                } else {
                    debug!(
                        "Skipping catchup from tentative working blockdue to ID mismatch: {:?} != {:?}",
                        block.block_id, bid
                    );
                    return Ok(false);
                }
            }
            WorkingBlockOption::NoWorkingBlock => {
                return Ok(false);
            }
        };

        info!("{}: Catching up to block #{}", state, block.block_num - 1);

        // Parse messages from seal, and add them to the backlog
        let seal: PbftSeal =
            protobuf::parse_from_bytes(&block.payload).map_err(PbftError::SerializationError)?;

        let messages =
            seal.get_previous_commit_votes()
                .iter()
                .try_fold(Vec::new(), |mut msgs, v| {
                    msgs.push(ParsedMessage::from_pbft_message(
                        protobuf::parse_from_bytes(&v.get_message_bytes())
                            .map_err(PbftError::SerializationError)?,
                    ));
                    Ok(msgs)
                })?;

        let view = messages[0].info().get_view();
        if state.view != view {
            info!("Updating view from {} to {}.", state.view, view);
            state.view = view;
        }

        for message in &messages {
            self.msg_log.add_message(message.clone());
        }

        // Commit the new block, using one of the parsed commit messages to simulate
        // having received a regular commit message.
        handlers::commit(state, &mut self.msg_log, &mut *self.service, &messages[0])?;

        // Start a view change if we need to force one for fairness
        if state.at_forced_view_change() {
            self.force_view_change(state);
        }

        self.msg_log
            .add_message(ParsedMessage::from_pbft_message(msg));
        state.working_block = WorkingBlockOption::TentativeWorkingBlock(block.block_id.clone());
        state.idle_timeout.stop();
        state.commit_timeout.start();

        Ok(true)
    }

    /// Creates a new working block on the working block queue and kicks off the consensus algorithm
    /// by broadcasting a `PrePrepare` message to peers. Starts a view change timer, just in case
    /// the primary decides not to commit this block. If a `BlockCommit` update doesn't happen in a
    /// timely fashion, then the primary can be considered faulty and a view change should happen.
    pub fn on_block_new(&mut self, block: Block, state: &mut PbftState) -> Result<(), PbftError> {
        if block.block_num == 0 {
            info!("Got genesis block as BlockNew; skipping");
            return Ok(());
        }

        info!(
            "{}: Got BlockNew: {} / {}",
            state,
            block.block_num,
            hex::encode(&block.block_id[..3]),
        );

        let pbft_block = pbft_block_from_block(block.clone());

        let mut msg = PbftMessage::new();
        if state.is_primary() {
            // Ensure that our local state doesn't get out of sync with actual state
            state.seq_num = head.block_num + 1;

            msg.set_info(handlers::make_msg_info(
                &PbftMessageType::BlockNew,
                state.view,
                state.seq_num, // primary knows the proper sequence number
                state.id.clone(),
            ));
        } else {
            // Ensure that our local state doesn't get out of sync with actual state
            state.seq_num = head.block_num;

            msg.set_info(handlers::make_msg_info(
                &PbftMessageType::BlockNew,
                state.view,
                0, // default to unset; change it later when we receive PrePrepare
                state.id.clone(),
            ));
        }

        msg.set_block(pbft_block.clone());

        match self.verify_consensus_seal(&block, state) {
            Ok(()) => {}
            Err(err) => {
                warn!(
                    "Failing block due to failed consensus seal verification and \
                     proposing view change! Error was {}",
                    err
                );
                self.service.fail_block(block.block_id).map_err(|err| {
                    PbftError::InternalError(format!("Couldn't fail block: {}", err))
                })?;
                self.propose_view_change(state)?;
                return Err(err);
            }
        }

        let head = self
            .service
            .get_chain_head()
            .map_err(|e| PbftError::InternalError(e.description().to_string()))?;

        if self.try_catchup(state, &block, msg.clone())? {
            return Ok(());
        }

        if block.block_num > head.block_num + 1
            || state.switch_phase(PbftPhase::PrePreparing).is_none()
        {
            debug!(
                "{}: Not ready for block {}, pushing to backlog",
                state,
                &hex::encode(block.block_id.clone())[..6]
            );
            self.msg_log.push_block_backlog(block.clone());
            return Ok(());
        }

        self.msg_log
            .add_message(ParsedMessage::from_pbft_message(msg));
        state.working_block = WorkingBlockOption::TentativeWorkingBlock(block.block_id);
        state.idle_timeout.stop();
        state.commit_timeout.start();

        if state.is_primary() {
            let s = state.seq_num;
            self._broadcast_pbft_message(s, &PbftMessageType::PrePrepare, pbft_block, state)?;
        }
        Ok(())
    }

    /// Handle a `BlockCommit` update from the Validator
    /// Since the block was successfully committed, the primary is not faulty and the view change
    /// timer can be stopped. If this node is a primary, then initialize a new block. Both node
    /// roles transition back to the `NotStarted` phase. If this node is at a checkpoint after the
    /// previously committed block (`checkpoint_period` blocks have been committed since the last
    /// checkpoint), then start a checkpoint.
    pub fn on_block_commit(
        &mut self,
        block_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        debug!("{}: <<<<<< BlockCommit: {:?}", state, block_id);

        if state.phase == PbftPhase::Finished {
            if state.is_primary() {
                info!(
                    "{}: Initializing block with previous ID {:?}",
                    state, block_id
                );
                self.service
                    .initialize_block(Some(block_id.clone()))
                    .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
            }

            state.switch_phase(PbftPhase::NotStarted);

            // Start a view change if we need to force one for fairness or if membership changed
            if state.at_forced_view_change() || self.update_membership(block_id, state) {
                self.force_view_change(state);
            }

            // Start a checkpoint in NotStarted, if we're at one
            if self.msg_log.at_checkpoint() {
                self.start_checkpoint(state)?;
            }
        } else {
            debug!("{}: Not doing anything with BlockCommit", state);
        }

        // The primary processessed this block in a timely manner, so stop the timeout.
        state.commit_timeout.stop();
        state.idle_timeout.start();

        Ok(())
    }

    /// Handle a `BlockValid` update
    /// This message arrives after `check_blocks` is called, signifying that the validator has
    /// successfully checked a block with this `BlockId`.
    /// Once a `BlockValid` is received, transition to committing blocks.
    pub fn on_block_valid(
        &mut self,
        block_id: BlockId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        debug!("{}: <<<<<< BlockValid: {:?}", state, block_id);
        state.switch_phase(PbftPhase::Committing);

        debug!("{}: Getting blocks", state);
        let valid_blocks: Vec<Block> = self
            .service
            .get_blocks(vec![block_id])
            .unwrap_or_default()
            .into_iter()
            .map(|(_block_id, block)| block)
            .collect();

        if valid_blocks.is_empty() {
            return Err(PbftError::WrongNumBlocks);
        }

        let s = state.seq_num; // By now, secondaries have the proper seq number
        self._broadcast_pbft_message(
            s,
            &PbftMessageType::Commit,
            handlers::pbft_block_from_block(valid_blocks[0].clone()),
            state,
        )?;
        Ok(())
    }

    // ---------- Methods for periodically checking on and updating the state, called by the engine ----------

    fn build_seal(
        &mut self,
        state: &PbftState,
        summary: Vec<u8>,
        head: Block,
    ) -> Result<Vec<u8>, PbftError> {
        info!("{}: Building seal with head at {}", state, head.block_num);

        let mut messages = self
            .msg_log
            .get_messages_of_type(&PbftMessageType::Commit, state.seq_num, state.view)
            .into_iter()
            .filter(|&m| !m.from_self)
            .collect::<Vec<_>>();

        // A forced view change will simply increment the view number, without sending
        // new messages. If we don't have enough messages for the current view, try
        // the previous view.
        if messages.is_empty() && state.view > 0 {
            info!(
                "Found 0 messages for seq num {} view {}, trying view {}",
                state.seq_num,
                state.view,
                state.view - 1
            );
            messages = self
                .msg_log
                .get_messages_of_type(&PbftMessageType::Commit, state.seq_num, state.view - 1)
                .into_iter()
                .filter(|&m| !m.from_self)
                .collect::<Vec<_>>();
        }

        let min_votes = 2 * state.f as usize;
        if messages.len() < min_votes {
            return Err(PbftError::InternalError(format!(
                "Need {} commit messages to publish block, only have {}!",
                min_votes,
                messages.len()
            )));
        }

        let mut seal = PbftSeal::new();

        seal.set_summary(summary);
        seal.set_previous_id(head.block_id);
        seal.set_previous_commit_votes(RepeatedField::from(
            messages
                .iter()
                .map(|m| {
                    let mut vote = PbftSignedCommitVote::new();

                    vote.set_header_bytes(m.header_bytes.clone());
                    vote.set_header_signature(m.header_signature.clone());
                    vote.set_message_bytes(m.message_bytes.clone());

                    vote
                }).collect::<Vec<_>>(),
        ));

        seal.write_to_bytes().map_err(PbftError::SerializationError)
    }

    /// The primary tries to finalize a block every so often
    /// # Panics
    /// Panics if `finalize_block` fails. This is necessary because it means the validator wasn't
    /// able to publish the new block.
    pub fn try_publish(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        // Only the primary takes care of this, and we try publishing a block
        // on every engine loop, even if it's not yet ready. This isn't an error,
        // so just return Ok(()).
        if !state.is_primary() || state.phase != PbftPhase::NotStarted {
            return Ok(());
        }

        info!("{}: Summarizing block", state);

        let summary = match self.service.summarize_block() {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!(
                    "{}: Couldn't summarize, so not finalizing: {}",
                    state,
                    e.description().to_string()
                );
                return Ok(());
            }
        };

        let head = self
            .service
            .get_chain_head()
            .map_err(|err| PbftError::InternalError(format!("Couldn't get chain head: {}", err)))?;

        // We don't publish a consensus seal until block 1, since we never receive any
        // votes on the genesis block. Leave payload blank for the first block.
        let data = if head.block_num < 1 {
            vec![]
        } else {
            self.build_seal(state, summary, head)?
        };

        match self.service.finalize_block(data) {
            Ok(block_id) => {
                info!("{}: Publishing block {:?}", state, block_id);
                Ok(())
            }
            Err(EngineError::BlockNotReady) => {
                debug!("{}: Block not ready", state);
                Ok(())
            }
            Err(err) => {
                error!("Couldn't finalize block: {}", err);
                Err(PbftError::InternalError("Couldn't finalize block!".into()))
            }
        }
    }

    /// Check to see if the view change timeout has expired
    pub fn check_commit_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.commit_timeout.check_expired()
    }

    /// Check to see if the idle timeout has expired
    pub fn check_idle_timeout_expired(&mut self, state: &mut PbftState) -> bool {
        state.idle_timeout.check_expired()
    }

    pub fn start_idle_timeout(&self, state: &mut PbftState) {
        state.idle_timeout.start();
    }

    /// Start the checkpoint process
    /// Primaries start the checkpoint to ensure sequence number correctness
    pub fn start_checkpoint(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        if !state.is_primary() {
            return Ok(());
        }
        if state.mode == PbftMode::Checkpointing {
            return Ok(());
        }

        state.pre_checkpoint_mode = state.mode;
        state.mode = PbftMode::Checkpointing;
        info!("{}: Starting checkpoint", state);
        let s = state.seq_num;
        self._broadcast_pbft_message(s, &PbftMessageType::Checkpoint, PbftBlock::new(), state)
    }

    /// Retry messages from the backlog queue
    pub fn retry_backlog(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        let mut peer_res = Ok(());
        if let Some(msg) = self.msg_log.pop_backlog() {
            debug!("{}: Popping message from backlog", state);
            peer_res = self.on_peer_message(msg, state);
        }
        if state.mode == PbftMode::Normal && state.phase == PbftPhase::NotStarted {
            if let Some(msg) = self.msg_log.pop_block_backlog() {
                debug!("{}: Popping BlockNew from backlog", state);
                self.on_block_new(msg, state)?;
            }
        }
        peer_res
    }

    pub fn force_view_change(&mut self, state: &mut PbftState) {
        info!("{}: Forcing view change", state);
        handlers::force_view_change(state, &mut *self.service)
    }

    /// Initiate a view change (this node suspects that the primary is faulty)
    /// Nodes drop everything when they're doing a view change - will not process any peer messages
    /// other than `ViewChanges` until the view change is complete.
    pub fn propose_view_change(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        if state.mode == PbftMode::ViewChanging {
            return Ok(());
        }
        warn!("{}: Starting view change", state);
        state.mode = PbftMode::ViewChanging;

        let PbftStableCheckpoint {
            seq_num: stable_seq_num,
            checkpoint_messages,
        } = if let Some(ref cp) = self.msg_log.latest_stable_checkpoint {
            debug!("{}: No stable checkpoint", state);
            cp.clone()
        } else {
            PbftStableCheckpoint {
                seq_num: 0,
                checkpoint_messages: vec![],
            }
        };

        let info = handlers::make_msg_info(
            &PbftMessageType::ViewChange,
            state.view + 1,
            stable_seq_num,
            state.id.clone(),
        );

        let mut vc_msg = PbftViewChange::new();
        vc_msg.set_info(info);
        vc_msg.set_checkpoint_messages(RepeatedField::from_vec(checkpoint_messages.to_vec()));
        let msg_bytes = vc_msg
            .write_to_bytes()
            .map_err(PbftError::SerializationError)?;

        self._broadcast_message(&PbftMessageType::ViewChange, msg_bytes, state)
    }

    /// Check the on-chain list of peers; if it has changed, update peers list and return true.
    fn update_membership(&mut self, block_id: BlockId, state: &mut PbftState) -> bool {
        // Get list of peers from settings
        let settings = self
            .service
            .get_settings(
                block_id,
                vec![String::from("sawtooth.consensus.pbft.peers")],
            ).expect("Failed to get settings");
        let peers = get_peers_from_settings(&settings);
        let new_peers_set: HashSet<PeerId> = peers.iter().cloned().collect();

        // Check if membership has changed
        let old_peers_set: HashSet<PeerId> = state.peer_ids.iter().cloned().collect();

        if new_peers_set != old_peers_set {
            state.peer_ids = peers;
            let f = ((state.peer_ids.len() - 1) / 3) as u64;
            if f == 0 {
                panic!("This network no longer contains enough nodes to be fault tolerant");
            }
            state.f = f;
            return true;
        }

        false
    }

    // ---------- Methods for communication between nodes ----------

    // Broadcast a message to this node's peers, and itself
    fn _broadcast_pbft_message(
        &mut self,
        seq_num: u64,
        msg_type: &PbftMessageType,
        block: PbftBlock,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        let expected_type = state.check_msg_type();
        // Make sure that we should be sending messages of this type
        if msg_type.is_multicast() && msg_type != &expected_type {
            return Ok(());
        }

        let msg_bytes = make_msg_bytes(
            handlers::make_msg_info(&msg_type, state.view, seq_num, state.id.clone()),
            block,
        ).unwrap_or_default();

        self._broadcast_message(&msg_type, msg_bytes, state)
    }

    #[cfg(not(test))]
    fn _broadcast_message(
        &mut self,
        msg_type: &PbftMessageType,
        msg: Vec<u8>,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Broadcast to peers
        debug!("{}: Broadcasting {:?}", state, msg_type);
        self.service
            .broadcast(String::from(msg_type).as_str(), msg.clone())
            .unwrap_or_else(|err| error!("Couldn't broadcast: {}", err));

        // Send to self
        let parsed_message = ParsedMessage::from_bytes(msg)?;

        self.on_peer_message(parsed_message, state)
    }

    /// NOTE: Disabling self-sending for testing purposes
    #[cfg(test)]
    fn _broadcast_message(
        &mut self,
        _msg_type: &PbftMessageType,
        _msg: Vec<u8>,
        _state: &mut PbftState,
    ) -> Result<(), PbftError> {
        return Ok(());
    }
}

fn check_if_secondary(state: &PbftState) -> bool {
    !state.is_primary() && state.mode != PbftMode::Checkpointing
}

fn ignore_hint_pre_prepare(state: &PbftState, pbft_message: &ParsedMessage) -> bool {
    if let WorkingBlockOption::TentativeWorkingBlock(ref block_id) = state.working_block {
        if block_id == &pbft_message.get_block().get_block_id()
            && pbft_message.info().get_seq_num() == state.seq_num + 1
        {
            debug!("{}: Ignoring not ready and starting multicast", state);
            true
        } else {
            debug!(
                "{}: Not starting multicast; ({} != {} or {} != {} + 1)",
                state,
                &hex::encode(block_id.clone())[..6],
                &hex::encode(pbft_message.get_block().get_block_id())[..6],
                pbft_message.info().get_seq_num(),
                state.seq_num,
            );
            false
        }
    } else {
        false
    }
}

/// Create a Protobuf binary representation of a PbftMessage from its info and corresponding Block
fn make_msg_bytes(info: PbftMessageInfo, block: PbftBlock) -> Result<Vec<u8>, ProtobufError> {
    let mut msg = PbftMessage::new();
    msg.set_info(info);
    msg.set_block(block);
    msg.write_to_bytes()
}

// Make a PbftBlock out of a consensus Block (PBFT doesn't need to use all the information about
// the block - this keeps blocks lighter weight)
fn pbft_block_from_block(block: Block) -> PbftBlock {
    let mut pbft_block = PbftBlock::new();
    pbft_block.set_block_id(block.block_id);
    pbft_block.set_signer_id(block.signer_id);
    pbft_block.set_block_num(block.block_num);
    pbft_block.set_summary(block.summary);
    pbft_block
}

/// NOTE: Testing the PbftNode is a bit strange. Due to missing functionality in the Service,
/// a node calling `broadcast()` doesn't include sending a message to itself. In order to get around
/// this, `on_peer_message()` is called, which sometimes causes unintended side effects when
/// testing. Self-sending has been disabled (see `broadcast()` method) for testing purposes.
#[cfg(test)]
mod tests {
    use super::*;
    use config::mock_config;
    use handlers::make_msg_info;
    use hash::{hash_sha256, hash_sha512};
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

            node.msg_log.add_message(message);
        }

        // Do some special jiu-jitsu to generate the seal for the node from itself. Basically,
        // do a bit of time travel into the future and then reset state.
        let actual_seq_num = state.seq_num;
        state.seq_num = num - 1;
        block.payload = node.build_seal(state, vec![1, 2, 3], head).unwrap();
        state.seq_num = actual_seq_num;

        block
    }

    /// Create a mock serialized PbftMessage
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

    fn handle_pbft_err(e: PbftError) {
        match e {
            PbftError::Timeout => (),
            PbftError::WrongNumMessages(_, _, _) | PbftError::NotReadyForMessage => {
                println!("{}", e)
            }
            _ => panic!("{}", e),
        }
    }

    /// Make sure that receiving a `BlockNew` update works as expected for block #1
    #[test]
    fn block_new_initial() {
        // NOTE: Special case for primary node
        let mut node0 = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], &cfg);
        node0.on_block_new(mock_block(1), &mut state0).unwrap();
        assert_eq!(state0.phase, PbftPhase::PrePreparing);
        assert_eq!(state0.seq_num, 1);
        assert_eq!(
            state0.working_block,
            WorkingBlockOption::TentativeWorkingBlock(mock_block_id(1))
        );

        // Try the next block
        let mut node1 = mock_node(vec![1]);
        let mut state1 = PbftState::new(vec![], &cfg);
        node1
            .on_block_new(mock_block(1), &mut state1)
            .unwrap_or_else(handle_pbft_err);
        assert_eq!(state1.phase, PbftPhase::PrePreparing);
        assert_eq!(
            state1.working_block,
            WorkingBlockOption::TentativeWorkingBlock(mock_block_id(1))
        );
        assert_eq!(state1.seq_num, 0);
    }

    #[test]
    fn block_new_first_10_blocks() {
        let mut node = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state = PbftState::new(vec![0], &cfg);

        let block_0_id = mock_block_id(0);
        let block_1_id = mock_block_id(1);

        // Assert starting state
        let head = node.service.get_chain_head().unwrap();
        assert_eq!(head.block_num, 0);
        assert_eq!(head.block_id, block_0_id);
        assert_eq!(head.previous_id, block_0_id);

        assert_eq!(state.id, vec![0]);
        assert_eq!(state.seq_num, 0);
        assert_eq!(state.view, 0);
        assert_eq!(state.phase, PbftPhase::NotStarted);
        assert_eq!(state.mode, PbftMode::Normal);
        assert_eq!(state.pre_checkpoint_mode, PbftMode::Normal);
        assert_eq!(state.peer_ids, (0..4).map(|i| vec![i]).collect::<Vec<_>>());
        assert_eq!(state.f, 1);
        assert_eq!(state.forced_view_change_period, 30);
        assert_eq!(state.working_block, WorkingBlockOption::NoWorkingBlock);
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
        assert_eq!(state.pre_checkpoint_mode, PbftMode::Normal);
        assert_eq!(state.peer_ids, (0..4).map(|i| vec![i]).collect::<Vec<_>>());
        assert_eq!(state.f, 1);
        assert_eq!(state.forced_view_change_period, 30);
        assert_eq!(
            state.working_block,
            WorkingBlockOption::TentativeWorkingBlock(block_1_id)
        );
        assert!(state.is_primary());

        // Handle the rest of the blocks
        for i in 2..10 {
            let block_ids = (i - 2..i + 1).map(mock_block_id).collect::<Vec<_>>();
            let block = mock_block_with_seal(i, &mut node, &mut state);
            node.on_block_new(block, &mut state).unwrap();

            let head = node.service.get_chain_head().unwrap();
            assert_eq!(head.block_num, i - 1);
            assert_eq!(head.block_id, block_ids[1]);
            assert_eq!(head.previous_id, block_ids[0]);

            assert_eq!(state.id, vec![0]);
            assert_eq!(state.seq_num, i - 1);
            assert_eq!(state.view, 0);
            assert_eq!(state.phase, PbftPhase::PrePreparing);
            assert_eq!(state.mode, PbftMode::Normal);
            assert_eq!(state.pre_checkpoint_mode, PbftMode::Normal);
            assert_eq!(state.peer_ids, (0..4).map(|i| vec![i]).collect::<Vec<_>>());
            assert_eq!(state.f, 1);
            assert_eq!(state.forced_view_change_period, 30);
            assert_eq!(
                state.working_block,
                WorkingBlockOption::TentativeWorkingBlock(block_ids[2].clone())
            );
            assert!(state.is_primary());
        }
    }

    /// Make sure that `BlockNew` properly checks the consensus seal.
    #[test]
    fn block_new_consensus() {
        let cfg = mock_config(4);
        let mut node = mock_node(vec![1]);
        let mut state = PbftState::new(vec![], &cfg);
        state.seq_num = 6;
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

            node.msg_log.add_message(message);
        }

        let seal = node.build_seal(&state, vec![1, 2, 3], head).unwrap();
        block.payload = seal;

        node.on_block_new(block, &mut state).unwrap();

        assert_eq!(state.phase, PbftPhase::NotStarted);
        assert_eq!(state.working_block, WorkingBlockOption::NoWorkingBlock);
    }

    /// Make sure that receiving a `BlockValid` update works as expected
    #[test]
    fn block_valid() {
        let mut node = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], &cfg);
        state0.phase = PbftPhase::Checking;
        node.on_block_valid(mock_block_id(1), &mut state0)
            .unwrap_or_else(handle_pbft_err);
        assert_eq!(state0.phase, PbftPhase::Committing);
    }

    /// Make sure that receiving a `BlockCommit` update works as expected
    #[test]
    fn block_commit() {
        let mut node = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], &cfg);
        state0.phase = PbftPhase::Finished;
        node.on_block_commit(mock_block_id(1), &mut state0)
            .unwrap_or_else(handle_pbft_err);
        assert_eq!(state0.phase, PbftPhase::NotStarted);
    }

    /// Test the multicast protocol (`PrePrepare` => `Prepare` => `Commit`)
    #[test]
    fn multicast_protocol() {
        let cfg = mock_config(4);

        // Make sure BlockNew is in the log
        let mut node1 = mock_node(vec![1]);
        let mut state1 = PbftState::new(vec![], &cfg);
        let block = mock_block(1);
        node1
            .on_block_new(block.clone(), &mut state1)
            .unwrap_or_else(handle_pbft_err);

        // Receive a PrePrepare
        let msg = mock_msg(&PbftMessageType::PrePrepare, 0, 1, block.clone(), vec![0]);
        node1
            .on_peer_message(msg, &mut state1)
            .unwrap_or_else(handle_pbft_err);

        assert_eq!(state1.phase, PbftPhase::Preparing);
        assert_eq!(state1.seq_num, 1);
        if let WorkingBlockOption::WorkingBlock(ref blk) = state1.working_block {
            assert_eq!(BlockId::from(blk.clone().block_id), mock_block_id(1));
        } else {
            panic!("Wrong WorkingBlockOption");
        }

        // Receive 3 `Prepare` messages
        for peer in 0..3 {
            assert_eq!(state1.phase, PbftPhase::Preparing);
            let msg = mock_msg(&PbftMessageType::Prepare, 0, 1, block.clone(), vec![peer]);
            node1
                .on_peer_message(msg, &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }
        assert_eq!(state1.phase, PbftPhase::Checking);

        // Spoof the `check_blocks()` call
        assert!(node1.on_block_valid(mock_block_id(1), &mut state1).is_ok());

        // Receive 3 `Commit` messages
        for peer in 0..3 {
            assert_eq!(state1.phase, PbftPhase::Committing);
            let msg = mock_msg(&PbftMessageType::Commit, 0, 1, block.clone(), vec![peer]);
            node1
                .on_peer_message(msg, &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }
        assert_eq!(state1.phase, PbftPhase::Finished);

        // Spoof the `commit_blocks()` call
        assert!(node1.on_block_commit(mock_block_id(1), &mut state1).is_ok());
        assert_eq!(state1.phase, PbftPhase::NotStarted);

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

    /// Make sure that checkpointing works as expected:
    /// + Node enters Normal mode again after checkpoint
    /// + A stable checkpoint is created
    #[test]
    fn checkpoint() {
        let mut node1 = mock_node(vec![1]);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(vec![], &cfg);
        // Pretend that the node just finished block 10
        state1.seq_num = 10;
        let block = mock_block(10);
        assert_eq!(state1.mode, PbftMode::Normal);
        assert!(node1.msg_log.latest_stable_checkpoint.is_none());

        // Receive 3 `Checkpoint` messages
        for peer in 0..3 {
            let msg = mock_msg(
                &PbftMessageType::Checkpoint,
                0,
                10,
                block.clone(),
                vec![peer],
            );
            node1
                .on_peer_message(msg, &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }

        assert_eq!(state1.mode, PbftMode::Normal);
        assert!(node1.msg_log.latest_stable_checkpoint.is_some());
    }

    /// Test that view changes work as expected, and that nodes take the proper roles after a view
    /// change
    #[test]
    fn view_change() {
        let mut node1 = mock_node(vec![1]);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(vec![1], &cfg);

        assert!(!state1.is_primary());

        // Receive 3 `ViewChange` messages
        for peer in 0..3 {
            // It takes f + 1 `ViewChange` messages to trigger a view change, if it wasn't started
            // by `propose_view_change()`
            if peer < 2 {
                assert_eq!(state1.mode, PbftMode::Normal);
            } else {
                assert_eq!(state1.mode, PbftMode::ViewChanging);
            }
            let info = make_msg_info(&PbftMessageType::ViewChange, 1, 1, vec![peer]);
            let mut vc_msg = PbftViewChange::new();
            vc_msg.set_info(info);
            vc_msg.set_checkpoint_messages(RepeatedField::default());

            node1
                .on_peer_message(ParsedMessage::from_view_change_message(vc_msg), &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }

        assert!(state1.is_primary());
        assert_eq!(state1.view, 1);
    }

    /// Make sure that view changes start correctly
    #[test]
    fn propose_view_change() {
        let mut node1 = mock_node(vec![1]);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(vec![], &cfg);
        assert_eq!(state1.mode, PbftMode::Normal);

        node1
            .propose_view_change(&mut state1)
            .unwrap_or_else(handle_pbft_err);

        assert_eq!(state1.mode, PbftMode::ViewChanging);
    }

    /// Test that try_publish adds in the consensus seal
    #[test]
    fn try_publish() {
        let mut node0 = mock_node(vec![0]);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(vec![0], &cfg);
        let block0 = mock_block(1);
        let pbft_block0 = pbft_block_from_block(block0);

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
                .add_message(ParsedMessage::from_pbft_message(msg));
        }

        state0.phase = PbftPhase::NotStarted;
        state0.working_block = WorkingBlockOption::WorkingBlock(pbft_block0.clone());

        node0.try_publish(&mut state0).unwrap();
    }
}
