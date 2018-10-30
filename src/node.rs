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

use hex;

use protobuf;
use protobuf::RepeatedField;
use protobuf::{Message, ProtobufError};

use std::convert::From;
use std::error::Error;

use sawtooth_sdk::consensus::engine::{Block, BlockId, Error as EngineError, PeerId};
use sawtooth_sdk::consensus::service::Service;

use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

use config::PbftConfig;
use error::PbftError;
use handlers;
use message_extensions::PbftGetInfo;
use message_log::{PbftLog, PbftStableCheckpoint};
use message_type::{PbftHint, PbftMessageType};
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
    #[allow(ptr_arg)]
    pub fn on_peer_message(
        &mut self,
        msg: &[u8],
        sender_id: &PeerId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Attempt to first parse the message as a `PbftMessage`, and if that fails, try
        // to parse as a `PbftViewChange` message.
        let msg_type = match protobuf::parse_from_bytes::<PbftMessage>(msg) {
            Ok(m) => PbftMessageType::from(m.get_info().msg_type.as_str()),
            Err(_) => match protobuf::parse_from_bytes::<PbftViewChange>(msg) {
                Ok(m) => PbftMessageType::from(m.get_info().msg_type.as_str()),
                Err(_) => {
                    return Err(PbftError::InternalError(
                        "Couldn't determine message type!".into(),
                    ))
                }
            },
        };

        // Handle a multicast protocol message
        let multicast_hint = extract_multicast_hint(state, &msg_type, msg)?;

        match msg_type {
            PbftMessageType::PrePrepare => {
                let pbft_message: PbftMessage = extract_message(&msg)?;

                if !verify_message_sender(&&pbft_message, sender_id) {
                    warn!(
                        "Ignoring message {:?}. Signer ID does not match sender ID {:?}",
                        pbft_message, sender_id
                    );
                    return Ok(());
                }

                if !ignore_hint_pre_prepare(state, &pbft_message) {
                    handlers::action_from_hint(
                        &mut self.msg_log,
                        &multicast_hint,
                        &pbft_message,
                        msg.to_vec(),
                        sender_id,
                    )?;
                }

                handlers::pre_prepare(state, &mut self.msg_log, &pbft_message)?;

                // NOTE: Putting log add here is necessary because on_peer_message gets
                // called again inside of _broadcast_pbft_message
                self.msg_log.add_message(pbft_message.clone());
                state.switch_phase(PbftPhase::Preparing);

                self.broadcast_pre_prepare(&pbft_message, state)?;
            }

            PbftMessageType::Prepare => {
                let pbft_message: PbftMessage = extract_message(&msg)?;

                if !verify_message_sender(&&pbft_message, sender_id) {
                    warn!(
                        "Ignoring message {:?}. Signer ID does not match sender ID {:?}",
                        pbft_message, sender_id
                    );
                    return Ok(());
                }

                handlers::action_from_hint(
                    &mut self.msg_log,
                    &multicast_hint,
                    &pbft_message,
                    msg.to_vec(),
                    sender_id,
                )?;

                self.msg_log.add_message(pbft_message.clone());

                self.msg_log.prepared(&pbft_message, state.f)?;

                self.check_blocks_if_not_checking(&pbft_message, state)?;
            }

            PbftMessageType::Commit => {
                let pbft_message: PbftMessage = extract_message(&msg)?;

                if !verify_message_sender(&&pbft_message, sender_id) {
                    warn!(
                        "Ignoring message {:?}. Signer ID does not match sender ID {:?}",
                        pbft_message, sender_id
                    );
                    return Ok(());
                }

                handlers::action_from_hint(
                    &mut self.msg_log,
                    &multicast_hint,
                    &pbft_message,
                    msg.to_vec(),
                    sender_id,
                )?;

                self.msg_log.add_message(pbft_message.clone());

                self.msg_log.check_committable(&pbft_message, state.f)?;

                self.commit_block_if_committing(msg, &pbft_message, &sender_id, state)?;
            }

            PbftMessageType::Checkpoint => {
                let pbft_message: PbftMessage = extract_message(&msg)?;

                if !verify_message_sender(&&pbft_message, sender_id) {
                    warn!(
                        "Ignoring message {:?}. Signer ID does not match sender ID {:?}",
                        pbft_message, sender_id
                    );
                    return Ok(());
                }

                if self.check_if_stale_checkpoint(&pbft_message, state)? {
                    return Ok(());
                }

                if !self.check_if_checkpoint_started(msg, sender_id, state) {
                    return Ok(());
                }

                // Add message to the log
                self.msg_log.add_message(pbft_message.clone());

                if check_if_secondary(state) {
                    self.start_checkpointing_and_forward(&pbft_message, state)?;
                }

                self.garbage_collect_if_stable_checkpoint(&pbft_message, state)?;
            }

            PbftMessageType::ViewChange => {
                let vc_message: PbftViewChange = extract_message(&msg)?;

                if !verify_message_sender(&&vc_message, sender_id) {
                    warn!(
                        "Ignoring message {:?}. Signer ID does not match sender ID {:?}",
                        vc_message, sender_id
                    );
                    return Ok(());
                }

                debug!(
                    "{}: Received ViewChange message from Node {:02} (v {}, seq {})",
                    state,
                    state.get_node_id_from_bytes(vc_message.get_info().get_signer_id())?,
                    vc_message.get_info().get_view(),
                    vc_message.get_info().get_seq_num(),
                );

                self.msg_log.add_view_change(vc_message.clone());

                if self.propose_view_change_if_enough_messages(&vc_message, state)? {
                    return Ok(());
                }

                handlers::view_change(state, &mut self.msg_log, &mut *self.service, &vc_message)?;
            }

            _ => warn!("Message type not implemented"),
        }
        Ok(())
    }

    fn broadcast_pre_prepare(
        &mut self,
        pbft_message: &PbftMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        info!(
            "{}: PrePrepare, sequence number {}",
            state,
            pbft_message.get_info().get_seq_num()
        );

        self._broadcast_pbft_message(
            pbft_message.get_info().get_seq_num(),
            &PbftMessageType::Prepare,
            (*pbft_message.get_block()).clone(),
            state,
        )
    }

    fn check_blocks_if_not_checking(
        &mut self,
        pbft_message: &PbftMessage,
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
        msg: &[u8],
        pbft_message: &PbftMessage,
        sender_id: &PeerId,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        if state.phase == PbftPhase::Committing {
            handlers::commit(
                state,
                &mut self.msg_log,
                &mut *self.service,
                &pbft_message,
                msg.to_vec(),
                sender_id,
            )
        } else {
            debug!(
                "{}: Already committed block {:?}",
                state,
                pbft_message.get_block().block_id
            );
            Ok(())
        }
    }

    fn check_if_stale_checkpoint(
        &mut self,
        pbft_message: &PbftMessage,
        state: &mut PbftState,
    ) -> Result<bool, PbftError> {
        debug!(
            "{}: Received Checkpoint message from {:02}",
            state,
            state.get_node_id_from_bytes(pbft_message.get_info().get_signer_id())?
        );

        if self.msg_log.get_latest_checkpoint() >= pbft_message.get_info().get_seq_num() {
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
    fn check_if_checkpoint_started(
        &mut self,
        msg: &[u8],
        sender_id: &PeerId,
        state: &mut PbftState,
    ) -> bool {
        // Not ready to receive checkpoint yet; only acceptable in NotStarted
        if state.phase != PbftPhase::NotStarted {
            self.msg_log.push_backlog(msg.to_vec(), sender_id.clone());
            debug!("{}: Not in NotStarted; not handling checkpoint yet", state);
            false
        } else {
            true
        }
    }

    fn start_checkpointing_and_forward(
        &mut self,
        pbft_message: &PbftMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        state.pre_checkpoint_mode = state.mode;
        state.mode = PbftMode::Checkpointing;
        self._broadcast_pbft_message(
            pbft_message.get_info().get_seq_num(),
            &PbftMessageType::Checkpoint,
            PbftBlock::new(),
            state,
        )
    }

    fn garbage_collect_if_stable_checkpoint(
        &mut self,
        pbft_message: &PbftMessage,
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        if state.mode == PbftMode::Checkpointing {
            self.msg_log
                .check_msg_against_log(&pbft_message, true, 2 * state.f + 1)?;
            warn!(
                "{}: Reached stable checkpoint (seq num {}); garbage collecting logs",
                state,
                pbft_message.get_info().get_seq_num()
            );
            self.msg_log.garbage_collect(
                pbft_message.get_info().get_seq_num(),
                pbft_message.get_info().get_view(),
            );

            state.mode = state.pre_checkpoint_mode;
        }
        Ok(())
    }

    fn propose_view_change_if_enough_messages(
        &mut self,
        vc_message: &PbftViewChange,
        state: &mut PbftState,
    ) -> Result<bool, PbftError> {
        if state.mode != PbftMode::ViewChanging {
            // Even if our own timer hasn't expired, still do a ViewChange if we've received
            // f + 1 VC messages to prevent being late to the new view party
            if self
                .msg_log
                .check_msg_against_log(&vc_message, true, state.f + 1)
                .is_ok()
                && vc_message.get_info().get_view() > state.view
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

    /// Creates a new working block on the working block queue and kicks off the consensus algorithm
    /// by broadcasting a `PrePrepare` message to peers. Starts a view change timer, just in case
    /// the primary decides not to commit this block. If a `BlockCommit` update doesn't happen in a
    /// timely fashion, then the primary can be considered faulty and a view change should happen.
    pub fn on_block_new(&mut self, block: Block, state: &mut PbftState) -> Result<(), PbftError> {
        info!("{}: Got BlockNew: {:?}", state, block.block_id);

        let pbft_block = pbft_block_from_block(block.clone());

        let mut msg = PbftMessage::new();
        if state.is_primary() {
            state.seq_num += 1;
            msg.set_info(handlers::make_msg_info(
                &PbftMessageType::BlockNew,
                state.view,
                state.seq_num, // primary knows the proper sequence number
                state.get_own_peer_id(),
            ));
        } else {
            msg.set_info(handlers::make_msg_info(
                &PbftMessageType::BlockNew,
                state.view,
                0, // default to unset; change it later when we receive PrePrepare
                state.get_own_peer_id(),
            ));
        }

        msg.set_block(pbft_block.clone());

        let head = self
            .service
            .get_chain_head()
            .map_err(|e| PbftError::InternalError(e.description().to_string()))?;

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

        self.msg_log.add_message(msg);
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
                    .initialize_block(Some(block_id))
                    .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
            }

            state.switch_phase(PbftPhase::NotStarted);

            // Start a view change if we need to force one for fairness
            if state.at_forced_view_change() {
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

    /// The primary tries to finalize a block every so often
    /// # Panics
    /// Panics if `finalize_block` fails. This is necessary because it means the validator wasn't
    /// able to publish the new block.
    pub fn try_publish(&mut self, state: &mut PbftState) -> Result<(), PbftError> {
        // Try to finalize a block
        if state.is_primary() && state.phase == PbftPhase::NotStarted {
            debug!("{}: Summarizing block", state);
            if let Err(e) = self.service.summarize_block() {
                debug!(
                    "{}: Couldn't summarize, so not finalizing: {}",
                    state,
                    e.description().to_string()
                );
            } else {
                debug!("{}: Trying to finalize block", state);
                match self.service.finalize_block(vec![]) {
                    Ok(block_id) => {
                        info!("{}: Publishing block {:?}", state, block_id);
                    }
                    Err(EngineError::BlockNotReady) => {
                        debug!("{}: Block not ready", state);
                    }
                    Err(err) => panic!("Failed to finalize block: {:?}", err),
                }
            }
        }
        Ok(())
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
        if let Some((msg, sender_id)) = self.msg_log.pop_backlog() {
            debug!(
                "{}: Popping message from {:?} from backlog",
                state, sender_id
            );
            peer_res = self.on_peer_message(&msg, &sender_id, state);
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
            state.get_own_peer_id(),
        );

        let mut vc_msg = PbftViewChange::new();
        vc_msg.set_info(info);
        vc_msg.set_checkpoint_messages(RepeatedField::from_vec(checkpoint_messages.to_vec()));

        let msg_bytes = vc_msg
            .write_to_bytes()
            .map_err(PbftError::SerializationError)?;

        self._broadcast_message(&PbftMessageType::ViewChange, &msg_bytes, state)
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
            handlers::make_msg_info(&msg_type, state.view, seq_num, state.get_own_peer_id()),
            block,
        ).unwrap_or_default();

        self._broadcast_message(&msg_type, &msg_bytes, state)
    }

    #[cfg(not(test))]
    fn _broadcast_message(
        &mut self,
        msg_type: &PbftMessageType,
        msg_bytes: &[u8],
        state: &mut PbftState,
    ) -> Result<(), PbftError> {
        // Broadcast to peers
        debug!("{}: Broadcasting {:?}", state, msg_type);
        self.service
            .broadcast(String::from(msg_type).as_str(), msg_bytes.to_vec())
            .unwrap_or_else(|err| error!("Couldn't broadcast: {}", err));

        // Send to self
        let own_peer_id = state.get_own_peer_id();
        self.on_peer_message(&msg_bytes, &own_peer_id, state)
    }

    /// NOTE: Disabling self-sending for testing purposes
    #[cfg(test)]
    fn _broadcast_message(
        &mut self,
        _msg_type: &PbftMessageType,
        _msg_bytes: &[u8],
        _state: &mut PbftState,
    ) -> Result<(), PbftError> {
        return Ok(());
    }
}

fn check_if_secondary(state: &PbftState) -> bool {
    !state.is_primary() && state.mode != PbftMode::Checkpointing
}

fn ignore_hint_pre_prepare(state: &PbftState, pbft_message: &PbftMessage) -> bool {
    if let WorkingBlockOption::TentativeWorkingBlock(ref block_id) = state.working_block {
        if block_id == &pbft_message.get_block().get_block_id()
            && pbft_message.get_info().get_seq_num() == state.seq_num + 1
        {
            debug!("{}: Ignoring not ready and starting multicast", state);
            true
        } else {
            debug!(
                "{}: Not starting multicast; ({} != {} or {} != {} + 1)",
                state,
                &hex::encode(block_id.clone())[..6],
                &hex::encode(pbft_message.get_block().get_block_id())[..6],
                pbft_message.get_info().get_seq_num(),
                state.seq_num,
            );
            false
        }
    } else {
        false
    }
}

fn extract_multicast_hint(
    state: &PbftState,
    msg_type: &PbftMessageType,
    msg: &[u8],
) -> Result<PbftHint, PbftError> {
    if msg_type.is_multicast() {
        let pbft_message: PbftMessage = extract_message(msg)?;

        debug!(
            "{}: <<<<<< {} [Node {:02}] (v {}, seq {}, b {})",
            state,
            msg_type,
            state.get_node_id_from_bytes(pbft_message.get_info().get_signer_id())?,
            pbft_message.get_info().get_view(),
            pbft_message.get_info().get_seq_num(),
            &hex::encode(pbft_message.get_block().get_block_id())[..6],
        );

        Ok(handlers::multicast_hint(state, &pbft_message))
    } else {
        Ok(PbftHint::PresentMessage)
    }
}

#[allow(ptr_arg)]
fn verify_message_sender<'a, T: PbftGetInfo<'a>>(msg: &T, sender_id: &PeerId) -> bool {
    let signer_id = msg.get_msg_info().get_signer_id().to_vec();
    &signer_id == sender_id
}

fn extract_message<T: Message>(msg: &[u8]) -> Result<T, PbftError> {
    protobuf::parse_from_bytes::<T>(msg).map_err(PbftError::SerializationError)
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
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use handlers::make_msg_info;
    use sawtooth_sdk::consensus::engine::{Error, PeerId};
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
            let prev_num = ::std::panic::catch_unwind(|| self.chain.len() - 2).unwrap_or(0);
            Ok(Block {
                block_id: self.chain.last().unwrap().clone(),
                previous_id: self.chain.get(prev_num).unwrap().clone(),
                signer_id: PeerId::from(vec![]),
                block_num: self.chain.len() as u64,
                payload: vec![],
                summary: vec![],
            })
        }
        fn get_settings(
            &mut self,
            _block_id: BlockId,
            _settings: Vec<String>,
        ) -> Result<HashMap<String, String>, Error> {
            Ok(Default::default())
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
    fn mock_node(node_id: usize) -> PbftNode {
        let service: Box<MockService> = Box::new(MockService {
            // Create genesis block (but with actual ID)
            chain: vec![mock_block_id(0)],
        });
        let cfg = mock_config(4);
        PbftNode::new(&cfg, service, node_id == 0)
    }

    /// Create a deterministic BlockId hash based on a block number
    fn mock_block_id(num: u64) -> BlockId {
        let mut sha = Sha256::new();
        sha.input_str(format!("I'm a block with block num {}", num).as_str());
        BlockId::from(sha.result_str().as_bytes().to_vec())
    }

    /// Create a deterministic PeerId hash based on a peer number
    fn mock_peer_id(num: u64) -> PeerId {
        let mut sha = Sha256::new();
        sha.input_str(format!("I'm a peer (number {})", num).as_str());
        PeerId::from(sha.result_str().as_bytes().to_vec())
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

    /// Create a mock serialized PbftMessage
    fn mock_msg(
        msg_type: &PbftMessageType,
        view: u64,
        seq_num: u64,
        block: Block,
        from: u64,
    ) -> Vec<u8> {
        let info = make_msg_info(&msg_type, view, seq_num, mock_peer_id(from));

        let mut pbft_msg = PbftMessage::new();
        pbft_msg.set_info(info);
        pbft_msg.set_block(pbft_block_from_block(block.clone()));

        pbft_msg.write_to_bytes().expect("SerializationError")
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

    /// Make sure that receiving a `BlockNew` update works as expected
    #[test]
    fn block_new() {
        // NOTE: Special case for primary node
        let mut node0 = mock_node(0);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(0, &cfg);
        node0
            .on_block_new(mock_block(1), &mut state0)
            .unwrap_or_else(handle_pbft_err);
        assert_eq!(state0.phase, PbftPhase::PrePreparing);
        assert_eq!(state0.seq_num, 1);
        assert_eq!(
            state0.working_block,
            WorkingBlockOption::TentativeWorkingBlock(mock_block_id(1))
        );

        // Try the next block
        let mut node1 = mock_node(1);
        let mut state1 = PbftState::new(1, &cfg);
        node1
            .on_block_new(mock_block(1), &mut state1)
            .unwrap_or_else(handle_pbft_err);
        assert_eq!(state1.phase, PbftPhase::PrePreparing);
        assert_eq!(
            state1.working_block,
            WorkingBlockOption::TentativeWorkingBlock(mock_block_id(1))
        );
        assert_eq!(state1.seq_num, 0);

        // Try a block way in the future (push to backlog)
        let mut node1 = mock_node(1);
        let mut state1 = PbftState::new(1, &cfg);
        node1
            .on_block_new(mock_block(7), &mut state1)
            .unwrap_or_else(handle_pbft_err);
        assert_eq!(state1.phase, PbftPhase::NotStarted);
        assert_eq!(state1.working_block, WorkingBlockOption::NoWorkingBlock);
        assert_eq!(state1.seq_num, 0);
    }

    /// Make sure that receiving a `BlockValid` update works as expected
    #[test]
    fn block_valid() {
        let mut node = mock_node(0);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(0, &cfg);
        state0.phase = PbftPhase::Checking;
        node.on_block_valid(mock_block_id(1), &mut state0)
            .unwrap_or_else(handle_pbft_err);
        assert!(state0.phase == PbftPhase::Committing);
    }

    /// Make sure that receiving a `BlockCommit` update works as expected
    #[test]
    fn block_commit() {
        let mut node = mock_node(0);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(0, &cfg);
        state0.phase = PbftPhase::Finished;
        node.on_block_commit(mock_block_id(1), &mut state0)
            .unwrap_or_else(handle_pbft_err);
        assert!(state0.phase == PbftPhase::NotStarted);
    }

    /// Test the multicast protocol (`PrePrepare` => `Prepare` => `Commit`)
    #[test]
    fn multicast_protocol() {
        let mut node = mock_node(0);
        let cfg = mock_config(4);
        let mut state0 = PbftState::new(0, &cfg);
        assert!(
            node.on_peer_message(
                b"this message will result in an error",
                &mock_peer_id(0),
                &mut state0
            ).is_err()
        );

        // Make sure BlockNew is in the log
        let mut node1 = mock_node(1);
        let mut state1 = PbftState::new(1, &cfg);
        let block = mock_block(1);
        node1
            .on_block_new(block.clone(), &mut state1)
            .unwrap_or_else(handle_pbft_err);

        // Receive a PrePrepare
        let msg = mock_msg(&PbftMessageType::PrePrepare, 0, 1, block.clone(), 0);
        node1
            .on_peer_message(&msg, &mock_peer_id(0), &mut state1)
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
            let msg = mock_msg(&PbftMessageType::Prepare, 0, 1, block.clone(), peer);
            node1
                .on_peer_message(&msg, &mock_peer_id(peer), &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }
        assert_eq!(state1.phase, PbftPhase::Checking);

        // Spoof the `check_blocks()` call
        assert!(node1.on_block_valid(mock_block_id(1), &mut state1).is_ok());

        // Receive 3 `Commit` messages
        for peer in 0..3 {
            assert_eq!(state1.phase, PbftPhase::Committing);
            let msg = mock_msg(&PbftMessageType::Commit, 0, 1, block.clone(), peer);
            node1
                .on_peer_message(&msg, &mock_peer_id(peer), &mut state1)
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
        let mut node1 = mock_node(1);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(1, &cfg);
        // Pretend that the node just finished block 10
        state1.seq_num = 10;
        let block = mock_block(10);
        assert_eq!(state1.mode, PbftMode::Normal);
        assert!(node1.msg_log.latest_stable_checkpoint.is_none());

        // Receive 3 `Checkpoint` messages
        for peer in 0..3 {
            let msg = mock_msg(&PbftMessageType::Checkpoint, 0, 10, block.clone(), peer);
            node1
                .on_peer_message(&msg, &mock_peer_id(peer), &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }

        assert_eq!(state1.mode, PbftMode::Normal);
        assert!(node1.msg_log.latest_stable_checkpoint.is_some());
    }

    /// Test that view changes work as expected, and that nodes take the proper roles after a view
    /// change
    #[test]
    fn view_change() {
        let mut node1 = mock_node(1);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(1, &cfg);

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
            let info = make_msg_info(&PbftMessageType::ViewChange, 1, 1, mock_peer_id(peer));
            let mut vc_msg = PbftViewChange::new();
            vc_msg.set_info(info);
            vc_msg.set_checkpoint_messages(RepeatedField::default());

            let msg_bytes = vc_msg.write_to_bytes().unwrap();
            node1
                .on_peer_message(&msg_bytes, &mock_peer_id(peer), &mut state1)
                .unwrap_or_else(handle_pbft_err);
        }

        assert!(state1.is_primary());
        assert_eq!(state1.view, 1);
    }

    /// Make sure that view changes start correctly
    #[test]
    fn propose_view_change() {
        let mut node1 = mock_node(1);
        let cfg = mock_config(4);
        let mut state1 = PbftState::new(1, &cfg);
        assert_eq!(state1.mode, PbftMode::Normal);

        node1
            .propose_view_change(&mut state1)
            .unwrap_or_else(handle_pbft_err);

        assert_eq!(state1.mode, PbftMode::ViewChanging);
    }

    /// Test that the legitimacy of message senders is verified correctly
    #[test]
    fn message_sender_verification() {
        let peer_msg = mock_msg(&PbftMessageType::PrePrepare, 0, 1, mock_block(1), 0);
        let msg: PbftMessage = extract_message(&peer_msg).unwrap();

        // Make sure a legitimate message is accepted
        assert!(verify_message_sender(&&msg, &mock_peer_id(0)));

        // Make sure an illegitimate message is rejected
        assert!(!verify_message_sender(&&msg, &mock_peer_id(1)));
    }
}
