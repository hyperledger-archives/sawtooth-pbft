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

use hex;

use protobuf;
use protobuf::RepeatedField;
use protobuf::{Message, ProtobufError};

use std::error::Error;
use std::collections::HashMap;
use std::convert::From;

use sawtooth_sdk::consensus::engine::{Block, BlockId, Error as EngineError, PeerId, PeerMessage};
use sawtooth_sdk::consensus::service::Service;

use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

use node::config::PbftConfig;
use node::error::{PbftError, PbftNotReadyType};
use node::message_type::PbftMessageType;
use node::pbft_log::{PbftLog, PbftStableCheckpoint};
use node::state::{PbftMode, PbftPhase, PbftState, WorkingBlockOption};

// The actual node
pub struct PbftNode {
    service: Box<Service>,
    pub state: PbftState,
    pub msg_log: PbftLog,
}

impl PbftNode {
    pub fn new(id: u64, config: &PbftConfig, mut service: Box<Service>) -> Self {
        let mut n = PbftNode {
            state: PbftState::new(id, config),
            service: service,
            msg_log: PbftLog::new(config),
        };

        // Primary initializes a block
        if n.state.is_primary() {
            info!("{}: Initializing block", n.state);
            n.service
                .initialize_block(None)
                .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
        }
        n
    }

    // ---------- Methods for handling Updates from the validator ----------

    // Handle a peer message from another PbftNode
    // This method controls the PBFT multicast protocol (PrePrepare, Prepare, Commit).
    pub fn on_peer_message(&mut self, msg: PeerMessage) -> Result<(), PbftError> {
        let msg_type = msg.message_type.clone();
        let msg_type = PbftMessageType::from(msg_type.as_str());

        // Handle a multicast protocol message
        let mut multicast_not_ready = PbftNotReadyType::Proceed;
        if msg_type.is_multicast() {
            let pbft_message = protobuf::parse_from_bytes::<PbftMessage>(&msg.content)
                .map_err(|e| PbftError::SerializationError(e))?;
            // Received a message from the primary, timeout can be reset
            let primary = self.state.get_primary_peer_id();
            if pbft_message.get_info().get_signer_id().to_vec() == Vec::<u8>::from(primary) {
                self.state.timeout.reset();
            }

            info!(
                "{}: <<<<<< {} [Node {:02}] (v {}, seq {}, b {})",
                self.state,
                msg_type,
                self.state
                    .get_node_id_from_bytes(pbft_message.get_info().get_signer_id())?,
                pbft_message.get_info().get_view(),
                pbft_message.get_info().get_seq_num(),
                &hex::encode(pbft_message.get_block().get_block_id())[..6],
            );

            multicast_not_ready = self._handle_multicast(pbft_message);
        }

        match msg_type {
            PbftMessageType::Pulse => {
                // Directly deserialize into PeerId
                let primary = PeerId::from(msg.content);

                // Reset the timer if the PeerId checks out
                if self.state.get_primary_peer_id() == primary {
                    self.state.timeout.reset();
                }
            }

            PbftMessageType::PrePrepare => {
                let pbft_message = protobuf::parse_from_bytes::<PbftMessage>(&msg.content)
                    .map_err(|e| PbftError::SerializationError(e))?;

                // If we've got a BlockNew ready and the sequence number is our current plus one,
                // then ignore whatever multicast_not_ready tells us to do.
                let mut ignore_not_ready = false;
                if let WorkingBlockOption::WorkingBlockNew(ref block_id) = self.state.working_block {
                    if block_id == &BlockId::from(pbft_message.get_block().get_block_id().to_vec())
                        && pbft_message.get_info().get_seq_num() == self.state.seq_num + 1
                    {
                        info!("{}: Ignoring not ready and starting multicast", self.state);
                        ignore_not_ready = true;
                    } else {
                        info!("{}: Not starting multicast; ({} != {} or {} != {} + 1)",
                            self.state,
                            &hex::encode(Vec::<u8>::from(block_id.clone()))[..6],
                            &hex::encode(pbft_message.get_block().get_block_id())[..6],
                            pbft_message.get_info().get_seq_num(),
                            self.state.seq_num,
                        );
                    }
                }

                if !ignore_not_ready {
                    self._handle_not_ready(multicast_not_ready, &pbft_message, msg.content.clone())?;
                }

                self._handle_pre_prepare(&pbft_message)?;

                // NOTE: Putting log add here is necessary because on_peer_message gets
                // called again inside of _broadcast_pbft_message
                self.msg_log.add_message(pbft_message.clone());
                self.state.switch_phase(PbftPhase::Preparing);

                warn!(
                    "{}: PrePrepare, sequence number {}",
                    self.state,
                    pbft_message.get_info().get_seq_num()
                );

                self._broadcast_pbft_message(
                    pbft_message.get_info().get_seq_num(),
                    PbftMessageType::Prepare,
                    (*pbft_message.get_block()).clone(),
                )?;
            }

            PbftMessageType::Prepare => {
                let pbft_message = protobuf::parse_from_bytes::<PbftMessage>(&msg.content)
                    .map_err(|e| PbftError::SerializationError(e))?;

                self._handle_not_ready(multicast_not_ready, &pbft_message, msg.content.clone())?;

                self.msg_log.add_message(pbft_message.clone());

                self.msg_log.prepared(&pbft_message, self.state.f)?;

                if self.state.phase != PbftPhase::Checking {
                    self.state.switch_phase(PbftPhase::Checking);
                    info!("{}: Checking blocks", self.state);
                    self.service
                        .check_blocks(vec![
                            BlockId::from(pbft_message.get_block().clone().block_id),
                        ])
                        .expect("Failed to check blocks");
                }
            }

            PbftMessageType::Commit => {
                let pbft_message = protobuf::parse_from_bytes::<PbftMessage>(&msg.content)
                    .map_err(|e| PbftError::SerializationError(e))?;

                self._handle_not_ready(multicast_not_ready, &pbft_message, msg.content.clone())?;

                self.msg_log.add_message(pbft_message.clone());

                self.msg_log.committed(&pbft_message, self.state.f)?;

                if self.state.phase == PbftPhase::Committing {
                    let working_block = if let WorkingBlockOption::WorkingBlock(ref wb) = self.state.working_block {
                        Ok(wb.clone())
                    } else {
                        Err(PbftError::NoWorkingBlock)
                    }?;

                    self.state.switch_phase(PbftPhase::Finished);

                    // Don't commit if we've seen this block already, but go ahead if we somehow
                    // skipped a block.
                    if pbft_message.get_block().get_block_id() != working_block.get_block_id()
                        && pbft_message.get_block().get_block_num() >= working_block.get_block_num()
                    {
                        warn!(
                            "{}: Not committing block {:?}",
                            self.state,
                            BlockId::from(pbft_message.get_block().block_id.clone())
                        );
                        return Err(PbftError::BlockMismatch(pbft_message.get_block().clone(), working_block.clone()));
                    }

                    // Also make sure that we're committing on top of the current chain head
                    let head = self.service.get_chain_head()
                        .map_err(|e| PbftError::InternalError(e.description().to_string()))?;
                    let cur_block = get_block_by_id(
                        &mut self.service,
                        BlockId::from(pbft_message.get_block().get_block_id().to_vec()))
                        .unwrap();
                    if cur_block.previous_id != head.block_id {
                        warn!(
                            "{}: Not committing block {:?} but pushing to unreads",
                            self.state,
                            BlockId::from(pbft_message.get_block().block_id.clone())
                        );
                        self.msg_log.push_unread(msg);
                        return Err(PbftError::BlockMismatch(pbft_message.get_block().clone(), working_block.clone()));
                    }

                    info!(
                        "{}: Committing block {:?}",
                        self.state,
                        BlockId::from(pbft_message.get_block().block_id.clone())
                    );

                    self.service
                        .commit_block(BlockId::from(pbft_message.get_block().block_id.clone()))
                        .expect("Failed to commit block");

                    // Previous block is sent to the validator; reset the working block
                    self.state.working_block = WorkingBlockOption::NoWorkingBlock;
                } else {
                    debug!(
                        "{}: Already committed block {:?}",
                        self.state,
                        BlockId::from(pbft_message.get_block().block_id.clone())
                    );
                }
            }

            PbftMessageType::Checkpoint => {
                let pbft_message = protobuf::parse_from_bytes::<PbftMessage>(&msg.content)
                    .map_err(|e| PbftError::SerializationError(e))?;

                debug!(
                    "{}: Received Checkpoint message from {:02}",
                    self.state,
                    self.state
                        .get_node_id_from_bytes(pbft_message.get_info().get_signer_id())?
                );

                if self.msg_log.get_latest_checkpoint() >= pbft_message.get_info().get_seq_num() {
                    debug!(
                        "{}: Already at a stable checkpoint with this sequence number or past it!",
                        self.state
                    );
                    return Ok(());
                }

                // Add message to the log
                self.msg_log.add_message(pbft_message.clone());

                self._handle_checkpoint(&pbft_message)?;
            }

            PbftMessageType::ViewChange => {
                let vc_message = protobuf::parse_from_bytes::<PbftViewChange>(&msg.content)
                    .map_err(|e| PbftError::SerializationError(e))?;

                debug!(
                    "{}: Received ViewChange message from Node {:02}",
                    self.state,
                    self.state
                        .get_node_id_from_bytes(vc_message.get_info().get_signer_id())?,
                );

                self.msg_log.add_view_change(vc_message.clone());

                if self.state.mode != PbftMode::ViewChange {
                    return Ok(());
                }

                self._handle_view_change(&vc_message)?;
            }

            _ => warn!("Message type not implemented"),
        }
        Ok(())
    }

    // Creates a new working block on the working block queue and kicks off the consensus algorithm
    // by broadcasting a "PrePrepare" message to peers
    //
    // Assumes the validator has checked that the block signature is valid, and that it is to
    // be built on top of the current chain head.
    pub fn on_block_new(&mut self, block: Block) -> Result<(), PbftError> {
        info!("{}: Got BlockNew: {:?}", self.state, block.block_id);

        let pbft_block = pbft_block_from_block(block.clone());

        let mut msg = PbftMessage::new();
        if self.state.is_primary() {
            self.state.seq_num += 1;
            msg.set_info(make_msg_info(
                &PbftMessageType::BlockNew,
                self.state.view,
                self.state.seq_num, // primary knows the proper sequence number
                self.state.get_own_peer_id(),
            ));
        } else {
            msg.set_info(make_msg_info(
                &PbftMessageType::BlockNew,
                self.state.view,
                0, // default to unset; change it later when we receive PrePrepare
                self.state.get_own_peer_id(),
            ));
        }

        msg.set_block(pbft_block.clone());

        let head = self.service.get_chain_head()
            .map_err(|e| PbftError::InternalError(e.description().to_string()))?;

        if self.state.switch_phase(PbftPhase::PrePreparing).is_none()
            || block.block_num > head.block_num + 1
        {
            info!("{}: Not ready for block {}, pushing to unread", self.state,
                  &hex::encode(Vec::<u8>::from(block.block_id.clone()))[..6]);
            self.msg_log.push_unread_block_new(block.clone());
            return Ok(())
        }
        self.msg_log.add_message(msg);
        self.state.working_block = WorkingBlockOption::WorkingBlockNew(block.block_id);

        if self.state.is_primary() {
            let s = self.state.seq_num;
            self._broadcast_pbft_message(s, PbftMessageType::PrePrepare, pbft_block)?;
        }
        Ok(())
    }

    // Handle a block commit from the Validator (the block was successfully committed)
    // If we're a primary, initialize a new block
    // For both node roles, change phase back to NotStarted
    pub fn on_block_commit(&mut self, block_id: BlockId) -> Result<(), PbftError> {
        info!("{}: <<<<<< BlockCommit: {:?}", self.state, block_id);

        if self.state.phase == PbftPhase::Finished {
            if self.state.is_primary() {
                info!("{}: Initializing block with previous ID {:?}", self.state, block_id);
                self.service
                    .initialize_block(Some(block_id))
                    .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
            }

            self.state.switch_phase(PbftPhase::NotStarted);

            // Start a checkpoint in NotStarted, if we're at one
            if self.msg_log.at_checkpoint() {
                self.start_checkpoint()?;
            }
        } else {
            debug!("{}: Not doing anything with BlockCommit :(", self.state);
        }
        Ok(())
    }

    // Handle a valid block notice
    // This message comes after check_blocks is called
    pub fn on_block_valid(&mut self, block_id: BlockId) -> Result<(), PbftError> {
        debug!("{}: <<<<<< BlockValid: {:?}", self.state, block_id);
        self.state.switch_phase(PbftPhase::Committing);

        info!("{}: Getting blocks", self.state);
        let valid_blocks: Vec<Block> = self.service
            .get_blocks(vec![block_id])
            .unwrap_or(HashMap::new())
            .into_iter()
            .map(|(_block_id, block)| block)
            .collect();

        if valid_blocks.len() < 1 {
            return Err(PbftError::WrongNumBlocks);
        }

        let s = self.state.seq_num; // By now, secondaries have the proper seq number
        self._broadcast_pbft_message(
            s,
            PbftMessageType::Commit,
            pbft_block_from_block(valid_blocks[0].clone()),
        )?;
        Ok(())
    }

    // ---------- Methods for periodically checking on and updating the state, called by the engine ----------

    // The primary tries to finalize a block every so often
    pub fn update_working_block(&mut self) -> Result<(), PbftError> {
        if self.state.is_primary() {
            // Try to finalize a block
            if self.state.phase == PbftPhase::NotStarted {
                debug!("{}: Summarizing block", self.state);
                if let Err(e) = self.service.summarize_block() {
                    error!("{}: Couldn't summarize, so not finalizing: {}", self.state,
                           e.description().to_string());
                } else {
                    debug!("{}: Trying to finalize block", self.state);
                    match self.service.finalize_block(vec![]) {
                        Ok(block_id) => {
                            info!("{}: Publishing block {:?}", self.state, block_id);
                        }
                        Err(EngineError::BlockNotReady) => {
                            debug!("{}: Block not ready", self.state);
                        }
                        Err(err) => panic!("Failed to finalize block: {:?}", err),
                    }
                }
                // First, get our PeerId
                let peer_id = self.state.get_own_peer_id();

                // Then send a pulse to all nodes to tell them that we're alive
                // and sign it with our PeerId
                debug!("{}: >>>>>> Pulse", self.state);
                self._broadcast_message(&PbftMessageType::Pulse, &Vec::<u8>::from(peer_id))?;
            }
        }
        Ok(())
    }

    // Check to see the state of the primary timeout
    pub fn check_timeout_expired(&mut self) -> bool {
        self.state.timeout.is_expired()
    }

    // Start the checkpoint process
    // Primaries start the checkpoint to ensure sequence number correctness
    pub fn start_checkpoint(&mut self) -> Result<(), PbftError> {
        if !self.state.is_primary() {
            return Ok(());
        }
        if self.state.mode == PbftMode::Checkpointing {
            return Ok(());
        }

        self.state.pre_checkpoint_mode = self.state.mode;
        self.state.mode = PbftMode::Checkpointing;
        debug!("{}: Starting checkpoint", self.state);
        let s = self.state.seq_num;
        self._broadcast_pbft_message(s, PbftMessageType::Checkpoint, PbftBlock::new())
    }

    pub fn retry_unread(&mut self) -> Result<(), PbftError> {
        let mut peer_res = Ok(());
        if let Some(msg) = self.msg_log.pop_unread() {
            debug!("{}: Popping unread {}", self.state, msg.message_type);
            peer_res = self.on_peer_message(msg);
        }
        if let Some(msg) = self.msg_log.pop_unread_block_new() {
            info!("{}: Popping unread BlockNew", self.state);
            self.on_block_new(msg)?;
        }
        peer_res
    }

    // Initiate a view change (this node suspects that the primary is faulty)
    //
    // Drop everything when we're doing a view change - nodes will not process any peer messages
    // until the view change is complete.
    pub fn start_view_change(&mut self) -> Result<(), PbftError> {
        if self.state.mode == PbftMode::ViewChange {
            return Ok(());
        }
        warn!("{}: Starting view change", self.state);
        self.state.mode = PbftMode::ViewChange;

        let PbftStableCheckpoint {
            seq_num: stable_seq_num,
            checkpoint_messages,
        } = if let Some(ref cp) = self.msg_log.latest_stable_checkpoint {
            cp.clone()
        } else {
            PbftStableCheckpoint {
                seq_num: 0,
                checkpoint_messages: vec![],
            }
        };

        let info = make_msg_info(
            &PbftMessageType::ViewChange,
            self.state.view,
            stable_seq_num,
            self.state.get_own_peer_id(),
        );

        let mut vc_msg = PbftViewChange::new();
        vc_msg.set_info(info);
        vc_msg.set_checkpoint_messages(RepeatedField::from_vec(checkpoint_messages.to_vec()));

        let msg_bytes = vc_msg
            .write_to_bytes()
            .map_err(|e| PbftError::SerializationError(e));

        match msg_bytes {
            Err(e) => Err(e),
            Ok(bytes) => self._broadcast_message(&PbftMessageType::ViewChange, &bytes),
        }
    }

    // ---------- Methods for handling individual PeerMessages

    // Either push to unreads or add message to log, depending on which type of not ready
    fn _handle_not_ready(
        &mut self,
        not_ready: PbftNotReadyType,
        pbft_message: &PbftMessage,
        msg_content: Vec<u8>,
    ) -> Result<(), PbftError> {
        let msg = PeerMessage {
            message_type: String::from(pbft_message.get_info().get_msg_type()),
            content: msg_content,
        };
        match not_ready {
            PbftNotReadyType::PushToUnreads
            | PbftNotReadyType::LimboPushToUnreads => {
                self.msg_log.push_unread(msg);
                Err(PbftError::NotReadyForMessage)
            }
            PbftNotReadyType::AddToLog
            | PbftNotReadyType::LimboAddToLog => {
                self.msg_log.add_message(pbft_message.clone());
                Err(PbftError::NotReadyForMessage)
            }
            PbftNotReadyType::Proceed => Ok(()),
        }
    }

    // Handle a multicast message (PrePrepare, Prepare, Commit)
    fn _handle_multicast(&mut self, pbft_message: PbftMessage) -> PbftNotReadyType {
        let msg_type = PbftMessageType::from(pbft_message.get_info().get_msg_type());

        if pbft_message.get_info().get_seq_num() > self.state.seq_num {
            info!(
                "{}: seq {} > {}, accept all.",
                self.state,
                pbft_message.get_info().get_seq_num(),
                self.state.seq_num
            );
            if self.state.working_block.is_none() {
                return PbftNotReadyType::LimboPushToUnreads;
            } else {
                return PbftNotReadyType::PushToUnreads;
            }
        } else if pbft_message.get_info().get_seq_num() == self.state.seq_num {
            if self.state.working_block.is_none() {
                info!(
                    "{}: seq {} == {}, in limbo",
                    self.state,
                    pbft_message.get_info().get_seq_num(),
                    self.state.seq_num,
                );
                return PbftNotReadyType::LimboAddToLog;
            }
            let expecting_type = self.state.check_msg_type();
            if msg_type < expecting_type {
                info!(
                    "{}: seq {} == {}, {} < {}, only add to log",
                    self.state,
                    self.state.seq_num,
                    self.state.seq_num,
                    msg_type,
                    expecting_type,
                );
                return PbftNotReadyType::AddToLog;
            } else if msg_type > expecting_type {
                info!(
                    "{}: seq {} == {}, {} > {}, push unread.",
                    self.state,
                    self.state.seq_num,
                    self.state.seq_num,
                    msg_type,
                    expecting_type,
                );
                return PbftNotReadyType::PushToUnreads;
            }
        } else {
            if self.state.working_block.is_none() {
                info!(
                    "{}: seq {} == {}, in limbo",
                    self.state,
                    pbft_message.get_info().get_seq_num(),
                    self.state.seq_num,
                );
                return PbftNotReadyType::LimboAddToLog;
            }
            info!(
                "{}: seq {} < {}, skip but add to log.",
                self.state,
                pbft_message.get_info().get_seq_num(),
                self.state.seq_num
            );
            return PbftNotReadyType::AddToLog;
        }
        PbftNotReadyType::Proceed
    }

    // Handle a PrePrepare message
    // A PrePrepare message with this view and sequence number must not exist in the log.
    // If this node is a primary, make sure there's a corresponding BlockNew message.
    // If this node is a secondary, then it takes the sequence number from this message as its own.
    fn _handle_pre_prepare(&mut self, pbft_message: &PbftMessage) -> Result<(), PbftError> {
        let info = pbft_message.get_info();

        if info.get_view() != self.state.view {
            return Err(PbftError::ViewMismatch(
                info.get_view() as usize,
                self.state.view as usize,
            ));
        }

        // Immutably borrow self for a bit, in a context
        {
            // Check that this PrePrepare doesn't already exist
            let existing_pre_prep_msgs = self.msg_log.get_messages_of_type(
                &PbftMessageType::PrePrepare,
                info.get_seq_num(),
                info.get_view(),
            );

            if existing_pre_prep_msgs.len() > 0 {
                return Err(PbftError::MessageExists(PbftMessageType::PrePrepare));
            }
        }

        if self.state.is_primary() {
            // Check that incoming PrePrepare matches original BlockNew
            let block_new_msgs = self.msg_log.get_messages_of_type(
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
            self.state.seq_num = info.get_seq_num();

            // ...then update the BlockNew message we received with the correct
            // sequence number
            let num_updated = self.msg_log.fix_seq_nums(
                &PbftMessageType::BlockNew,
                info.get_seq_num(),
                pbft_message.get_block(),
            );

            debug!(
                "{}: The log updated {} BlockNew messages to seq num {}",
                self.state,
                num_updated,
                info.get_seq_num()
            );

            if num_updated < 1 {
                return Err(PbftError::WrongNumMessages(PbftMessageType::BlockNew, 1, num_updated));
            }
        }

        // Take the working block from PrePrepare message as our current working block
        self.state.working_block = WorkingBlockOption::WorkingBlock(pbft_message.get_block().clone());

        Ok(())
    }

    // Handle a Checkpoint message
    // Secondaries send out a Checkpoint message
    // Everyone waits to receive 2f + 1 Checkpoint messages, then garbage collects logs
    fn _handle_checkpoint(&mut self, pbft_message: &PbftMessage) -> Result<(), PbftError> {
        // If we're a secondary, forward the message to everyone else in the network (resign it)
        if !self.state.is_primary() && self.state.mode != PbftMode::Checkpointing {
            self.state.pre_checkpoint_mode = self.state.mode;
            self.state.mode = PbftMode::Checkpointing;
            self._broadcast_pbft_message(
                pbft_message.get_info().get_seq_num(),
                PbftMessageType::Checkpoint,
                PbftBlock::new(),
            )?;
        }

        if self.state.mode == PbftMode::Checkpointing {
            self.msg_log.check_msg_against_log(&pbft_message, true, 2 * self.state.f + 1)?;
            warn!(
                "{}: Reached stable checkpoint (seq num {}); garbage collecting logs",
                self.state,
                pbft_message.get_info().get_seq_num()
            );
            self.msg_log.garbage_collect(
                pbft_message.get_info().get_seq_num(),
                pbft_message.get_info().get_view(),
            );

            self.state.mode = self.state.pre_checkpoint_mode;
        }
        Ok(())
    }

    fn _handle_view_change(
        &mut self,
        vc_message: &PbftViewChange,
    ) -> Result<(), PbftError> {
        self.msg_log.check_msg_against_log(&vc_message, true, 2 * self.state.f + 1)?;

        // Update current view and reset timer
        self.state.timeout.reset();
        self.state.view += 1;
        warn!(
            "{}: Updating to view {} and resetting timeout",
            self.state, self.state.view
        );

        // Upgrade this node to primary, if its ID is correct
        if self.state.get_own_peer_id() == self.state.get_primary_peer_id() {
            self.state.upgrade_role();
            warn!("{}: I'm now a primary", self.state);

            // If we're the new primary, need to clean up the block mess from the view change
            if let WorkingBlockOption::WorkingBlock(ref working_block) = self.state.working_block {
                info!("{}: Ignoring block {}", self.state, &hex::encode(working_block.get_block_id()));
                self.service
                    .ignore_block(BlockId::from(working_block.get_block_id().to_vec()))
                    .unwrap_or_else(|e| error!("Couldn't ignore block: {}", e));
            }
            info!("{}: Initializing block", self.state);
            self.service
                .initialize_block(None)
                .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
        } else {
            warn!("{}: I'm now a secondary", self.state);
            self.state.downgrade_role();
        }
        self.state.working_block = WorkingBlockOption::NoWorkingBlock;
        self.state.phase = PbftPhase::NotStarted;
        self.state.mode = PbftMode::Normal;
        warn!("{}: Entered normal mode in new view {}", self.state, self.state.view);
        Ok(())
    }

    // ---------- Methods for communication between nodes ----------

    // Broadcast a message to this node's peers, and itself
    fn _broadcast_pbft_message(
        &mut self,
        seq_num: u64,
        msg_type: PbftMessageType,
        block: PbftBlock,
    ) -> Result<(), PbftError> {
        let expected_type = self.state.check_msg_type();
        // Make sure that we should be sending messages of this type
        if msg_type.is_multicast() && msg_type != expected_type {
            return Ok(());
        }

        let msg_bytes = make_msg_bytes(
            make_msg_info(
                &msg_type,
                self.state.view,
                seq_num,
                self.state.get_own_peer_id(),
            ),
            block,
        ).unwrap_or(Vec::<u8>::new());

        self._broadcast_message(&msg_type, &msg_bytes)
    }

    fn _broadcast_message(
        &mut self,
        msg_type: &PbftMessageType,
        msg_bytes: &Vec<u8>,
    ) -> Result<(), PbftError> {
        // Broadcast to peers
        info!("{}: Broadcasting {:?}", self.state, msg_type);
        self.service
            .broadcast(String::from(msg_type).as_str(), msg_bytes.clone())
            .unwrap_or_else(|err| error!("Couldn't broadcast: {}", err));

        // Send to self
        let peer_msg = PeerMessage {
            message_type: String::from(msg_type),
            content: msg_bytes.clone(),
        };
        self.on_peer_message(peer_msg)
    }
}

// Check that everything but the signers of a block match
fn blocks_match(b1: &PbftBlock, b2: &PbftBlock) -> bool {
    b1.get_block_id() == b2.get_block_id()
        && b1.get_block_num() == b2.get_block_num()
}

// Create a PbftMessageInfo struct with the desired type, view, sequence number, and signer ID
fn make_msg_info(
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

// Create a Protobuf binary representation of a PbftMessage from its info and corresponding Block
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
    pbft_block.set_block_id(Vec::<u8>::from(block.block_id));
    pbft_block.set_signer_id(Vec::<u8>::from(block.signer_id));
    pbft_block.set_block_num(block.block_num);
    pbft_block.set_summary(block.summary);
    pbft_block
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
