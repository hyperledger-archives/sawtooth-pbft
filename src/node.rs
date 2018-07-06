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

use protobuf;
use protobuf::RepeatedField;
use protobuf::{Message, ProtobufError};

use std::collections::{HashMap, HashSet};

use std::convert::From;
use std::fmt;

use sawtooth_sdk::consensus::engine::{Block, BlockId, Error as EngineError, PeerId, PeerMessage};
use sawtooth_sdk::consensus::service::Service;

use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftNewView, PbftViewChange,
                           PbftViewChange_PrepareMessagePair as PrepareMessagePair};

use config::PbftConfig;
use error::PbftError;
use message_type::PbftMessageType;
use pbft_log::{PbftGetInfo, PbftLog};
use state::{PbftMode, PbftPhase, PbftState};

// The actual node
pub struct PbftNode {
    service: Box<Service>,
    pub state: PbftState,
    pub msg_log: PbftLog,
}

impl fmt::Display for PbftNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ast = if self.state.is_primary() { "*" } else { " " };
        let mode = match self.state.mode {
            PbftMode::Normal => "N",
            PbftMode::Checkpointing => "C",
            PbftMode::ViewChange => "V",
        };

        write!(
            f,
            "Node {}{:02} ({:?} {} {})",
            ast, self.state.id, self.state.phase, mode, self.state.view
        )
    }
}

impl PbftNode {
    pub fn new(id: u64, config: &PbftConfig, service: Box<Service>) -> Self {
        let mut n = PbftNode {
            state: PbftState::new(id, config),
            service: service,
            msg_log: PbftLog::new(config),
        };

        // Primary initializes a block
        if n.state.is_primary() {
            n.service
                .initialize_block(None)
                .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
        }

        n
    }

    // Handle a peer message from another PbftNode
    // This method controls the PBFT multicast protocol (PrePrepare, Prepare, Commit, CommitFinal).
    pub fn on_peer_message(&mut self, msg: PeerMessage) -> Result<(), PbftError> {
        let msg_type = msg.message_type.clone();
        debug!("{}: RECEIVED MESSAGE {}", self, msg_type);
        let msg_type = PbftMessageType::from(msg_type.as_str());

        // Handle a multicast protocol message
        if msg_type.is_multicast() {
            let deser_msg = protobuf::parse_from_bytes::<PbftMessage>(&msg.content);
            if let Err(e) = deser_msg {
                return Err(PbftError::SerializationError(e));
            }
            let deser_msg = deser_msg.unwrap();

            // Received a message from the primary, timeout can be reset
            let primary = self.state.get_primary_peer_id();
            if deser_msg.get_info().get_signer_id().to_vec() == Vec::<u8>::from(primary) {
                self.state.timeout.reset();
            }

            // Don't process message if we're not ready for it.
            // i.e. Don't process prepare messages if we're not in the PbftPhase::Preparing
            // Discard all multicast messages that come while we're in a ViewChange
            let expecting_type = self.state.check_msg_type();
            if expecting_type != msg_type && self.state.mode != PbftMode::ViewChange {
                debug!(
                    "{}: !!!!!! [Node {:02}]: {:?} (in mode {:?})",
                    self,
                    self.state
                        .get_node_id_from_bytes(deser_msg.get_info().get_signer_id()),
                    msg_type,
                    self.state.phase,
                );

                if expecting_type != PbftMessageType::Unset && msg_type > expecting_type {
                    info!("{}: Pushing unread {:?}", self, msg_type);
                    self.msg_log.push_unread(msg);
                }
                return Ok(());
            }

            info!(
                "{}: <<<<<< [Node {:02}]: {:?}",
                self,
                self.state
                    .get_node_id_from_bytes(deser_msg.get_info().get_signer_id()),
                msg.message_type,
            );

            match msg_type {
                PbftMessageType::PrePrepare => {
                    let info = deser_msg.get_info();

                    if info.get_view() != self.state.view {
                        // TODO: return after cleaning up and resetting state (?)
                        return Err(PbftError::ViewMismatch(
                            info.get_view() as usize,
                            self.state.view as usize,
                        ));
                    }

                    // Immutably borrow self for a limited time
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
                    {
                        // TODO: Should the sequence number just be the block number?
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

                            if block_new_msgs[0].get_block() != deser_msg.get_block() {
                                return Err(PbftError::BlockMismatch(
                                    block_new_msgs[0].get_block().clone(),
                                    deser_msg.get_block().clone(),
                                ));
                            }
                        } else {
                            // Set this secondary's sequence number from the PrePrepare message
                            // (this was originally set by the primary)...
                            self.state.seq_num = info.get_seq_num();

                            // ...then update the BlockNew message we received with the correct
                            // sequence number
                            let num_updated = self.msg_log
                                .fix_seq_nums(&PbftMessageType::BlockNew, info.get_seq_num());
                            info!("The log updated {} BlockNew messages", num_updated);
                        }
                    }

                    // Add message to the log
                    // TODO: Putting log add here is necessary because on_peer_message gets
                    // called again inside of _broadcast_pbft_message
                    self.msg_log.add_message(deser_msg.clone());
                    self.state.phase = PbftPhase::Preparing;

                    self._broadcast_pbft_message(
                        info.get_seq_num(),
                        PbftMessageType::Prepare,
                        (*deser_msg.get_block()).clone(),
                    )?;
                }

                PbftMessageType::Prepare => {
                    // Add message to the log
                    self.msg_log.add_message(deser_msg.clone());

                    self._prepared(&deser_msg)?;

                    if self.state.phase != PbftPhase::Checking {
                        self.state.phase = PbftPhase::Checking;
                        info!("{}: ------ Checking blocks", self);
                        self.service
                            .check_blocks(vec![
                                BlockId::from(deser_msg.get_block().clone().block_id),
                            ])
                            .expect("Failed to check blocks");
                    }
                }

                PbftMessageType::Commit => {
                    // Add message to the log
                    self.msg_log.add_message(deser_msg.clone());

                    self._committed(&deser_msg)?;

                    self.state.phase = PbftPhase::FinalCommitting;

                    self._broadcast_pbft_message(
                        deser_msg.get_info().get_seq_num(),
                        PbftMessageType::CommitFinal,
                        (*deser_msg.get_block()).clone(),
                    )?;
                }

                PbftMessageType::CommitFinal => {
                    // Add message to the log
                    self.msg_log.add_message(deser_msg.clone());

                    let commit_final_msgs = self.msg_log.get_messages_of_type(
                        &PbftMessageType::CommitFinal,
                        deser_msg.get_info().get_seq_num(),
                        deser_msg.get_info().get_view(),
                    );

                    self._check_msg_against_log(&&deser_msg, true, Some(self.state.f + 1))?;

                    self.state.phase = PbftPhase::Finished;

                    info!(
                        "{}: Committing block {:?}",
                        self,
                        BlockId::from(deser_msg.get_block().block_id.clone())
                    );

                    self.service
                        .commit_block(BlockId::from(deser_msg.get_block().block_id.clone()))
                        .expect("Failed to commit block");
                }

                _ => warn!("Message type not implemented"),
            }
        } else if msg_type.is_view_change() {
            info!("{}: Received ViewChange message", self);

            let deser_msg = protobuf::parse_from_bytes::<PbftViewChange>(&msg.content);
            if let Err(e) = deser_msg {
                return Err(PbftError::SerializationError(e));
            }
            let deser_msg = deser_msg.unwrap();

            self.msg_log.add_view_change(deser_msg.clone());

            {
                self.msg_log.add_view_change(deser_msg.clone());

                let vc_msgs = self.msg_log.get_view_change(self.state.view);
                let infos = vc_msgs
                    .iter()
                    .map(|&msg| msg.get_info())
                    .collect();
                let num_vc_msgs = num_unique_signers(&infos);

                if num_vc_msgs < 2 * self.state.f + 1 {
                    return Err(PbftError::WrongNumMessages(
                        PbftMessageType::ViewChange,
                        (2 * self.state.f + 1) as usize,
                        num_vc_msgs as usize,
                    ));
                }
            }
            let mut nv_msg = PbftNewView::new();
            {
                // Advance this node's view and upgrade it to primary, if its ID is correct
                self.state.view += 1;
                info!(
                    "{}: Updating to view {} and resetting timeout",
                    self, self.state.view
                );
                self.state.timeout.reset();
                self.state.mode = PbftMode::Normal;

                if self.state.get_own_peer_id() == self.state.get_primary_peer_id() {
                    self.state.upgrade_role();

                    // If we're the new primary, need to clean up the block mess from the view change
                    self.service
                        .cancel_block()
                        .unwrap_or_else(|e| error!("Couldn't cancel block: {}", e));
                    self.service
                        .initialize_block(None)
                        .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
                } else {
                    self.state.downgrade_role();
                }

                // ViewChange messages
                let vc_msgs_send = self.msg_log
                    .get_view_change(self.state.view)
                    .iter()
                    .map(|&msg| msg.clone())
                    .collect();

                // PrePrepare messages - requests that need to get re-processed
                let mut pre_prep_msgs: Vec<PbftMessage> = vec![];

                let info = make_msg_info(
                    &PbftMessageType::NewView,
                    self.state.view,
                    self.state.seq_num,
                    self.state.get_own_peer_id(),
                );

                nv_msg.set_info(info);
                nv_msg.set_view_change_messages(RepeatedField::from_vec(vc_msgs_send));
                nv_msg.set_pre_prepare_messages(RepeatedField::from_vec(pre_prep_msgs));
            }

            let msg_bytes = nv_msg
                .write_to_bytes()
                .map_err(|e| PbftError::SerializationError(e));

            match msg_bytes {
                Err(e) => return Err(e),
                Ok(bytes) => self._broadcast_message(&PbftMessageType::NewView, &bytes),
            };
        } else if msg_type.is_new_view() {
            // TODO: Here is where we should restart the multicast protocol for messages since the
            // last stable checkpoint
            info!("{}: Received NewView message", self);
        } else if msg_type.is_checkpoint() {
            let deser_msg = protobuf::parse_from_bytes::<PbftMessage>(&msg.content);
            if let Err(e) = deser_msg {
                return Err(PbftError::SerializationError(e));
            }
            let deser_msg = deser_msg.unwrap();

            info!(
                "{}: Received Checkpoint message from {:02}",
                self,
                self.state
                    .get_node_id_from_bytes(deser_msg.get_info().get_signer_id())
            );

            if let Some(ref checkpoint) = self.msg_log.latest_stable_checkpoint {
                if checkpoint.seq_num >= deser_msg.get_info().get_seq_num() {
                    debug!(
                        "{}: Already at a stable checkpoint with this sequence number or past it!",
                        self
                    );
                    return Ok(());
                }
            }

            // Add message to the log
            self.msg_log.add_message(deser_msg.clone());

            // If we're a secondary, forward the message to everyone else in the network (resign it)
            if !self.state.is_primary() && self.state.mode != PbftMode::Checkpointing {
                self.state.pre_checkpoint_mode = self.state.mode;
                self.state.mode = PbftMode::Checkpointing;
                self._broadcast_pbft_message(
                    deser_msg.get_info().get_seq_num(),
                    PbftMessageType::Checkpoint,
                    PbftBlock::new(),
                )?;
            }

            if self.state.mode == PbftMode::Checkpointing {
                self._check_msg_against_log(&&deser_msg, true, None)?;
                info!(
                    "{}: Reached stable checkpoint (seq num {}); garbage collecting logs",
                    self,
                    deser_msg.get_info().get_seq_num()
                );
                self.msg_log.garbage_collect(
                    deser_msg.get_info().get_seq_num(),
                    deser_msg.get_info().get_view(),
                );

                self.state.mode = self.state.pre_checkpoint_mode;
            }
        } else if msg_type.is_pulse() {
            // Directly deserialize into PeerId
            let primary = PeerId::from(msg.content);

            // Reset the timer if the PeerId checks out
            if self.state.get_primary_peer_id() == primary {
                self.state.timeout.reset();
            }
        }

        Ok(())
    }

    // Creates a new working block on the working block queue and kicks off the consensus algorithm
    // by broadcasting a "PrePrepare" message to peers
    //
    // Assumes the validator has checked that the block signature is valid, and that it is to
    // be built on top of the current chain head.
    pub fn on_block_new(&mut self, block: Block) -> Result<(), PbftError> {
        info!("{}: <<<<<< BlockNew: {:?}", self, block.block_id);

        let pbft_block = pbft_block_from_block(block.clone());

        let mut msg = PbftMessage::new();
        if self.state.is_primary() {
            if self.state.seq_num == 0 {
                self.state.seq_num = 1;
            }
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

        self.msg_log.add_message(msg);
        self.state.phase = PbftPhase::PrePreparing;

        if self.state.is_primary() {
            let s = self.state.seq_num;
            self._broadcast_pbft_message(s, PbftMessageType::PrePrepare, pbft_block)?;
        }

        Ok(())
    }

    // Handle a block commit from the Validator
    // If we're a primary, initialize a new block
    // For both node roles, change phase back to NotStarted
    pub fn on_block_commit(&mut self, block_id: BlockId) -> Result<(), PbftError> {
        if self.state.phase == PbftPhase::Finished {
            if self.state.is_primary() {
                // Initialize block if we're ready to do so
                info!(
                    "{}: <<<<<< BlockCommit and initializing new one: {:?}",
                    self, block_id
                );
                self.service
                    .initialize_block(None)
                    .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
                self.state.seq_num += 1;
            }
            self.state.phase = PbftPhase::NotStarted;
        }

        Ok(())
    }

    // Handle a valid block notice
    // This message comes after check_blocks is called
    pub fn on_block_valid(&mut self, block_id: BlockId) -> Result<(), PbftError> {
        info!("{}: <<<<<< BlockValid: {:?}", self, block_id);
        self.state.phase = PbftPhase::Committing;

        let valid_blocks: Vec<Block> = self.service
            .get_blocks(vec![block_id])
            .unwrap_or(HashMap::new())
            .into_iter()
            .map(|(_block_id, block)| block)
            .collect();

        assert_eq!(valid_blocks.len(), 1);

        let s = self.state.seq_num; // By now, secondaries have the proper seq number
        self._broadcast_pbft_message(
            s,
            PbftMessageType::Commit,
            pbft_block_from_block(valid_blocks[0].clone()),
        )?;

        Ok(())
    }

    // The primary tries to finalize a block every so often
    pub fn update_working_block(&mut self) -> Result<(), PbftError> {
        if self.state.is_primary() {
            // First, get our PeerId
            let peer_id = self.state.get_own_peer_id();

            // Then send a pulse to all nodes to tell them that we're alive
            // and sign it with our PeerId
            self._broadcast_message(&PbftMessageType::Pulse, &Vec::<u8>::from(peer_id))?;

            // Try to finalize a block
            if self.state.phase == PbftPhase::NotStarted {
                match self.service.finalize_block(vec![]) {
                    Ok(block_id) => {
                        info!("{}: Publishing block {:?}", self, block_id);
                    }
                    Err(EngineError::BlockNotReady) => {
                        info!("{}: Block not ready", self);
                    }
                    Err(err) => panic!("Failed to finalize block: {:?}", err),
                }
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
        info!("{}: Starting checkpoint", self);
        let s = self.state.seq_num;
        self._broadcast_pbft_message(s, PbftMessageType::Checkpoint, PbftBlock::new())
    }

    pub fn retry_unread(&mut self) -> Result<(), PbftError> {
        if let Some(msg) = self.msg_log.pop_unread() {
            info!("{}: Popping unread {}", self, msg.message_type);
            self.on_peer_message(msg)?
        }
        Ok(())
    }

    // Initiate a view change (this node suspects that the primary is faulty)
    //
    // Drop everything when we're doing a view change - nodes will not process any peer messages
    // until the view change is complete.
    pub fn start_view_change(&mut self) -> Result<(), PbftError> {
        if self.state.mode == PbftMode::ViewChange {
            warn!(
                "{}: Already in a view change -- this might mean the network is dead",
                self
            );
            return Ok(());
        }
        info!("{}: Starting view change", self);
        self.state.mode = PbftMode::ViewChange;

        // TODO: use actual checkpoints. For now take current seq num as stable
        let mut checkpoint_msgs: Vec<PbftMessage> = vec![];
        // TODO: actually build PrePrepare, Prepare, Checkpoint proofs
        let mut pairs: Vec<PrepareMessagePair> = vec![];

        let info = make_msg_info(
            &PbftMessageType::ViewChange,
            self.state.view,
            self.state.seq_num,
            self.state.get_own_peer_id(),
        );

        let mut vc_msg = PbftViewChange::new();
        vc_msg.set_info(info);
        vc_msg.set_checkpoint_messages(RepeatedField::from_vec(checkpoint_msgs));
        vc_msg.set_prepare_messages(RepeatedField::from_vec(pairs));

        let msg_bytes = vc_msg
            .write_to_bytes()
            .map_err(|e| PbftError::SerializationError(e));

        match msg_bytes {
            Err(e) => Err(e),
            Ok(bytes) => self._broadcast_message(&PbftMessageType::ViewChange, &bytes),
        }
    }

    // "prepared" predicate
    fn _prepared(&self, deser_msg: &PbftMessage) -> Result<(), PbftError> {
        let info = deser_msg.get_info();
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

        let pre_prep_msgs = self.msg_log.get_messages_of_type(
            &PbftMessageType::PrePrepare,
            info.get_seq_num(),
            info.get_view(),
        );
        if pre_prep_msgs.len() != 1 {
            return Err(PbftError::WrongNumMessages(
                PbftMessageType::PrePrepare,
                1,
                pre_prep_msgs.len(),
            ));
        }

        let prep_msgs = self.msg_log.get_messages_of_type(
            &PbftMessageType::Prepare,
            info.get_seq_num(),
            info.get_view(),
        );
        for prep_msg in prep_msgs.iter() {
            // Make sure the contents match
            if (!message_infos_match(prep_msg.get_info(), &pre_prep_msgs[0].get_info())
                && prep_msg.get_block() != pre_prep_msgs[0].get_block())
                || (!message_infos_match(prep_msg.get_info(), block_new_msgs[0].get_info())
                    && prep_msg.get_block() != block_new_msgs[0].get_block())
            {
                return Err(PbftError::MessageMismatch(PbftMessageType::Prepare));
            }
        }

        self._check_msg_against_log(&deser_msg, true, None)?;

        Ok(())
    }

    // "committed" predicate
    fn _committed(&self, deser_msg: &PbftMessage) -> Result<(), PbftError> {
        let commit_msgs = self.msg_log.get_messages_of_type(
            &PbftMessageType::Commit,
            deser_msg.get_info().get_seq_num(),
            deser_msg.get_info().get_view(),
        );

        self._check_msg_against_log(&deser_msg, true, None)?;

        self._prepared(deser_msg)
    }

    // Check an incoming message against its counterparts in the message log
    fn _check_msg_against_log<'a, T: PbftGetInfo<'a>>(
        &self,
        message: &'a T,
        check_match: bool,
        num_cutoff: Option<u64>,
    ) -> Result<(), PbftError> {
        let num_cutoff = num_cutoff.unwrap_or(2 * self.state.f + 1);
        let msg_type = PbftMessageType::from(message.get_msg_info().get_msg_type());

        let msg_infos: Vec<&PbftMessageInfo> = self.msg_log.get_message_infos(
            &msg_type,
            message.get_msg_info().get_seq_num(),
            message.get_msg_info().get_view(),
        );

        let num_cp_msgs = num_unique_signers(&msg_infos);
        if num_cp_msgs < num_cutoff {
            return Err(PbftError::WrongNumMessages(
                msg_type,
                num_cutoff as usize,
                num_cp_msgs as usize,
            ));
        }

        if check_match {
            let non_matches: usize = msg_infos
                .iter()
                .filter(|&m| !message_infos_match(message.get_msg_info(), m))
                .count();
            if non_matches > 0 {
                return Err(PbftError::MessageMismatch(msg_type));
            }
        }

        Ok(())
    }

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
            info!("{}: xxxxxx {:?} not sending", self, msg_type);
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
        self.service
            .broadcast(String::from(msg_type).as_str(), msg_bytes.clone())
            .unwrap_or_else(|err| error!("Couldn't broadcast: {}", err));
        info!("{}: >>>>>> {:?}", self, msg_type);

        // Send to self
        let peer_msg = PeerMessage {
            message_type: String::from(msg_type),
            content: msg_bytes.clone(),
        };
        info!("{}: >self> {:?}", self, msg_type);
        self.on_peer_message(peer_msg)
    }
}

// TODO: break these out into better places
fn message_infos_match(m1: &PbftMessageInfo, m2: &PbftMessageInfo) -> bool {
    m1.get_view() == m2.get_view() && m1.get_seq_num() == m2.get_seq_num()
}

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

fn make_msg_bytes(info: PbftMessageInfo, block: PbftBlock) -> Result<Vec<u8>, ProtobufError> {
    let mut msg = PbftMessage::new();
    msg.set_info(info);
    msg.set_block(block);

    msg.write_to_bytes()
}

fn pbft_block_from_block(block: Block) -> PbftBlock {
    let mut pbft_block = PbftBlock::new();
    pbft_block.set_block_id(Vec::<u8>::from(block.block_id));
    pbft_block.set_signer_id(Vec::<u8>::from(block.signer_id));
    pbft_block.set_block_num(block.block_num);
    pbft_block.set_summary(block.summary);
    pbft_block
}

// Make sure messages are all from different nodes
fn num_unique_signers(msg_info_list: &Vec<&PbftMessageInfo>) -> u64 {
    let mut received_from: HashSet<&[u8]> = HashSet::new();
    let mut diff_msgs = 0;
    for info in msg_info_list {
        // If the signer is NOT already in the set
        if received_from.insert(info.get_signer_id()) {
            diff_msgs += 1;
        }
    }
    diff_msgs as u64
}
