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
use protobuf::{Message, ProtobufError};

use std::collections::{HashMap, HashSet};

use std::convert::From;
use std::fmt;

use sawtooth_sdk::consensus::engine::{Block, BlockId, Error as EngineError, PeerId, PeerMessage};
use sawtooth_sdk::consensus::service::Service;

use config::PbftConfig;
use message_type::PbftMessageType;
use pbft_log::PbftLog;
use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo};
use state::{PbftPhase, PbftState};

// The actual node
pub struct PbftNode {
    service: Box<Service>,
    state: PbftState,
    msg_log: PbftLog,
}

impl fmt::Display for PbftNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ast = if self.state.is_primary() { "*" } else { " " };

        write!(
            f,
            "Node {}{:02} ({:?})",
            ast, self.state.id, self.state.phase
        )
    }
}

impl PbftNode {
    pub fn new(id: u64, config: &PbftConfig, service: Box<Service>) -> Self {
        PbftNode {
            state: PbftState::new(id, config),
            service: service,
            msg_log: PbftLog::new(config),
        }
    }

    // Handle a peer message from another PbftNode
    // This method controls the PBFT multicast protocol (PrePrepare, Prepare, Commit, CommitFinal).
    pub fn on_peer_message(&mut self, msg: PeerMessage) {
        let msg_type = msg.message_type.clone();
        let msg_type = msg_type.as_str();

        match msg_type {
            "PrePrepare" | "Prepare" | "Commit" | "CommitFinal" => {
                let mc_type = PbftMessageType::from(msg_type);

                let deser_msg = protobuf::parse_from_bytes::<PbftMessage>(&msg.content);
                if let Err(e) = deser_msg {
                    error!("Couldn't deserialize message: {}", e);
                    return;
                }
                let deser_msg = deser_msg.unwrap();

                // Don't process message if we're not ready for it.
                // i.e. Don't process prepare messages if we're not in the PbftPhase::Preparing
                let expecting_type = self.state.check_msg_type();
                if expecting_type != mc_type {
                    debug!(
                        "{}: !!!!!! [Node {:02}]: {:?} (in mode {:?})",
                        self,
                        self.state
                            .get_node_id_from_bytes(deser_msg.get_info().get_signer_id()),
                        msg_type,
                        self.state.phase,
                    );
                    return;
                }

                info!(
                    "{}: <<<<<< [Node {:02}]: {:?}",
                    self,
                    self.state
                        .get_node_id_from_bytes(deser_msg.get_info().get_signer_id()),
                    msg.message_type,
                );

                match mc_type {
                    PbftMessageType::PrePrepare => {
                        let info = deser_msg.get_info();

                        if info.get_view() != self.state.view {
                            // TODO: return after cleaning up and resetting state (?)
                            error!("View mismatch: {} != {}", info.get_view(), self.state.view);
                            return;
                        }

                        // Immutably borrow self for a limited time
                        {
                            {
                                // Check that this PrePrepare doesn't already exist
                                let existing_pre_prep_msgs = self.msg_log.get_messages_of_type(
                                    &PbftMessageType::PrePrepare,
                                    info.get_seq_num(),
                                );

                                if existing_pre_prep_msgs.len() > 0 {
                                    error!("A PrePrepare message already exists with this sequence number");
                                    return;
                                }
                            }

                            {
                                // Check that incoming PrePrepare matches original BlockNew
                                let block_new_msgs = self.msg_log.get_messages_of_type(
                                    &PbftMessageType::BlockNew,
                                    deser_msg.get_info().get_seq_num(),
                                );

                                if block_new_msgs.len() > 1
                                    || block_new_msgs[0].get_block() != deser_msg.get_block()
                                {
                                    error!("Block mismatch");
                                    return;
                                }
                            }

                            // TODO: Not sure if this is actually the way this is supposed to
                            // happen. Theoretically, primaries should be the only ones that care
                            // about sequence numbers
                            //
                            // Should the sequence number just be the block number?
                            if self.state.is_primary() {
                                // Check that incoming PrePrepare matches original BlockNew
                                let block_new_msgs = self.msg_log.get_messages_of_type(
                                    &PbftMessageType::BlockNew,
                                    info.get_seq_num(),
                                );

                                if block_new_msgs.len() != 1 {
                                    error!(
                                        "Wrong number of BlockNew messages in this sequence (expected 1, got {})",
                                        block_new_msgs.len()
                                    );
                                    return;
                                }

                                if block_new_msgs[0].get_block() != deser_msg.get_block() {
                                    error!(
                                        "Block mismatch\nBlock1: {:?}\nBlock2: {:?}",
                                        block_new_msgs[0],
                                        deser_msg.get_block()
                                    );
                                    return;
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
                        self.state.advance_phase();

                        self._broadcast_pbft_message(
                            info.get_seq_num(),
                            PbftMessageType::Prepare,
                            (*deser_msg.get_block()).clone(),
                        );
                    }
                    PbftMessageType::Prepare => {
                        // Add message to the log
                        self.msg_log.add_message(deser_msg.clone());
                        self.state.advance_phase();

                        if !self._prepared(&deser_msg) {
                            error!("`prepared` predicate is false!");
                            return;
                        }

                        info!("{}: ------ Checking blocks", self);
                        self.service
                            .check_blocks(vec![
                                BlockId::from(deser_msg.get_block().clone().block_id),
                            ])
                            .expect("Failed to check blocks");
                    }
                    PbftMessageType::Commit => {
                        // Add message to the log
                        self.msg_log.add_message(deser_msg.clone());
                        self.state.advance_phase();

                        if !self._committed(&deser_msg) {
                            error!("`committed` predicate is false!");
                            return;
                        }

                        self._broadcast_pbft_message(
                            deser_msg.get_info().get_seq_num(),
                            PbftMessageType::CommitFinal,
                            (*deser_msg.get_block()).clone(),
                        );
                    }
                    PbftMessageType::CommitFinal => {
                        // Add message to the log
                        self.msg_log.add_message(deser_msg.clone());
                        self.state.advance_phase();

                        let commit_final_msgs = self.msg_log.get_messages_of_type(
                            &PbftMessageType::CommitFinal,
                            deser_msg.get_info().get_seq_num(),
                        );

                        // TODO: check that messages are unique
                        if commit_final_msgs.len() < (self.state.f + 1) as usize {
                            error!(
                                "Not enough CommitFinal messages (have {}, need {})",
                                commit_final_msgs.len(),
                                self.state.f + 1
                            );
                            return;
                        }

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
            }
            t => warn!("Message type {:?} not implemented", t),
        }
    }

    // Creates a new working block on the working block queue and kicks off the consensus algorithm
    // by broadcasting a "PrePrepare" message to peers
    //
    // Assumes the validator has checked that the block signature is valid, and that it is to
    // be built on top of the current chain head.
    pub fn on_block_new(&mut self, block: Block) {
        info!("{}: <<<<<< BlockNew: {:?}", self, block.block_id.clone());

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
        self.state.advance_phase();

        // TODO: keep track of view in Node
        if self.state.is_primary() {
            let s = self.state.seq_num;
            self._broadcast_pbft_message(s, PbftMessageType::PrePrepare, pbft_block);
        }
    }

    // Handle a block commit from the Validator
    // If we're a primary, initialize a new block
    // If we're a secondary, commit the block in the message
    pub fn on_block_commit(&mut self, block_id: BlockId) {
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
            self.state.advance_phase();
        }
    }

    // Handle a valid block notice
    // This message comes after check_blocks is called
    pub fn on_block_valid(&mut self, block_id: BlockId) {
        info!("{}: <<<<<< BlockValid: {:?}", self, block_id);
        self.state.advance_phase();

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
        );
    }

    // The primary tries to finalize a block every so often
    pub fn update_working_block(&mut self) {
        if self.state.is_primary() {
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
    }

    // "prepared" predicate
    fn _prepared(&self, deser_msg: &PbftMessage) -> bool {
        let info = deser_msg.get_info();
        let block_new_msgs = self.msg_log
            .get_messages_of_type(&PbftMessageType::BlockNew, info.get_seq_num());
        if block_new_msgs.len() != 1 {
            error!(
                "Received {} BlockNew messages in this sequence, expected 1",
                block_new_msgs.len()
            );
            return false;
        }

        let pre_prep_msgs = self.msg_log
            .get_messages_of_type(&PbftMessageType::PrePrepare, info.get_seq_num());
        if pre_prep_msgs.len() != 1 {
            error!(
                "Received {} PrePrepare messages in this sequence, expected 1",
                pre_prep_msgs.len()
            );
            return false;
        }

        let prep_msgs = self.msg_log
            .get_messages_of_type(&PbftMessageType::Prepare, info.get_seq_num());

        for prep_msg in prep_msgs.iter() {
            // Make sure the contents match
            if !messages_match(prep_msg, pre_prep_msgs[0])
                || !messages_match(prep_msg, block_new_msgs[0])
            {
                error!("Prepare message mismatch");
                return false;
            }
        }

        let different_prepared_msgs = num_unique_signers(&prep_msgs);

        if different_prepared_msgs < 2 * self.state.f + 1 {
            error!(
                "Not enough Prepare messages (have {}, need {})",
                different_prepared_msgs,
                2 * self.state.f + 1
            );
            return false;
        }

        true
    }

    // "committed" predicate
    fn _committed(&self, deser_msg: &PbftMessage) -> bool {
        let commit_msgs = self.msg_log
            .get_messages_of_type(&PbftMessageType::Commit, deser_msg.get_info().get_seq_num());

        let different_commit_msgs = num_unique_signers(&commit_msgs);

        if different_commit_msgs < 2 * self.state.f + 1 {
            error!(
                "Not enough Commit messages (have {}, need {})",
                commit_msgs.len(),
                2 * self.state.f + 1
            );
            return false;
        }

        self._prepared(deser_msg)
    }

    fn _broadcast_pbft_message(
        &mut self,
        seq_num: u64,
        msg_type: PbftMessageType,
        block: PbftBlock,
    ) {
        // Make sure that we should be sending messages of this type
        if msg_type != self.state.check_msg_type() {
            info!("{}: xxxxxx {:?} not sending", self, msg_type);
            return;
        }

        let msg_bytes = make_msg_bytes(
            make_msg_info(
                &msg_type,
                self.state.view,
                seq_num,
                self.state.get_own_peer_id(),
            ),
            block,
        ).unwrap();

        // Broadcast to peers
        self.service
            .broadcast(String::from(&msg_type).as_str(), msg_bytes.clone())
            .unwrap_or_else(|err| error!("Couldn't broadcast: {}", err));
        info!("{}: >>>>>> {:?}", self, msg_type);

        // Send to self
        let peer_msg = PeerMessage {
            message_type: String::from(&msg_type),
            content: msg_bytes.clone(),
        };
        info!("{}: >self> {:?}", self, msg_type);
        self.on_peer_message(peer_msg);
    }
}

// TODO: break these out into better places
fn messages_match(m1: &PbftMessage, m2: &PbftMessage) -> bool {
    let (info1, info2) = (m1.get_info(), m2.get_info());

    info1.get_view() == info2.get_view() && info1.get_seq_num() == info2.get_seq_num()
        && m1.get_block() == m2.get_block()
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
fn num_unique_signers(msg_list: &Vec<&PbftMessage>) -> u64 {
    let mut received_from: HashSet<&[u8]> = HashSet::new();
    let mut different_prepared_msgs = 0;
    for b in msg_list {
        // If the signer is NOT already in the set
        if received_from.insert(b.get_block().get_signer_id()) {
            different_prepared_msgs += 1;
        }
    }
    different_prepared_msgs as u64
}
