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
use protobuf::Message;

use std::collections::HashMap;
use std::collections::VecDeque;

use std::fmt;
use std::convert::From;

use pbft_log::PbftLog;
use sawtooth_sdk::consensus::service::Service;
use sawtooth_sdk::consensus::engine::{
    PeerMessage,
    Block,
    BlockId,
    PeerId,
    Error as EngineError,
};

use protos::pbft_message::{
    PbftBlock,
    PbftMessage,
    PbftMessageInfo,
};

// Possible roles for a node
// Primary is the only node who is allowed to commit to the blockchain
#[derive(PartialEq)]
enum PbftNodeRole {
    Primary,
    Secondary,
}

// Messages related to the multicast protocol
#[derive(Debug, PartialEq, PartialOrd)]
enum PbftMulticastType {
    Unset,
    PrePrepare,
    Prepare,
    Commit,
    CommitFinal,
}

impl<'a> From<&'a str> for PbftMulticastType {
    fn from(s: &'a str) -> Self {
        match s {
            "pre_prepare" => PbftMulticastType::PrePrepare,
            "prepare" => PbftMulticastType::Prepare,
            "commit" => PbftMulticastType::Commit,
            "commit_final" => PbftMulticastType::CommitFinal,
            _ => {
                warn!("Unhandled multicast message type: {}", s);
                PbftMulticastType::Unset
            },
        }
    }
}

impl<'a> From<&'a PbftMulticastType> for String {
    fn from(mc_type: &'a PbftMulticastType) -> String {
        match mc_type {
            PbftMulticastType::PrePrepare => String::from("pre_prepare"),
            PbftMulticastType::Prepare => String::from("prepare"),
            PbftMulticastType::Commit => String::from("commit"),
            PbftMulticastType::CommitFinal => String::from("commit_final"),
            _ => String::from("unset"),
        }
    }
}


// Stages of the PBFT algorithm
#[derive(Debug, PartialEq, PartialOrd)]
enum PbftStage {
    NotStarted,
    PrePreparing,
    Preparing,
    Checking,
    Committing,
    FinalCommitting,
    Finished,
}

// The actual node
pub struct PbftNode {
    id: u64,
    stage: PbftStage,
    service: Box<Service>,
    role: PbftNodeRole,
    network_node_ids: HashMap<u64, PeerId>,
    msg_log: PbftLog,
    unread_queue: VecDeque<PeerMessage>,
}

impl fmt::Display for PbftNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ast = if self.role == PbftNodeRole::Primary {
            "*"
        } else {
            " "
        };

        write!(f, "Node {}{:02} ({:?})", ast, self.id, self.stage)
    }
}

impl PbftNode {
    pub fn new(id: u64, peers: HashMap<PeerId, u64>, service: Box<Service>) -> Self {
        // TODO: This is inefficient, but should only get run as many times as there are nodes
        let peer_id_map: HashMap<u64, PeerId> = peers
            .clone()
            .into_iter()
            .map(|(peer_id, node_id)| (node_id, peer_id))
            .collect();

        let current_primary = peers
            .iter()
            .map(|(_peer_id, node_id)| node_id)
            .min()
            .unwrap_or(&1);

        PbftNode {
            id: id,
            stage: PbftStage::NotStarted,
            role: if &id == current_primary {
                PbftNodeRole::Primary
            } else {
                PbftNodeRole::Secondary
            },
            network_node_ids: peer_id_map,
            service: service,
            msg_log: PbftLog::new(),
            unread_queue: VecDeque::new(), // TODO: Move this to message log?

        }
    }

    // Handle a peer message from another PbftNode
    // This method controls the PBFT multicast protocol (PrePrepare, Prepare, Commit, CommitFinal).
    pub fn on_peer_message(&mut self, msg: PeerMessage) {
        let msg_type = msg.message_type.clone();
        let msg_type = msg_type.as_str();

        match msg_type {
            "pre_prepare" | "prepare" | "commit" | "commit_final" => {
                let mc_type = PbftMulticastType::from(msg_type);

                let deser_msg = protobuf::parse_from_bytes::<PbftMessage>(&msg.content)
                    .unwrap_or_else(|err| {
                        error!("Couldn't deserialize message: {}", err);
                        panic!();
                });

                // Don't process message if we're not ready for it.
                // i.e. Don't process prepare messages if we're not in the PbftStage::Preparing
                if !self._check_ready_for_msg(&mc_type) {
                    // Only push unreads that contain a stage greater than the one we're at
                    let expecting_type = self._sending_message_type();
                    if mc_type >= expecting_type {
                        debug!(
                            "{}: !!!!!! [Node {:02}]: {:?} (in mode {:?})",
                            self,
                            self._get_node_id(PeerId::from(deser_msg.get_block().clone().signer_id)),
                            msg_type,
                            self.stage,
                        );
                        self.unread_queue.push_back(msg);
                    }
                    return;
                }

                info!(
                    "{}: <<<<<< [Node {:02}]: {:?}",
                    self,
                    self._get_node_id(PeerId::from(deser_msg.get_block().clone().signer_id)),
                    msg.message_type,
                );

                match mc_type {
                    PbftMulticastType::PrePrepare => {
                        // TODO check legitimacy of pre_prepare messages
                        self.stage = PbftStage::Preparing;

                        self._broadcast_pbft_message(
                            PbftMulticastType::Prepare,
                            1,
                            1,
                            (*deser_msg.get_block()).clone()
                        );
                    }
                    PbftMulticastType::Prepare => {
                        // TODO check prepared predicate
                        self.stage = PbftStage::Checking;

                        debug!("{}: ------ Checking blocks", self);
                        self.service.check_blocks(vec![BlockId::from(deser_msg.get_block().clone().block_id)])
                            .expect("Failed to check blocks");
                    }
                    PbftMulticastType::Commit => {
                        self.stage = PbftStage::FinalCommitting;

                        // TODO: check committed predicate
                        self._broadcast_pbft_message(
                            PbftMulticastType::CommitFinal,
                            1,
                            1,
                            (*deser_msg.get_block()).clone()
                        );
                    }
                    PbftMulticastType::CommitFinal => {
                        self.stage = PbftStage::Finished; // TODO: This will need to be changed

                        if self.role == PbftNodeRole::Primary {
                            debug!(
                                "{}: Primary committing block {:?}",
                                self,
                                BlockId::from(deser_msg.get_block().block_id.clone())
                            );
                            self.service.commit_block(
                                    BlockId::from(deser_msg.get_block().block_id.clone())
                                )
                                .expect("Failed to commit block");
                        }
                    }
                    PbftMulticastType::Unset => warn!("Message type Unset"),
                }
            }
            t => warn!("Message type {:?} not implemented", t),
        }
    }

    // Handle a new block from the Validator
    // Create a new working block on the working block queue and kick off the consensus algorithm
    // by broadcasting a "pre_prepare" message to peers
    pub fn on_block_new(&mut self, block: Block) {
        info!("{}: <<<<<< BlockNew: {:?}", self, block.block_id);

        self.stage = PbftStage::PrePreparing;
        // TODO: Check validity of block
        // TODO: keep track of seq number and view in Node
        if self.role == PbftNodeRole::Primary {
            self._broadcast_pbft_message(
                PbftMulticastType::PrePrepare,
                1,
                1,
                pbft_block_from_block(block)
            );
        }
    }

    // Handle a block commit from the Validator
    // If we're a primary, do nothing??
    // If we're a secondary, commit the block in the message
    pub fn on_block_commit(&mut self, block_id: BlockId) {
        if self.stage == PbftStage::Committing {
            match self.role {
                PbftNodeRole::Primary => {
                    // Initialize block if we're ready to do so
                    debug!("{}: <<<<<< BlockCommit and initializing new one: {:?}", self, block_id);
                    self.service.initialize_block(None)
                        .unwrap_or_else(|err| error!("Couldn't initialize block: {}", err));
                    self.stage = PbftStage::NotStarted;
                }
                PbftNodeRole::Secondary => {
                    debug!("{}: <<<<<< BlockCommit and committing: {:?}", self, block_id);
                    self.service.commit_block(block_id)
                        .unwrap_or_else(|err| error!("Couldn't commit block: {}", err));
                }
            }
        }
    }

    // Handle a valid block notice
    // This message comes after check_blocks is called
    pub fn on_block_valid(&mut self, block_id: BlockId) {
        info!("{}: <<<<<< BlockValid: {:?}", self, block_id);

        self.stage = PbftStage::Committing;

        // TODO: remove panic?
        let valid_blocks: Vec<Block> = self.service.get_blocks(vec![block_id])
            .unwrap_or_else(|err| panic!("Couldn't get block: {:?}", err))
            .into_iter()
            .map(|(_block_id, block)| block)
            .collect();

        assert_eq!(valid_blocks.len(), 1);

        self._broadcast_pbft_message(
            PbftMulticastType::Commit,
            1,
            1,
            pbft_block_from_block(valid_blocks[0].clone())
        );
    }

    pub fn update_working_block(&mut self) {
        debug!("{}: tried to update working block", self);
        if self.role == PbftNodeRole::Primary {
            if self.stage == PbftStage::Finished {
                self.service.initialize_block(None)
                    .expect("Couldn't initialize_block");
                self.stage = PbftStage::NotStarted;
            }
            if self.stage == PbftStage::NotStarted {
                match self.service.finalize_block(vec![]) {
                    Ok(block_id) => {
                        debug!("{}: Publishing block {:?}", self, block_id);
                    },
                    Err(EngineError::BlockNotReady) => {
                        debug!("{}: Block not ready", self);
                    },
                    Err(err) => panic!("Failed to finalize block: {:?}", err),
                }
            }
        }
    }

    // Retry one unread message. Called from event loop rapidly
    pub fn retry_unread(&mut self) {
        if let Some(m) = self.unread_queue.pop_front() {
            debug!("{}: Resending message: {:?}", self, m.message_type);
            self.on_peer_message(m);
        }
    }

    // Checks to see if a message type is acceptable to receive, in this node's
    // current stage.
    fn _check_ready_for_msg(&self, msg_type: &PbftMulticastType) -> bool {
        let corresponding_stage = match msg_type {
            PbftMulticastType::PrePrepare => Some(PbftStage::PrePreparing),
            PbftMulticastType::Prepare => Some(PbftStage::Preparing),
            PbftMulticastType::Commit => Some(PbftStage::Committing),
            PbftMulticastType::CommitFinal => Some(PbftStage::FinalCommitting),
            _ => None
        };

        if let Some(stage) = corresponding_stage {
            stage == self.stage
        } else {
            warn!("Didn't find a PbftStage corresponding to {:?}", msg_type);
            false
        }
    }

    // Tells what kind of message we're supposed to be sending right now
    fn _sending_message_type(&self) -> PbftMulticastType {
        match self.stage {
            PbftStage::PrePreparing => PbftMulticastType::PrePrepare,
            PbftStage::Preparing => PbftMulticastType::Prepare,
            PbftStage::Committing => PbftMulticastType::Commit,
            PbftStage::FinalCommitting => PbftMulticastType::CommitFinal,
            _ => PbftMulticastType::Unset,
        }
    }

    // Obtain the node ID (u64) from a PeerId
    fn _get_node_id(&self, peer_id: PeerId) -> u64 {
        let matching_node_ids: Vec<u64> = self.network_node_ids
            .iter()
            .filter(|(_node_id, network_peer_id)| *network_peer_id == &peer_id)
            .map(|(node_id, _network_peer_id)| *node_id)
            .collect();

        assert_eq!(matching_node_ids.len(), 1);

        matching_node_ids[0]
    }

    fn _broadcast_pbft_message(
        &mut self,
        msg_type: PbftMulticastType,
        view: u64,
        seq_num: u64,
        block: PbftBlock
    ) {
        // Make sure that we should be sending messages of this type
        if msg_type != self._sending_message_type() {
            debug!("{}: xxxxxx {:?} not sending", self, msg_type);
            return;
        }

        let msg_bytes = make_msg_bytes(make_msg_info(&msg_type, view, seq_num), block);

        // TODO: self.stage should probably have a mutex around it.
        // Broadcast to peers
        self.service.broadcast(String::from(&msg_type).as_str(), msg_bytes.clone())
            .unwrap_or_else(|err| error!("Couldn't broadcast: {}", err));
        debug!("{}: >>>>>> {:?}", self, msg_type);

        // Send to self
        let peer_msg = PeerMessage {
            message_type: String::from(&msg_type),
            content: msg_bytes.clone(),
        };
        debug!("{}: >self> {:?}", self, msg_type);
        self.on_peer_message(peer_msg);
    }

}

// TODO: break these out into better places
fn make_msg_info(msg_type: &PbftMulticastType, view: u64, seq_num: u64) -> PbftMessageInfo {
    let mut info = PbftMessageInfo::new();
    info.set_msg_type(String::from(msg_type));
    info.set_view(view);
    info.set_seq_num(seq_num);
    info
}

fn make_msg_bytes(info: PbftMessageInfo, block: PbftBlock) -> Vec<u8> {
    let mut msg = PbftMessage::new();
    msg.set_info(info);
    msg.set_block(block);

    msg.write_to_bytes().unwrap_or_else(|err| {
        panic!("Couldn't serialize commit message: {}", err);
    })
}

fn pbft_block_from_block(block: Block) -> PbftBlock {
    let mut pbft_block = PbftBlock::new();
    pbft_block.set_block_id(Vec::<u8>::from(block.block_id));
    pbft_block.set_signer_id(Vec::<u8>::from(block.signer_id));
    pbft_block.set_block_num(block.block_num);
    pbft_block
}
