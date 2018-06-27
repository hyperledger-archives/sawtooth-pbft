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

use std::collections::HashMap;

use sawtooth_sdk::consensus::engine::PeerId;

use message_type::PbftMessageType;

// Possible roles for a node
// Primary is in charge of making consensus decisions
#[derive(PartialEq)]
enum PbftNodeRole {
    Primary,
    Secondary,
}

// Stages of the PBFT algorithm
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub enum PbftPhase {
    NotStarted,
    PrePreparing,
    Preparing,
    Checking,
    Committing,
    FinalCommitting,
    Finished,
}

// Information about the PBFT algorithm's state
pub struct PbftState {
    // This node's ID
    pub id: u64,

    // The node's current sequence number
    // Always starts at 0; representative of an unknown sequence number.
    pub seq_num: u64,

    // The current view (where the primary's ID is p = v mod network_node_ids.len())
    pub view: u64,

    // Current phase of the algorithm
    pub phase: PbftPhase,

    // Is this node primary or secondary?
    role: PbftNodeRole,

    // Map of peers in the network, including ourselves
    network_node_ids: HashMap<u64, PeerId>,

    // The maximum number of faulty nodes in the network
    pub f: u64,
}

impl PbftState {
    pub fn new(id: u64, peers: HashMap<PeerId, u64>) -> Self {
        let peer_id_map: HashMap<u64, PeerId> = peers
            .clone()
            .into_iter()
            .map(|(peer_id, node_id)| (node_id, peer_id))
            .collect();

        // TODO: update this to reflect view
        let current_primary = peers
            .iter()
            .map(|(_peer_id, node_id)| node_id)
            .min()
            .unwrap_or(&1);

        PbftState {
            id: id,
            seq_num: 0, // Default to unknown
            view: 1,
            phase: PbftPhase::NotStarted,
            role: if &id == current_primary {
                PbftNodeRole::Primary
            } else {
                PbftNodeRole::Secondary
            },
            f: ((peer_id_map.len() - 1) / 3) as u64,
            network_node_ids: peer_id_map,
        }
    }

    // Checks to see what type of message we're expecting or sending, based on what phase we're in
    pub fn check_msg_type(&self) -> PbftMessageType {
        match self.phase {
            PbftPhase::PrePreparing => PbftMessageType::PrePrepare,
            PbftPhase::Preparing => PbftMessageType::Prepare,
            PbftPhase::Committing => PbftMessageType::Commit,
            PbftPhase::FinalCommitting => PbftMessageType::CommitFinal,
            _ => PbftMessageType::Unset,
        }
    }

    // Obtain the node ID from a serialized PeerId
    pub fn get_node_id_from_bytes(&self, peer_id: &[u8]) -> u64 {
        let deser_id = PeerId::from(peer_id.to_vec());

        let matching_node_ids: Vec<u64> = self.network_node_ids
            .iter()
            .filter(|(_node_id, network_peer_id)| *network_peer_id == &deser_id)
            .map(|(node_id, _network_peer_id)| *node_id)
            .collect();

        assert_eq!(matching_node_ids.len(), 1);

        matching_node_ids[0]
    }

    pub fn get_own_peer_id(&self) -> PeerId {
        self.network_node_ids[&self.id].clone()
    }

    // Tell if this node is currently a primary
    pub fn is_primary(&self) -> bool {
        self.role == PbftNodeRole::Primary
    }

    // Go to the next phase and return the phase we're at now
    pub fn advance_phase(&mut self) -> PbftPhase {
        let next = match self.phase {
            PbftPhase::NotStarted => PbftPhase::PrePreparing,
            PbftPhase::PrePreparing => PbftPhase::Preparing,
            PbftPhase::Preparing => PbftPhase::Checking,
            PbftPhase::Checking => PbftPhase::Committing,
            PbftPhase::Committing => PbftPhase::FinalCommitting,
            PbftPhase::FinalCommitting => PbftPhase::Finished,
            PbftPhase::Finished => PbftPhase::NotStarted,
        };
        self.phase = next.clone();
        next
    }
}
