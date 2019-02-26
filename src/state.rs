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

//! Information about a PBFT node's state

use std::fmt;
use std::time::Duration;

use sawtooth_sdk::consensus::engine::PeerId;

use crate::config::PbftConfig;
use crate::timing::Timeout;

/// Phases of the PBFT algorithm, in `Normal` mode
#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum PbftPhase {
    PrePreparing,
    Preparing,
    Committing,
    // Node is waiting for a BlockCommit (bool indicates if it's a catch-up commit)
    Finishing(bool),
}

impl fmt::Display for PbftPhase {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PbftPhase::PrePreparing => "PrePreparing".into(),
                PbftPhase::Preparing => "Preparing".into(),
                PbftPhase::Committing => "Committing".into(),
                PbftPhase::Finishing(cu) => format!("Finishing {}", cu),
            },
        )
    }
}

/// Modes that the PBFT algorithm can possibly be in
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum PbftMode {
    Normal,
    /// Contains the view number of the view this node is attempting to change to
    ViewChanging(u64),
}

impl fmt::Display for PbftState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let is_primary = if self.is_primary() { " *" } else { "" };
        let phase = if let PbftMode::ViewChanging(v) = self.mode {
            format!("V({})", v)
        } else {
            match self.phase {
                PbftPhase::PrePreparing => "PP".into(),
                PbftPhase::Preparing => "Pr".into(),
                PbftPhase::Committing => "Co".into(),
                PbftPhase::Finishing(cu) => format!("Fi({})", cu),
            }
        };
        write!(
            f,
            "({}, view {}, seq {}{})",
            phase, self.view, self.seq_num, is_primary,
        )
    }
}

/// Information about the PBFT algorithm's state
#[derive(Debug, Serialize, Deserialize)]
pub struct PbftState {
    /// This node's ID
    pub id: PeerId,

    /// The node's current sequence number
    pub seq_num: u64,

    /// The current view
    pub view: u64,

    /// Current phase of the algorithm
    pub phase: PbftPhase,

    /// Normal operation or view changing
    pub mode: PbftMode,

    /// Map of peers in the network, including ourselves
    pub peer_ids: Vec<PeerId>,

    /// The maximum number of faulty nodes in the network
    pub f: u64,

    /// Timer used to make sure the primary publishes blocks in a timely manner. If not, then this
    /// node will initiate a view change.
    pub faulty_primary_timeout: Timeout,

    /// Timer used to make sure the network doesn't get stuck if it fails to commit a block in a
    /// reasonable amount of time. If it doesn't commit a block in time, this node will initiate a
    /// view change when the timer expires.
    pub commit_timeout: Timeout,

    /// When view changing, timer is used to make sure a valid NewView message is sent by the new
    /// primary in a timely manner. If not, this node will start a different view change.
    pub view_change_timeout: Timeout,

    /// The duration of the view change timeout; when a view change is initiated for view v + 1,
    /// the timeout will be equal to the `view_change_duration`; if the timeout expires and the
    /// node starts a change to view v + 2, the timeout will be `2 * view_change_duration`; etc.
    pub view_change_duration: Duration,

    /// The base time to use for retrying with exponential backoff
    pub exponential_retry_base: Duration,

    /// The maximum time for retrying with exponential backoff
    pub exponential_retry_max: Duration,

    /// How many blocks to commit before forcing a view change for fairness
    pub forced_view_change_period: u64,
}

impl PbftState {
    /// Construct the initial state for a PBFT node
    ///
    /// # Panics
    /// + If the network this node is on does not have enough nodes to be Byzantine fault tolernant
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(id: PeerId, head_block_num: u64, config: &PbftConfig) -> Self {
        // Maximum number of faulty nodes in this network. Panic if there are not enough nodes.
        let f = ((config.peers.len() - 1) / 3) as u64;
        if f == 0 {
            panic!("This network does not contain enough nodes to be fault tolerant");
        }

        PbftState {
            id,
            seq_num: head_block_num + 1,
            view: 0,
            phase: PbftPhase::PrePreparing,
            mode: PbftMode::Normal,
            f,
            peer_ids: config.peers.clone(),
            faulty_primary_timeout: Timeout::new(config.faulty_primary_timeout),
            commit_timeout: Timeout::new(config.commit_timeout),
            view_change_timeout: Timeout::new(config.view_change_duration),
            view_change_duration: config.view_change_duration,
            exponential_retry_base: config.exponential_retry_base,
            exponential_retry_max: config.exponential_retry_max,
            forced_view_change_period: config.forced_view_change_period,
        }
    }

    /// Obtain the ID for the primary node in the network
    pub fn get_primary_id(&self) -> PeerId {
        let primary_index = (self.view as usize) % self.peer_ids.len();
        self.peer_ids[primary_index].clone()
    }

    /// Obtain the ID for the primary node at the specified view
    pub fn get_primary_id_at_view(&self, view: u64) -> PeerId {
        let primary_index = (view as usize) % self.peer_ids.len();
        self.peer_ids[primary_index].clone()
    }

    /// Tell if this node is currently the primary
    pub fn is_primary(&self) -> bool {
        self.id == self.get_primary_id()
    }

    /// Tell if this node is the primary at the specified view
    pub fn is_primary_at_view(&self, view: u64) -> bool {
        self.id == self.get_primary_id_at_view(view)
    }

    pub fn at_forced_view_change(&self) -> bool {
        self.seq_num % self.forced_view_change_period == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::mock_config;

    /// Check that state responds to having an inadequately sized network
    #[test]
    fn no_fault_tolerance() {
        let config = mock_config(1);
        let caught = ::std::panic::catch_unwind(|| {
            PbftState::new(vec![0], 0, &config);
        })
        .is_err();
        assert!(caught);
    }

    /// Check that the initial configuration of state is as we expect:
    /// + Primary is node 0, secondaries are other nodes
    /// + The node is not expecting any particular message type
    /// + `peer_ids` got set properly
    /// + The node's own PeerId got set properly
    /// + The primary PeerId got se properly
    #[test]
    fn initial_config() {
        let config = mock_config(4);
        let state0 = PbftState::new(vec![0], 0, &config);
        let state1 = PbftState::new(vec![], 0, &config);

        assert!(state0.is_primary());
        assert!(!state1.is_primary());

        assert_eq!(state0.f, 1);
        assert_eq!(state1.f, 1);

        assert_eq!(state0.get_primary_id(), state0.peer_ids[0]);
        assert_eq!(state1.get_primary_id(), state1.peer_ids[0]);
    }
}
