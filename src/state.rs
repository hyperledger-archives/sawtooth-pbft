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

use hex;
use sawtooth_sdk::consensus::engine::PeerId;

use crate::config::PbftConfig;
use crate::error::PbftError;
use crate::message_type::PbftMessageType;
use crate::protos::pbft_message::PbftBlock;
use crate::timing::Timeout;

/// Phases of the PBFT algorithm, in `Normal` mode
#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum PbftPhase {
    PrePreparing,
    Checking,
    Preparing,
    Committing,
    Finished,
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
        let ast = if self.is_primary() { "*" } else { " " };
        let mode = match self.mode {
            PbftMode::Normal => String::from("N"),
            PbftMode::ViewChanging(v) => format!("V{}", v),
        };

        let phase = match self.phase {
            PbftPhase::PrePreparing => "PP",
            PbftPhase::Checking => "Ch",
            PbftPhase::Preparing => "Pr",
            PbftPhase::Committing => "Co",
            PbftPhase::Finished => "Fi",
        };

        let wb = match self.working_block {
            Some(ref block) => format!(
                "{}/{}",
                block.block_num,
                &hex::encode(block.get_block_id())[..6]
            ),
            None => String::from("~none~"),
        };

        write!(
            f,
            "({} {} {}, seq {}, wb {}), Node {}{}",
            phase,
            mode,
            self.view,
            self.seq_num,
            wb,
            ast,
            &hex::encode(self.id.clone())[..6],
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

    /// When view changing, timer is used to make sure a valid NewView message is sent by the new
    /// primary in a timely manner. If not, this node will start a different view change.
    pub view_change_timeout: Timeout,

    /// The duration of the view change timeout; when a view change is initiated for view v + 1,
    /// the timeout will be equal to the `view_change_duration`; if the timeout expires and the
    /// node starts a change to view v + 2, the timeout will be `2 * view_change_duration`; etc.
    pub view_change_duration: Duration,

    /// How many blocks to commit before forcing a view change for fairness
    pub forced_view_change_period: u64,

    /// The current block this node is working on
    pub working_block: Option<PbftBlock>,
}

impl PbftState {
    /// Construct the initial state for a PBFT node
    /// # Panics
    /// Panics if the network this node is on does not have enough nodes to be Byzantine fault
    /// tolernant.
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
            view_change_timeout: Timeout::new(config.view_change_duration),
            view_change_duration: config.view_change_duration,
            forced_view_change_period: config.forced_view_change_period,
            working_block: None,
        }
    }

    /// Check to see what type of message this node is expecting or sending, based on the current
    /// phase
    pub fn check_msg_type(&self) -> PbftMessageType {
        match self.phase {
            PbftPhase::PrePreparing => PbftMessageType::PrePrepare,
            PbftPhase::Checking => PbftMessageType::Prepare,
            PbftPhase::Preparing => PbftMessageType::Prepare,
            PbftPhase::Committing => PbftMessageType::Commit,
            PbftPhase::Finished => PbftMessageType::Unset,
        }
    }

    /// Obtain the ID for the primary node in the network
    pub fn get_primary_id(&self) -> PeerId {
        let primary_index = (self.view % (self.peer_ids.len() as u64)) as usize;
        self.peer_ids[primary_index].clone()
    }

    /// Obtain the ID for the primary node at the specified view
    pub fn get_primary_id_at_view(&self, view: u64) -> PeerId {
        let primary_index = (view % (self.peer_ids.len() as u64)) as usize;
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

    /// Switch to the desired phase if it is the next phase of the algorithm; if it is not the next
    /// phase, return an error
    pub fn switch_phase(&mut self, desired_phase: PbftPhase) -> Result<(), PbftError> {
        let next = match self.phase {
            PbftPhase::PrePreparing => PbftPhase::Checking,
            PbftPhase::Checking => PbftPhase::Preparing,
            PbftPhase::Preparing => PbftPhase::Committing,
            PbftPhase::Committing => PbftPhase::Finished,
            PbftPhase::Finished => PbftPhase::PrePreparing,
        };
        if desired_phase == next {
            debug!("{}: Changing to {:?}", self, desired_phase);
            self.phase = desired_phase;
            Ok(())
        } else {
            Err(PbftError::InternalError(format!(
                "Node is in {:?} phase; attempted to switch to {:?}",
                self.phase, desired_phase
            )))
        }
    }

    pub fn at_forced_view_change(&self) -> bool {
        self.seq_num > 0 && self.seq_num % self.forced_view_change_period == 0
    }

    /// Reset the phase and mode, restart the timers; used after a view change has occured
    pub fn reset_to_start(&mut self) {
        info!("Resetting state: {}", self);
        self.phase = PbftPhase::PrePreparing;
        self.mode = PbftMode::Normal;
        self.faulty_primary_timeout.start();
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

        assert_eq!(state0.check_msg_type(), PbftMessageType::PrePrepare);
        assert_eq!(state1.check_msg_type(), PbftMessageType::PrePrepare);

        assert_eq!(state0.get_primary_id(), state0.peer_ids[0]);
        assert_eq!(state1.get_primary_id(), state1.peer_ids[0]);
    }

    /// Make sure that a normal PBFT cycle works properly
    /// `PrePreparing` => `Checking` => `Preparing` => `Committing` => `Finished` => `PrePreparing`
    /// and that invalid phase changes are detected
    #[test]
    fn valid_phase_changes() {
        let config = mock_config(4);
        let mut state = PbftState::new(vec![0], 0, &config);

        // Valid changes
        assert!(state.switch_phase(PbftPhase::Checking).is_ok());
        assert!(state.switch_phase(PbftPhase::Preparing).is_ok());
        assert!(state.switch_phase(PbftPhase::Committing).is_ok());
        assert!(state.switch_phase(PbftPhase::Finished).is_ok());
        assert!(state.switch_phase(PbftPhase::PrePreparing).is_ok());

        // Invalid changes
        assert!(state.switch_phase(PbftPhase::Committing).is_err());
        assert!(state.switch_phase(PbftPhase::Finished).is_err());
        assert!(state.switch_phase(PbftPhase::PrePreparing).is_err());
    }
}
