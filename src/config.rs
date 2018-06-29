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
use serde_json;

use std::collections::HashMap;

use std::time::Duration;

use sawtooth_sdk::consensus::{engine::{BlockId, PeerId}, service::Service};

#[derive(Debug)]
pub struct PbftConfig {
    // Peers that this node is connected to
    pub peers: HashMap<PeerId, u64>,

    // How long to wait in between trying to publish blocks
    pub block_duration: Duration,

    // How long to wait for a message to arrive
    pub message_timeout: Duration,

    // How many requests in between each checkpoint
    pub checkpoint_period: u64,

    // How large the PbftLog is allowed to get
    pub max_log_size: u64,
}

impl PbftConfig {
    pub fn default() -> Self {
        PbftConfig {
            peers: HashMap::new(),
            block_duration: Duration::from_millis(2000),
            message_timeout: Duration::from_millis(10),
            checkpoint_period: 100,
            max_log_size: 1000,
        }
    }
}

pub fn load_pbft_config(block_id: BlockId, service: &mut Box<Service>) -> PbftConfig {
    let mut config = PbftConfig::default();

    let sawtooth_settings: HashMap<String, String> = service
        .get_settings(
            block_id,
            vec![
                String::from("sawtooth.consensus.pbft.peers"),
                String::from("sawtooth.consensus.pbft.block_duration"),
                String::from("sawtooth.consensus.pbft.checkpoint_period"),
                String::from("sawtooth.consensus.pbft.message_timeout"),
                String::from("sawtooth.consensus.pbft.max_log_size"),
            ],
        )
        .expect("Failed to get on-chain settings");

    // Get the peers associated with this node (including ourselves)
    let peers_string = sawtooth_settings
        .get("sawtooth.consensus.pbft.peers")
        .expect("'sawtooth.consensus.pbft.peers' must be set");

    let peers: HashMap<String, u64> = serde_json::from_str(peers_string)
        .expect("Invalid value in 'sawtooth.consensus.pbft.peers'");

    let peers: HashMap<PeerId, u64> = peers
        .into_iter()
        .map(|(s, id)| {
            (
                PeerId::from(hex::decode(s).expect("PeerId is not valid hex")),
                id,
            )
        })
        .collect();

    config.peers = peers;

    // Get various durations
    if let Some(s) = sawtooth_settings.get("sawtooth.consensus.pbft.block_duration") {
        if let Ok(block_duration) = s.parse() {
            config.block_duration = Duration::from_millis(block_duration);
        }
    }
    if let Some(s) = sawtooth_settings.get("sawtooth.consensus.pbft.message_timeout") {
        if let Ok(message_timeout) = s.parse() {
            config.message_timeout = Duration::from_millis(message_timeout);
        }
    }

    // Get various integer constants
    if let Some(s) = sawtooth_settings.get("sawtooth.consensus.pbft.checkpoint_period") {
        if let Ok(checkpoint_period) = s.parse() {
            config.checkpoint_period = checkpoint_period;
        }
    }
    if let Some(s) = sawtooth_settings.get("sawtooth.consensus.pbft.max_log_size") {
        if let Ok(max_log_size) = s.parse() {
            config.max_log_size = max_log_size;
        }
    }

    config
}
