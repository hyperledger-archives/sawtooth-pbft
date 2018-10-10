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

//! Initial configuration for a PBFT node

use hex;
use serde_json;

use std::collections::HashMap;

use std::time::Duration;

use sawtooth_sdk::consensus::{
    engine::{BlockId, PeerId},
    service::Service,
};

/// Contains the initial configuration loaded from on-chain settings, if present, or defaults in
/// their absence.
#[derive(Debug)]
pub struct PbftConfig {
    // Peers that this node is connected to
    pub peers: Vec<PeerId>,

    /// How long to wait in between trying to publish blocks
    pub block_duration: Duration,

    /// How long to wait for a message to arrive
    pub message_timeout: Duration,

    /// How long to wait to initiate a ViewChange if we suspect the primary's faulty
    /// Should be longer than block_duration
    pub view_change_timeout: Duration,

    /// How many requests in between each checkpoint
    pub checkpoint_period: u64,

    /// How large the PbftLog is allowed to get
    pub max_log_size: u64,
}

impl PbftConfig {
    pub fn default() -> Self {
        PbftConfig {
            peers: Vec::new(),
            block_duration: Duration::from_millis(200),
            message_timeout: Duration::from_millis(10),
            view_change_timeout: Duration::from_millis(4000),
            checkpoint_period: 100,
            max_log_size: 1000,
        }
    }
}

/// Load configuration from on-chain Sawtooth settings.
///
/// Configuration loads the following settings:
/// + `sawtooth.consensus.pbft.peers` (required)
/// + `sawtooth.consensus.pbft.block_duration` (optional, default 200 ms)
/// + `sawtooth.consensus.pbft.checkpoint_period` (optional, default 10 ms)
/// + `sawtooth.consensus.pbft.view_change_timeout` (optional, default 4000 ms)
/// + `sawtooth.consensus.pbft.message_timeout` (optional, default 100 blocks)
/// + `sawtooth.consensus.pbft.max_log_size` (optional, default 1000 messages)
///
/// # Panics
/// + If the `sawtooth.consensus.pbft.peers` setting is not provided
/// + If settings loading fails entirely
/// + If block duration is greater than the view change timeout
pub fn load_pbft_config(block_id: BlockId, service: &mut Service) -> PbftConfig {
    let mut config = PbftConfig::default();

    let settings: HashMap<String, String> = service
        .get_settings(
            block_id,
            vec![
                String::from("sawtooth.consensus.pbft.peers"),
                String::from("sawtooth.consensus.pbft.block_duration"),
                String::from("sawtooth.consensus.pbft.checkpoint_period"),
                String::from("sawtooth.consensus.pbft.view_change_timeout"),
                String::from("sawtooth.consensus.pbft.message_timeout"),
                String::from("sawtooth.consensus.pbft.max_log_size"),
            ],
        ).expect("Failed to get on-chain settings");

    // Get the peers associated with this node (including ourselves). Panic if it is not provided;
    // the network cannot function without this setting.
    let peers_string = settings
        .get("sawtooth.consensus.pbft.peers")
        .expect("'sawtooth.consensus.pbft.peers' must be set");

    let peers: Vec<String> = serde_json::from_str(peers_string)
        .expect("Invalid value in 'sawtooth.consensus.pbft.peers'");

    let peers: Vec<PeerId> = peers
        .into_iter()
        .map(|s| PeerId::from(hex::decode(s).expect("PeerId is not valid hex")))
        .collect();

    config.peers = peers;

    // Get various durations
    merge_millis_setting_if_set(
        &settings,
        &mut config.block_duration,
        "sawtooth.consensus.pbft.block_duration",
    );
    merge_millis_setting_if_set(
        &settings,
        &mut config.message_timeout,
        "sawtooth.consensus.pbft.message_timeout",
    );
    merge_millis_setting_if_set(
        &settings,
        &mut config.view_change_timeout,
        "sawtooth.consensus.pbft.view_change_timeout",
    );

    // Check to make sure block_duration < view_change_timeout
    if config.block_duration >= config.view_change_timeout {
        panic!("Block duration must be less than the view change timeout");
    }

    // Get various integer constants
    merge_setting_if_set(
        &settings,
        &mut config.checkpoint_period,
        "sawtooth.consensus.pbft.checkpoint_period",
    );
    merge_setting_if_set(
        &settings,
        &mut config.max_log_size,
        "sawtooth.consensus.pbft.max_log_size",
    );

    config
}

fn merge_setting_if_set<T: ::std::str::FromStr>(
    settings_map: &HashMap<String, String>,
    setting_field: &mut T,
    setting_key: &str,
) {
    merge_setting_if_set_and_map(settings_map, setting_field, setting_key, |setting| setting)
}

fn merge_setting_if_set_and_map<U, F, T>(
    settings_map: &HashMap<String, String>,
    setting_field: &mut U,
    setting_key: &str,
    map: F,
) where
    F: Fn(T) -> U,
    T: ::std::str::FromStr,
{
    if let Some(setting) = settings_map.get(setting_key) {
        if let Ok(setting_value) = setting.parse() {
            *setting_field = map(setting_value);
        }
    }
}

fn merge_millis_setting_if_set(
    settings_map: &HashMap<String, String>,
    setting_field: &mut Duration,
    setting_key: &str,
) {
    merge_setting_if_set_and_map(
        settings_map,
        setting_field,
        setting_key,
        Duration::from_millis,
    )
}

/// Create a mock configuration, given a number of nodes. PeerIds are generated using a Sha256
/// hash.
#[cfg(test)]
pub fn mock_config(num_nodes: usize) -> PbftConfig {
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;

    let mut ids = Vec::new();
    for i in 0..num_nodes {
        let mut sha = Sha256::new();
        sha.input_str(format!("I'm a node with ID {}", i).as_str());
        ids.push(PeerId::from(sha.result_str().as_bytes().to_vec()));
    }

    let mut config = PbftConfig::default();
    config.peers = ids;
    config
}
