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

use std::collections::HashMap;
use std::time::Duration;

use hex;
use sawtooth_sdk::consensus::{
    engine::{BlockId, PeerId},
    service::Service,
};
use serde_json;

use crate::timing::retry_until_ok;

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

    /// The base time to use for retrying with exponential backoff
    pub exponential_retry_base: Duration,

    /// The maximum time for retrying with exponential backoff
    pub exponential_retry_max: Duration,

    /// How long to wait for the next BlockNew + PrePrepare before determining primary is faulty
    /// Should be longer than block_duration
    pub faulty_primary_timeout: Duration,

    /// How long to wait (after Pre-Preparing) for the node to commit the block before starting a
    /// view change (guarantees liveness by allowing the network to get "unstuck" if something goes
    // wrong)
    pub commit_timeout: Duration,

    /// When view changing, how long to wait for a valid NewView message before starting a
    /// different view change
    pub view_change_duration: Duration,

    /// How many blocks to commit before forcing a view change for fairness
    pub forced_view_change_period: u64,

    /// How large the PbftLog is allowed to get
    pub max_log_size: u64,

    /// Where to store PbftState
    pub storage: String,
}

impl PbftConfig {
    pub fn default() -> Self {
        PbftConfig {
            peers: Vec::new(),
            block_duration: Duration::from_millis(200),
            message_timeout: Duration::from_millis(10),
            exponential_retry_base: Duration::from_millis(100),
            exponential_retry_max: Duration::from_secs(60),
            faulty_primary_timeout: Duration::from_secs(30),
            commit_timeout: Duration::from_secs(30),
            view_change_duration: Duration::from_secs(5),
            forced_view_change_period: 30,
            max_log_size: 1000,
            storage: "memory".into(),
        }
    }

    /// Load configuration from on-chain Sawtooth settings.
    ///
    /// Configuration loads the following settings:
    /// + `sawtooth.consensus.pbft.peers` (required)
    /// + `sawtooth.consensus.pbft.block_duration` (optional, default 200 ms)
    /// + `sawtooth.consensus.pbft.faulty_primary_timeout` (optional, default 30s)
    /// + `sawtooth.consensus.pbft.commit_timeout` (optional, default 30s)
    /// + `sawtooth.consensus.pbft.view_change_duration` (optional, default 5s)
    /// + `sawtooth.consensus.pbft.forced_view_change_period` (optional, default 30 blocks)
    /// + `sawtooth.consensus.pbft.message_timeout` (optional, default 10 ms)
    /// + `sawtooth.consensus.pbft.max_log_size` (optional, default 1000 messages)
    /// + `sawtooth.consensus.pbft.storage` (optional, default `"memory"`)
    ///
    /// # Panics
    /// + If block duration is greater than the faulty primary timeout
    /// + If the `sawtooth.consensus.pbft.peers` setting is not provided or is invalid
    pub fn load_settings(&mut self, block_id: BlockId, service: &mut Service) {
        debug!("Getting on-chain settings for config");
        let settings: HashMap<String, String> = retry_until_ok(
            self.exponential_retry_base,
            self.exponential_retry_max,
            || {
                service.get_settings(
                    block_id.clone(),
                    vec![
                        String::from("sawtooth.consensus.pbft.peers"),
                        String::from("sawtooth.consensus.pbft.block_duration"),
                        String::from("sawtooth.consensus.pbft.faulty_primary_timeout"),
                        String::from("sawtooth.consensus.pbft.commit_timeout"),
                        String::from("sawtooth.consensus.pbft.view_change_duration"),
                        String::from("sawtooth.consensus.pbft.forced_view_change_period"),
                        String::from("sawtooth.consensus.pbft.message_timeout"),
                        String::from("sawtooth.consensus.pbft.max_log_size"),
                    ],
                )
            },
        );

        // Get the peers associated with this node (including ourselves). Panic if it is not provided;
        // the network cannot function without this setting.
        let peers = get_peers_from_settings(&settings);

        self.peers = peers;

        // Get various durations
        merge_millis_setting_if_set(
            &settings,
            &mut self.block_duration,
            "sawtooth.consensus.pbft.block_duration",
        );
        merge_millis_setting_if_set(
            &settings,
            &mut self.message_timeout,
            "sawtooth.consensus.pbft.message_timeout",
        );
        merge_secs_setting_if_set(
            &settings,
            &mut self.faulty_primary_timeout,
            "sawtooth.consensus.pbft.faulty_primary_timeout",
        );
        merge_secs_setting_if_set(
            &settings,
            &mut self.commit_timeout,
            "sawtooth.consensus.pbft.commit_timeout",
        );
        merge_secs_setting_if_set(
            &settings,
            &mut self.view_change_duration,
            "sawtooth.consensus.pbft.view_change_duration",
        );

        // Check to make sure block_duration < faulty_primary_timeout
        if self.block_duration >= self.faulty_primary_timeout {
            panic!(
                "Block duration ({:?}) must be less than the faulty primary timeout ({:?})",
                self.block_duration, self.faulty_primary_timeout
            );
        }

        // Get various integer constants
        merge_setting_if_set(
            &settings,
            &mut self.forced_view_change_period,
            "sawtooth.consensus.pbft.forced_view_change_period",
        );
        merge_setting_if_set(
            &settings,
            &mut self.max_log_size,
            "sawtooth.consensus.pbft.max_log_size",
        );
    }
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

fn merge_secs_setting_if_set(
    settings_map: &HashMap<String, String>,
    setting_field: &mut Duration,
    setting_key: &str,
) {
    merge_setting_if_set_and_map(
        settings_map,
        setting_field,
        setting_key,
        Duration::from_secs,
    )
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

/// Get the peers as a Vec<PeerId> from settings
///
/// # Panics
/// + If the `sawtooth.consenus.pbft.peers` setting is unset or invalid
pub fn get_peers_from_settings<S: std::hash::BuildHasher>(
    settings: &HashMap<String, String, S>,
) -> Vec<PeerId> {
    let peers_setting_value = settings
        .get("sawtooth.consensus.pbft.peers")
        .expect("'sawtooth.consensus.pbft.peers' is empty; this setting must exist to use PBFT");

    let peers: Vec<String> = serde_json::from_str(peers_setting_value).unwrap_or_else(|err| {
        panic!(
            "Unable to parse value at 'sawtooth.consensus.pbft.peers' due to error: {:?}",
            err
        )
    });

    peers
        .into_iter()
        .map(|s| {
            hex::decode(s).unwrap_or_else(|err| {
                panic!("Unable to parse PeerId from string due to error: {:?}", err)
            })
        })
        .collect()
}

/// Create a mock configuration, given a number of nodes. PeerIds are generated using a Sha256
/// hash.
#[cfg(test)]
pub fn mock_config(num_nodes: u64) -> PbftConfig {
    let mut config = PbftConfig::default();
    config.peers = (0..num_nodes).map(|id| vec![id as u8]).collect();
    config
}
