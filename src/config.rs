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

use sawtooth_sdk::consensus::{
    engine::{BlockId, PeerId},
    service::Service,
};

use crate::timing::retry_until_ok;

/// Contains the initial configuration loaded from on-chain settings and local configuration. The
/// `members` list is required; all other settings are optional (defaults used in their absence)
#[derive(Debug)]
pub struct PbftConfig {
    // Members of the PBFT network
    pub members: Vec<PeerId>,

    /// How long to wait in between trying to publish blocks
    pub block_publishing_delay: Duration,

    /// How long to wait for an update to arrive from the validator
    pub update_recv_timeout: Duration,

    /// The base time to use for retrying with exponential backoff
    pub exponential_retry_base: Duration,

    /// The maximum time for retrying with exponential backoff
    pub exponential_retry_max: Duration,

    /// How long to wait for the next BlockNew + PrePrepare before determining primary is faulty
    /// Must be longer than block_publishing_delay
    pub idle_timeout: Duration,

    /// How long to wait (after Pre-Preparing) for the node to commit the block before starting a
    /// view change (guarantees liveness by allowing the network to get "unstuck" if it is unable
    /// to commit a block)
    pub commit_timeout: Duration,

    /// When view changing, how long to wait for a valid NewView message before starting a
    /// different view change
    pub view_change_duration: Duration,

    /// How many blocks to commit before forcing a view change for fairness
    pub forced_view_change_interval: u64,

    /// How large the PbftLog is allowed to get before being pruned
    pub max_log_size: u64,

    /// Where to store PbftState ("memory" or "disk+/path/to/file")
    pub storage_location: String,
}

impl PbftConfig {
    pub fn default() -> Self {
        PbftConfig {
            members: Vec::new(),
            block_publishing_delay: Duration::from_millis(1000),
            update_recv_timeout: Duration::from_millis(10),
            exponential_retry_base: Duration::from_millis(100),
            exponential_retry_max: Duration::from_millis(60000),
            idle_timeout: Duration::from_millis(30000),
            commit_timeout: Duration::from_millis(10000),
            view_change_duration: Duration::from_millis(5000),
            forced_view_change_interval: 100,
            max_log_size: 10000,
            storage_location: "memory".into(),
        }
    }

    /// Load configuration from on-chain Sawtooth settings.
    ///
    /// Configuration loads the following settings:
    /// + `sawtooth.consensus.pbft.members` (required)
    /// + `sawtooth.consensus.pbft.block_publishing_delay` (optional, default 1000 ms)
    /// + `sawtooth.consensus.pbft.idle_timeout` (optional, default 30000 ms)
    /// + `sawtooth.consensus.pbft.commit_timeout` (optional, default 10000 ms)
    /// + `sawtooth.consensus.pbft.view_change_duration` (optional, default 5000 ms)
    /// + `sawtooth.consensus.pbft.forced_view_change_interval` (optional, default 100 blocks)
    ///
    /// # Panics
    /// + If block publishing delay is greater than the idle timeout
    /// + If the `sawtooth.consensus.pbft.members` setting is not provided or is invalid
    pub fn load_settings(&mut self, block_id: BlockId, service: &mut dyn Service) {
        debug!("Getting on-chain settings for config");
        let settings: HashMap<String, String> = retry_until_ok(
            self.exponential_retry_base,
            self.exponential_retry_max,
            || {
                service.get_settings(
                    block_id.clone(),
                    vec![
                        String::from("sawtooth.consensus.pbft.members"),
                        String::from("sawtooth.consensus.pbft.block_publishing_delay"),
                        String::from("sawtooth.consensus.pbft.idle_timeout"),
                        String::from("sawtooth.consensus.pbft.commit_timeout"),
                        String::from("sawtooth.consensus.pbft.view_change_duration"),
                        String::from("sawtooth.consensus.pbft.forced_view_change_interval"),
                    ],
                )
            },
        );

        // Get the on-chain list of PBFT members or panic if it is not provided; the network cannot
        // function without this setting, since there is no way of knowing which nodes are members.
        self.members = get_members_from_settings(&settings);

        // Get durations
        merge_millis_setting_if_set(
            &settings,
            &mut self.block_publishing_delay,
            "sawtooth.consensus.pbft.block_publishing_delay",
        );
        merge_millis_setting_if_set(
            &settings,
            &mut self.idle_timeout,
            "sawtooth.consensus.pbft.idle_timeout",
        );
        merge_millis_setting_if_set(
            &settings,
            &mut self.commit_timeout,
            "sawtooth.consensus.pbft.commit_timeout",
        );
        merge_millis_setting_if_set(
            &settings,
            &mut self.view_change_duration,
            "sawtooth.consensus.pbft.view_change_duration",
        );

        // Check to make sure block_publishing_delay < idle_timeout
        if self.block_publishing_delay >= self.idle_timeout {
            panic!(
                "Block publishing delay ({:?}) must be less than the idle timeout ({:?})",
                self.block_publishing_delay, self.idle_timeout
            );
        }

        // Get integer constants
        merge_setting_if_set(
            &settings,
            &mut self.forced_view_change_interval,
            "sawtooth.consensus.pbft.forced_view_change_interval",
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

/// Get the list of PBFT members as a Vec<PeerId> from settings
///
/// # Panics
/// + If the `sawtooth.consenus.pbft.members` setting is unset or invalid
pub fn get_members_from_settings<S: std::hash::BuildHasher>(
    settings: &HashMap<String, String, S>,
) -> Vec<PeerId> {
    let members_setting_value = settings
        .get("sawtooth.consensus.pbft.members")
        .expect("'sawtooth.consensus.pbft.members' is empty; this setting must exist to use PBFT");

    let members: Vec<String> = serde_json::from_str(members_setting_value).unwrap_or_else(|err| {
        panic!(
            "Unable to parse value at 'sawtooth.consensus.pbft.members' due to error: {:?}",
            err
        )
    });

    members
        .into_iter()
        .map(|s| {
            hex::decode(s).unwrap_or_else(|err| {
                panic!("Unable to parse PeerId from string due to error: {:?}", err)
            })
        })
        .collect()
}
