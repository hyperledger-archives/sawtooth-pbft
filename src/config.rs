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

use sawtooth_sdk::consensus::{engine::{BlockId, PeerId}, service::Service};

#[derive(Debug)]
pub struct PbftConfig {
    pub peers: HashMap<PeerId, u64>,
}

impl PbftConfig {
    pub fn default() -> Self {
        PbftConfig {
            peers: HashMap::new(),
        }
    }
}

pub fn load_pbft_config(node_id: u64, block_id: BlockId, service: &mut Box<Service>) -> PbftConfig {
    let mut config = PbftConfig::default();

    let sawtooth_settings: HashMap<String, String> = service
        .get_settings(block_id, vec!["sawtooth.consensus.pbft.peers".into()])
        .expect("Failed to get on-chain settings");

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

    let ids: Vec<u64> = peers.values().cloned().collect();

    config.peers = peers;

    config
}
