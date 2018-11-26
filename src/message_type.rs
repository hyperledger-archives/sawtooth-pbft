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

//! Message types for PeerMessages

#![allow(unknown_lints, derive_hash_xor_eq)]

use std::fmt;
use std::hash::{Hash, Hasher};

use hash::verify_sha512;
use protobuf::Message;
use sawtooth_sdk::consensus::engine::PeerMessage;

use error::PbftError;
use protos::pbft_message::{PbftBlock, PbftMessage, PbftMessageInfo, PbftViewChange};

/// Wrapper enum for all of the possible PBFT-related messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PbftMessageWrapper {
    Message(PbftMessage),
    ViewChange(PbftViewChange),
}

/// Container for a received PeerMessage and the PBFT message parsed from it
///
/// The bits of the `PeerMessage` struct that this carries around are used in
/// constructing the consensus seal.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedMessage {
    /// Serialized ConsensusPeerMessageHeader. Inserted into the consensus seal.
    pub header_bytes: Vec<u8>,

    /// Signature for `header_bytes`. Inserted into the consensus seal.
    pub header_signature: Vec<u8>,

    /// The parsed PBFT message.
    pub message: PbftMessageWrapper,

    /// The serialized PBFT message. Inserted into the consensus seal.
    pub message_bytes: Vec<u8>,

    /// Whether or not this message was self-constructed. Self-constructed messages
    /// are skipped during creationg of the consensus seal, since PBFT doesn't have
    /// access to the validator key necessary to create valid signed messages.
    pub from_self: bool,
}

impl Hash for ParsedMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.message {
            PbftMessageWrapper::Message(m) => m.hash(state),
            PbftMessageWrapper::ViewChange(m) => m.hash(state),
        }
    }
}

impl ParsedMessage {
    /// Constructs a `ParsedMessage` from the given `PbftMessage`.
    ///
    /// Does not add metadata necessary for adding this message to the consensus seal.
    pub fn from_pbft_message(message: PbftMessage) -> Self {
        Self {
            from_self: false,
            header_bytes: vec![],
            header_signature: vec![],
            message_bytes: message.write_to_bytes().unwrap(),
            message: PbftMessageWrapper::Message(message),
        }
    }

    /// Constructs a `ParsedMessage` from the given `PbftViewChange`.
    ///
    /// Does not add metadata necessary for adding this message to the consensus seal.
    pub fn from_view_change_message(message: PbftViewChange) -> Self {
        Self {
            from_self: false,
            header_bytes: vec![],
            header_signature: vec![],
            message_bytes: message.write_to_bytes().unwrap(),
            message: PbftMessageWrapper::ViewChange(message),
        }
    }

    pub fn info(&self) -> &PbftMessageInfo {
        match &self.message {
            PbftMessageWrapper::Message(m) => &m.get_info(),
            PbftMessageWrapper::ViewChange(m) => &m.get_info(),
        }
    }

    pub fn info_mut(&mut self) -> &mut PbftMessageInfo {
        match self.message {
            PbftMessageWrapper::Message(ref mut m) => m.mut_info(),
            PbftMessageWrapper::ViewChange(ref mut m) => m.mut_info(),
        }
    }

    /// Returns the `PbftBlock` for this message's wrapped `PbftMessage`.
    ///
    /// Panics if it encounters a view change message, as that should never happen.
    pub fn get_block(&self) -> &PbftBlock {
        match &self.message {
            PbftMessageWrapper::Message(m) => m.get_block(),
            PbftMessageWrapper::ViewChange(_) => {
                panic!("ParsedPeerMessage.get_block found a view change message!")
            }
        }
    }

    /// Returns the wrapped `PbftMessage`.
    ///
    /// Panics if it encounters a view change message, as that should never happen.
    pub fn get_pbft_message(&self) -> &PbftMessage {
        match &self.message {
            PbftMessageWrapper::Message(m) => m,
            PbftMessageWrapper::ViewChange(_) => {
                panic!("ParsedPeerMessage.get_pbft_message found a view change message!")
            }
        }
    }

    /// Returns the wrapped `PbftViewChange`.
    ///
    /// Panics if it encounters a view change message, as that should never happen.
    pub fn get_view_change_message(&self) -> &PbftViewChange {
        match &self.message {
            PbftMessageWrapper::Message(_) => {
                panic!("ParsedPeerMessage.get_view_change_message found a pbft message!")
            }
            PbftMessageWrapper::ViewChange(m) => m,
        }
    }

    /// Constructs a `ParsedMessage` from the given `PeerMessage`.
    ///
    /// Attempts to parse the message contents as either a `PbftMessage` or a `PbftViewChange`,
    /// and wraps that in an internal enum.
    pub fn from_peer_message(message: PeerMessage, from_self: bool) -> Result<Self, PbftError> {
        // Self-constructed messages aren't signed, since we don't have access to
        // the validator key necessary for signing them.
        if !from_self {
            verify_sha512(&message.content, &message.header.content_sha512)?;
        }
        // This complex parsing is due to the fact that proto3 doesn't have any way of requiring
        // fields, so a `PbftViewChange` can get parsed as a `PbftMessage` that doesn't have
        // the `block` field defined. So, we try parsing a PbftMessage first, and if that fails
        // or has a ViewChange message type, then try parsing it as a view change message, and
        // if that fails, then it's probably a bad message.
        let parsed_message = protobuf::parse_from_bytes::<PbftMessage>(&message.content)
            .ok()
            .and_then(|m| {
                if m.get_info().get_msg_type() == "ViewChange" {
                    None
                } else {
                    Some(PbftMessageWrapper::Message(m))
                }
            }).or_else(|| {
                protobuf::parse_from_bytes::<PbftViewChange>(&message.content)
                    .ok()
                    .and_then(|m| Some(PbftMessageWrapper::ViewChange(m)))
            }).ok_or_else(|| PbftError::InternalError("Couldn't parse message!".into()))?;

        Ok(Self {
            header_bytes: message.header_bytes,
            header_signature: message.header_signature,
            message: parsed_message,
            message_bytes: message.content.clone(),
            from_self,
        })
    }

    /// Constructs a `ParsedMessage` from the given serialized `PbftMessage`
    pub fn from_bytes(message: Vec<u8>) -> Result<Self, PbftError> {
        let peer_message = PeerMessage {
            content: message,
            ..Default::default()
        };

        Self::from_peer_message(peer_message, true)
    }

    /// Constructs a copy of this message with the given message type
    #[allow(needless_pass_by_value)]
    pub fn as_msg_type(&self, msg_type: PbftMessageType) -> ParsedMessage {
        let mut new_msg = self.get_pbft_message().clone();
        let mut info = new_msg.take_info();
        info.set_msg_type(String::from(&msg_type));
        new_msg.set_info(info);

        ParsedMessage {
            from_self: self.from_self,
            header_bytes: self.header_bytes.clone(),
            header_signature: self.header_signature.clone(),
            message: PbftMessageWrapper::Message(new_msg),
            message_bytes: self.message_bytes.clone(),
        }
    }
}

/// Enum for showing the difference between future messages, present messages, and past messages.
#[derive(Debug, PartialEq)]
pub enum PbftHint {
    /// A future message. The node is not ready to process it yet.
    FutureMessage,

    /// A past message. It's possible the node may still need it though, so it is added to the log.
    PastMessage,

    /// A present message. The node is ready to process this message immediately.
    PresentMessage,
}

// Messages related to PBFT consensus
#[derive(Debug, PartialEq, PartialOrd)]
pub enum PbftMessageType {
    /// Basic message types for the multicast protocol
    PrePrepare,
    Prepare,
    Commit,

    /// Auxiliary PBFT messages
    BlockNew,
    Checkpoint,
    ViewChange,

    Unset,
}

impl fmt::Display for PbftMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let txt = match self {
            PbftMessageType::PrePrepare => "PP",
            PbftMessageType::Prepare => "Pr",
            PbftMessageType::Commit => "Co",
            PbftMessageType::BlockNew => "BN",
            PbftMessageType::Checkpoint => "CP",
            PbftMessageType::ViewChange => "VC",
            PbftMessageType::Unset => "Un",
        };
        write!(f, "{}", txt)
    }
}

impl PbftMessageType {
    /// Is the message type a multicast message (`PrePrepare`, `Prepare`, or `Commit`)?
    pub fn is_multicast(&self) -> bool {
        match self {
            PbftMessageType::PrePrepare | PbftMessageType::Prepare | PbftMessageType::Commit => {
                true
            }
            _ => false,
        }
    }
}

impl<'a> From<&'a str> for PbftMessageType {
    fn from(s: &'a str) -> Self {
        match s {
            "PrePrepare" => PbftMessageType::PrePrepare,
            "Prepare" => PbftMessageType::Prepare,
            "Commit" => PbftMessageType::Commit,
            "BlockNew" => PbftMessageType::BlockNew,
            "ViewChange" => PbftMessageType::ViewChange,
            "Checkpoint" => PbftMessageType::Checkpoint,
            _ => {
                warn!("Unhandled PBFT message type: {}", s);
                PbftMessageType::Unset
            }
        }
    }
}

impl<'a> From<&'a PbftMessageType> for String {
    fn from(mc_type: &'a PbftMessageType) -> String {
        format!("{:?}", mc_type)
    }
}
