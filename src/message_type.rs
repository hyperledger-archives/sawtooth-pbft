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

#![allow(unknown_lints, clippy::derive_hash_xor_eq)]

use std::fmt;
use std::hash::{Hash, Hasher};

use protobuf::Message;
use sawtooth_sdk::consensus::engine::{BlockId, PeerMessage};

use crate::error::PbftError;
use crate::protos::pbft_message::{
    PbftMessage, PbftMessageInfo, PbftNewView, PbftSeal, PbftSignedVote,
};

/// Wrapper enum for all of the possible PBFT-related messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PbftMessageWrapper {
    Message(PbftMessage),
    NewView(PbftNewView),
    Seal(PbftSeal),
}

/// Container for a received PeerMessage and the PBFT message parsed from it
///
/// The bits of the `PeerMessage` struct that this carries around are used in constructing signed
/// votes.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedMessage {
    /// Serialized ConsensusPeerMessageHeader. Inserted into a signed vote.
    pub header_bytes: Vec<u8>,

    /// Signature for `header_bytes`. Inserted into a signed vote.
    pub header_signature: Vec<u8>,

    /// The parsed PBFT message.
    pub message: PbftMessageWrapper,

    /// The serialized PBFT message. Inserted into a signed vote.
    pub message_bytes: Vec<u8>,

    /// Whether or not this message was self-constructed. Self-constructed messages are skipped
    /// when assembling signed votes, since PBFT doesn't have access to the validator key necessary
    /// to create valid signed messages.
    pub from_self: bool,
}

impl Hash for ParsedMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.message {
            PbftMessageWrapper::Message(m) => m.hash(state),
            PbftMessageWrapper::NewView(m) => m.hash(state),
            PbftMessageWrapper::Seal(m) => m.hash(state),
        }
    }
}

impl ParsedMessage {
    /// Constructs a `ParsedMessage` from the given `PeerMessage`.
    ///
    /// Attempts to parse the message contents as a `PbftMessage`, `PbftNewView`, or
    /// `PbftSeal` and wraps that in an internal enum.
    pub fn from_peer_message(message: PeerMessage, own_id: &[u8]) -> Result<Self, PbftError> {
        let deserialized_message = match message.header.message_type.as_str() {
            "Seal" => PbftMessageWrapper::Seal(
                protobuf::parse_from_bytes::<PbftSeal>(&message.content).map_err(|err| {
                    PbftError::SerializationError("Error parsing PbftSeal".into(), err)
                })?,
            ),
            "NewView" => PbftMessageWrapper::NewView(
                protobuf::parse_from_bytes::<PbftNewView>(&message.content).map_err(|err| {
                    PbftError::SerializationError("Error parsing PbftNewView".into(), err)
                })?,
            ),
            _ => PbftMessageWrapper::Message(
                protobuf::parse_from_bytes::<PbftMessage>(&message.content).map_err(|err| {
                    PbftError::SerializationError("Error parsing PbftMessage".into(), err)
                })?,
            ),
        };

        let mut parsed_message = Self {
            from_self: false,
            header_bytes: message.header_bytes,
            header_signature: message.header_signature,
            message: deserialized_message,
            message_bytes: message.content.clone(),
        };

        // Ensure that the type of the ParsedMessage matches the type of the PeerMessage; if this
        // is not enforced, a node could, for instance, send a Seal but trick the other node into
        // parsing it as a NewView
        if parsed_message.info().get_msg_type() != message.header.message_type.as_str() {
            return Err(PbftError::InvalidMessage(format!(
                "Message type mismatch: received a PeerMessage with type {} that contains a PBFT \
                 message with type {}",
                message.header.message_type.as_str(),
                parsed_message.info().get_msg_type()
            )));
        }

        // Make sure from_self is properly set
        parsed_message.from_self = parsed_message.info().get_signer_id() == own_id;

        Ok(parsed_message)
    }

    /// Constructs a `ParsedMessage` from the given `PbftMessage`.
    ///
    /// Does not add metadata necessary for creating a signed vote from this message.
    pub fn from_pbft_message(message: PbftMessage) -> Result<Self, PbftError> {
        let message_bytes = message.write_to_bytes().map_err(|err| {
            PbftError::SerializationError("Error writing PbftMessage to bytes".into(), err)
        })?;

        Ok(Self {
            from_self: true,
            header_bytes: vec![],
            header_signature: vec![],
            message_bytes,
            message: PbftMessageWrapper::Message(message),
        })
    }

    /// Constructs a `ParsedMessage` from the given `PbftNewView`.
    ///
    /// Does not add metadata necessary for creating a signed vote from this message.
    pub fn from_new_view_message(message: PbftNewView) -> Result<Self, PbftError> {
        let message_bytes = message.write_to_bytes().map_err(|err| {
            PbftError::SerializationError("Error writing PbftNewView to bytes".into(), err)
        })?;

        Ok(Self {
            from_self: true,
            header_bytes: vec![],
            header_signature: vec![],
            message_bytes,
            message: PbftMessageWrapper::NewView(message),
        })
    }

    /// Constructs a `ParsedMessage` from the given `PbftSignedVote`.
    ///
    /// Adds metadata necessary for re-creating a signed vote later on.
    pub fn from_signed_vote(vote: &PbftSignedVote) -> Result<Self, PbftError> {
        let message = protobuf::parse_from_bytes(vote.get_message_bytes())
            .map_err(|err| PbftError::SerializationError("Error parsing vote".into(), err))?;

        Ok(Self {
            from_self: false,
            header_bytes: vote.get_header_bytes().to_vec(),
            header_signature: vote.get_header_signature().to_vec(),
            message_bytes: vote.get_message_bytes().to_vec(),
            message: PbftMessageWrapper::Message(message),
        })
    }

    pub fn info(&self) -> &PbftMessageInfo {
        match &self.message {
            PbftMessageWrapper::Message(m) => &m.get_info(),
            PbftMessageWrapper::NewView(m) => &m.get_info(),
            PbftMessageWrapper::Seal(m) => &m.get_info(),
        }
    }

    /// Returns the `BlockId` for this message's wrapped `PbftMessage`.
    ///
    /// # Panics
    /// + If the wrapped message is a `NewView` or `Seal`, which don't contain a block_id
    pub fn get_block_id(&self) -> BlockId {
        match &self.message {
            PbftMessageWrapper::Message(m) => m.get_block_id().to_vec(),
            PbftMessageWrapper::NewView(_) => {
                panic!("ParsedPeerMessage.get_block_id found a new view message!")
            }
            PbftMessageWrapper::Seal(_) => {
                panic!("ParsedPeerMessage.get_block_id found a seal response message!")
            }
        }
    }

    /// Returns the wrapped `PbftNewView`.
    ///
    /// # Panics
    /// + If the wrapped message is a regular message or `Seal`, not a `NewView`
    pub fn get_new_view_message(&self) -> &PbftNewView {
        match &self.message {
            PbftMessageWrapper::Message(_) => {
                panic!("ParsedPeerMessage.get_view_change_message found a pbft message!")
            }
            PbftMessageWrapper::NewView(m) => m,
            PbftMessageWrapper::Seal(_) => {
                panic!("ParsedPeerMessage.get_view_change_message found a seal response message!")
            }
        }
    }

    /// Returns the wrapped `PbftSeal`.
    ///
    /// # Panics
    /// + If the wrapped message is a regular message or `NewView`
    pub fn get_seal(&self) -> &PbftSeal {
        match &self.message {
            PbftMessageWrapper::Message(_) => {
                panic!("ParsedPeerMessage.get_seal found a pbft message!")
            }
            PbftMessageWrapper::NewView(_) => {
                panic!("ParsedPeerMessage.get_seal found a new view message!")
            }
            PbftMessageWrapper::Seal(s) => s,
        }
    }
}

// Messages related to PBFT consensus
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum PbftMessageType {
    /// Basic message types for the multicast protocol
    PrePrepare,
    Prepare,
    Commit,

    /// Auxiliary PBFT messages
    NewView,
    ViewChange,
    SealRequest,
    Seal,

    Unset,
}

impl fmt::Display for PbftMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let txt = match self {
            PbftMessageType::PrePrepare => "PP",
            PbftMessageType::Prepare => "Pr",
            PbftMessageType::Commit => "Co",
            PbftMessageType::NewView => "NV",
            PbftMessageType::ViewChange => "VC",
            PbftMessageType::SealRequest => "Rq",
            PbftMessageType::Seal => "Rs",
            PbftMessageType::Unset => "Un",
        };
        write!(f, "{}", txt)
    }
}

impl<'a> From<&'a str> for PbftMessageType {
    fn from(s: &'a str) -> Self {
        match s {
            "PrePrepare" => PbftMessageType::PrePrepare,
            "Prepare" => PbftMessageType::Prepare,
            "Commit" => PbftMessageType::Commit,
            "NewView" => PbftMessageType::NewView,
            "ViewChange" => PbftMessageType::ViewChange,
            "SealRequest" => PbftMessageType::SealRequest,
            "Seal" => PbftMessageType::Seal,
            _ => {
                warn!("Unhandled PBFT message type: {}", s);
                PbftMessageType::Unset
            }
        }
    }
}

impl From<PbftMessageType> for String {
    fn from(msg_type: PbftMessageType) -> String {
        format!("{:?}", msg_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The log stores `ParsedMessage`s, and `ParsedMessage`s need to be constructed from
    /// `PbftMessage`s directly (when self-sending messages), `PbftSignedVote`s (during catch-up),
    /// and from `PeerMessage`s that contain `PbftMessage`s (when receiving messages from peers).
    /// These are parsed using the `ParsedMessage::from_pbft_message`,
    /// `ParsedMessage::from_signed_vote`, and `ParsedMessage::from_peer_message` constructors
    /// respectively.
    #[test]
    fn test_pbft_message_parsing() {
        // Create a PbftMessage and serialize it
        let info = PbftMessageInfo::new_from(PbftMessageType::Commit, 0, 1, vec![0]);
        let mut msg = PbftMessage::new();
        msg.set_info(info);
        msg.set_block_id(vec![0]);

        let msg_bytes = msg
            .write_to_bytes()
            .expect("Failed to serialize PbftMessage");

        // Validate that the PbftMessage is parsed correctly
        let parsed1 = ParsedMessage::from_pbft_message(msg.clone())
            .expect("PbftMessage parsing not successful");
        assert_eq!(msg.get_info().get_msg_type(), parsed1.info().get_msg_type());
        assert_eq!(msg.get_info().get_view(), parsed1.info().get_view());
        assert_eq!(msg.get_info().get_seq_num(), parsed1.info().get_seq_num());
        assert_eq!(
            msg.get_info().get_signer_id(),
            parsed1.info().get_signer_id()
        );
        assert_eq!(msg.get_block_id(), parsed1.get_block_id().as_slice());
        assert_eq!(msg_bytes, parsed1.message_bytes);
        assert!(parsed1.from_self);

        // Validate that a PbftSignedVote is parsed correctly
        let mut vote = PbftSignedVote::new();
        vote.set_header_bytes(b"abc".to_vec());
        vote.set_header_signature(b"def".to_vec());
        vote.set_message_bytes(msg_bytes.clone());

        let parsed2 =
            ParsedMessage::from_signed_vote(&vote).expect("PbftSignedVote parsing not successful");
        assert_eq!(msg.get_info().get_msg_type(), parsed2.info().get_msg_type());
        assert_eq!(msg.get_info().get_view(), parsed2.info().get_view());
        assert_eq!(msg.get_info().get_seq_num(), parsed2.info().get_seq_num());
        assert_eq!(
            msg.get_info().get_signer_id(),
            parsed2.info().get_signer_id()
        );
        assert_eq!(msg.get_block_id(), parsed2.get_block_id().as_slice());
        assert_eq!(vote.get_header_bytes(), parsed2.header_bytes.as_slice());
        assert_eq!(
            vote.get_header_signature(),
            parsed2.header_signature.as_slice()
        );
        assert_eq!(vote.get_message_bytes(), parsed2.message_bytes.as_slice());
        assert!(!parsed2.from_self);

        // Validate that a PeerMessage containing a PbftMessage is parsed correctly
        let mut peer_msg = PeerMessage::default();
        peer_msg.header.message_type = msg.get_info().get_msg_type().into();
        peer_msg.header_bytes = b"abc".to_vec();
        peer_msg.header_signature = b"def".to_vec();
        peer_msg.content = msg_bytes;

        let parsed3 = ParsedMessage::from_peer_message(peer_msg.clone(), &vec![1])
            .expect("PeerMessage parsing not successful");
        assert_eq!(msg.get_info().get_msg_type(), parsed3.info().get_msg_type());
        assert_eq!(msg.get_info().get_view(), parsed3.info().get_view());
        assert_eq!(msg.get_info().get_seq_num(), parsed3.info().get_seq_num());
        assert_eq!(
            msg.get_info().get_signer_id(),
            parsed3.info().get_signer_id()
        );
        assert_eq!(msg.get_block_id(), parsed3.get_block_id().as_slice());
        assert_eq!(peer_msg.header_bytes, parsed3.header_bytes);
        assert_eq!(peer_msg.header_signature, parsed3.header_signature);
        assert_eq!(peer_msg.content, parsed3.message_bytes);
        assert!(!parsed3.from_self);

        // Validate that the from_self field is set correctly
        let parsed4 = ParsedMessage::from_peer_message(peer_msg.clone(), &vec![0])
            .expect("PeerMessage parsing not successful");
        assert!(parsed4.from_self);

        // Validate that the PeerMessage's type is checked against the ParsedMessage's type
        peer_msg.header.message_type = "Seal".into();
        assert!(ParsedMessage::from_peer_message(peer_msg.clone(), &vec![1]).is_err());
        peer_msg.header.message_type = "NewView".into();
        assert!(ParsedMessage::from_peer_message(peer_msg, &vec![1]).is_err());
    }

    /// `PbftNewView` messages are structurally different from `PbftMessage`s and`PbftSeal`s, but
    /// `ParsedMessage`s must also be able to be constructed from `PbftNewView` messages directly
    /// (for self-sent messages) and those contained in a `PeerMessage` (from other peers) for view
    /// changing to work. This parsing is handled by the `ParsedMessage::from_new_view_message` and
    /// `ParsedMessage::from_peer_message` methods respectively.
    #[test]
    fn test_new_view_parsing() {
        // Create a PbftNewView and serialize it
        let info = PbftMessageInfo::new_from(PbftMessageType::NewView, 1, 1, vec![0]);
        let mut msg = PbftNewView::new();
        msg.set_info(info);

        let msg_bytes = msg
            .write_to_bytes()
            .expect("Failed to serialize PbftNewView");

        // Validate that the PbftNewView is parsed correctly
        let parsed1 = ParsedMessage::from_new_view_message(msg.clone())
            .expect("PbftNewView parsing not successful");
        assert_eq!(&msg, parsed1.get_new_view_message());
        assert_eq!(msg_bytes, parsed1.message_bytes);
        assert!(parsed1.from_self);

        // Validate that a PeerMessage containing a PbftNewView is parsed correctly
        let mut peer_msg = PeerMessage::default();
        peer_msg.header.message_type = msg.get_info().get_msg_type().into();
        peer_msg.header_bytes = b"abc".to_vec();
        peer_msg.header_signature = b"def".to_vec();
        peer_msg.content = msg_bytes;

        let parsed2 = ParsedMessage::from_peer_message(peer_msg.clone(), &vec![1])
            .expect("PeerMessage parsing not successful");
        assert_eq!(&msg, parsed2.get_new_view_message());
        assert_eq!(peer_msg.header_bytes, parsed2.header_bytes);
        assert_eq!(peer_msg.header_signature, parsed2.header_signature);
        assert_eq!(peer_msg.content, parsed2.message_bytes);
        assert!(!parsed2.from_self);

        // Validate that the from_self field is set correctly
        let parsed3 = ParsedMessage::from_peer_message(peer_msg.clone(), &vec![0])
            .expect("PeerMessage parsing not successful");
        assert!(parsed3.from_self);

        // Validate that the PeerMessage's type is checked against the ParsedMessage's type
        peer_msg.header.message_type = "Seal".into();
        assert!(ParsedMessage::from_peer_message(peer_msg.clone(), &vec![1]).is_err());
        peer_msg.header.message_type = "Commit".into();
        assert!(ParsedMessage::from_peer_message(peer_msg, &vec![1]).is_err());
    }

    /// `PbftSeal` messages are structurally different from `PbftMessage`s and `PbftNewView`s, but
    /// `ParsedMessage`s must also be able to be constructed from those contained in a
    /// `PeerMessage` for the catch-up procedure to work.
    #[test]
    fn test_seal_parsing() {
        // Create a PbftSeal and serialize it
        let info = PbftMessageInfo::new_from(PbftMessageType::Seal, 1, 1, vec![0]);
        let mut msg = PbftSeal::new();
        msg.set_info(info);
        msg.set_block_id(vec![1]);

        let msg_bytes = msg.write_to_bytes().expect("Failed to serialize PbftSeal");

        // Validate that a PeerMessage containing a PbftSeal is parsed correctly
        let mut peer_msg = PeerMessage::default();
        peer_msg.header.message_type = msg.get_info().get_msg_type().into();
        peer_msg.header_bytes = b"abc".to_vec();
        peer_msg.header_signature = b"def".to_vec();
        peer_msg.content = msg_bytes;

        let parsed1 = ParsedMessage::from_peer_message(peer_msg.clone(), &vec![1])
            .expect("PeerMessage parsing not successful");
        assert_eq!(&msg, parsed1.get_seal());
        assert_eq!(peer_msg.header_bytes, parsed1.header_bytes);
        assert_eq!(peer_msg.header_signature, parsed1.header_signature);
        assert_eq!(peer_msg.content, parsed1.message_bytes);
        assert!(!parsed1.from_self);

        // Validate that the from_self field is set correctly
        let parsed2 = ParsedMessage::from_peer_message(peer_msg.clone(), &vec![0])
            .expect("PeerMessage parsing not successful");
        assert!(parsed2.from_self);

        // Validate that the PeerMessage's type is checked against the ParsedMessage's type
        peer_msg.header.message_type = "NewView".into();
        assert!(ParsedMessage::from_peer_message(peer_msg.clone(), &vec![1]).is_err());
        peer_msg.header.message_type = "Commit".into();
        assert!(ParsedMessage::from_peer_message(peer_msg, &vec![1]).is_err());
    }
}
