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

//! PBFT-specific error messages

use std::error::Error;
use std::fmt;

use hex;
use protobuf::error::ProtobufError;

use crate::message_type::PbftMessageType;
use crate::protos::pbft_message::PbftBlock;

/// Errors that might occur in a PbftNode
#[derive(Debug)]
pub enum PbftError {
    /// An error occured while serializing or deserializing a Protobuf message
    SerializationError(ProtobufError),

    /// Too many or too few messages recieved so far (expected, got)
    WrongNumMessages(PbftMessageType, usize, usize),

    /// The block in the message doesn't match the one this node was expecting
    BlockMismatch(PbftBlock, PbftBlock),

    /// The message information doesn't match the one this node was expecting
    MessageMismatch(PbftMessageType),

    /// The message is in a different view than this node is
    ViewMismatch(usize, usize),

    /// The message has a sequence number that is not between watermarks
    /// (message's sequence number, low watermark, high watermark)
    InvalidSequenceNumber(usize, usize, usize),

    /// Internal PBFT error (description)
    InternalError(String),

    /// The requested node is not found on the network
    NodeNotFound,

    /// More than one block matched with the given ID
    WrongNumBlocks,

    /// Timed out waiting for a message
    Timeout,

    /// There is no working block; no operations can be performed
    NoWorkingBlock,

    /// Not ready for this message type
    NotReadyForMessage,

    /// The message should only come from the primary, but was sent by a secondary node
    NotFromPrimary,

    /// Got a PrePrepare without a matching BlockNew
    NoBlockNew,
}

impl Error for PbftError {
    fn description(&self) -> &str {
        use self::PbftError::*;
        match self {
            SerializationError(_) => "SerializationError",
            WrongNumMessages(_, _, _) => "WrongNumMessages",
            BlockMismatch(_, _) => "BlockMismatch",
            MessageMismatch(_) => "MessageMismatch",
            ViewMismatch(_, _) => "ViewMismatch",
            InvalidSequenceNumber(_, _, _) => "InvalidSequenceNumber",
            InternalError(_) => "InternalError",
            NodeNotFound => "NodeNotFound",
            WrongNumBlocks => "WrongNumBlocks",
            Timeout => "Timeout",
            NoWorkingBlock => "NoWorkingBlock",
            NotReadyForMessage => "NotReadyForMessage",
            NotFromPrimary => "NotFromPrimary",
            NoBlockNew => "NoBlockNew",
        }
    }
}

impl fmt::Display for PbftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: ", self.description())?;
        match self {
            PbftError::SerializationError(pb_err) => pb_err.fmt(f),
            PbftError::WrongNumMessages(t, exp, got) => write!(
                f,
                "Wrong number of {:?} messages in this sequence (expected {}, got {})",
                t, exp, got
            ),
            PbftError::MessageMismatch(t) => write!(f, "{:?} message mismatch", t),
            PbftError::ViewMismatch(exp, got) => write!(f, "View mismatch: {} != {}", exp, got),
            PbftError::InvalidSequenceNumber(got, low, high) => write!(
                f,
                "Invalid sequence number: {} is not in range [{},{})",
                got, low, high
            ),
            PbftError::BlockMismatch(exp, got) => write!(
                f,
                "{:?} != {:?}",
                &hex::encode(exp.get_block_id())[..6],
                &hex::encode(got.get_block_id())[..6]
            ),
            PbftError::NodeNotFound => write!(f, "Couldn't find node in the network"),
            PbftError::WrongNumBlocks => write!(f, "Incorrect number of blocks"),
            PbftError::Timeout => write!(f, "Timed out"),
            PbftError::InternalError(description) => write!(f, "{}", description),
            PbftError::NoWorkingBlock => write!(f, "There is no working block"),
            PbftError::NotReadyForMessage => write!(f, "Not ready"),
            PbftError::NotFromPrimary => write!(
                f,
                "Message should be from primary, but was sent by secondary"
            ),
            PbftError::NoBlockNew => write!(f, "Got a PrePrepare without a matching BlockNew"),
        }
    }
}
