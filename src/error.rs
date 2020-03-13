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

use protobuf::error::ProtobufError;
use sawtooth_sdk::consensus::engine::Error as ServError;

/// Errors that might occur in a PbftNode
#[derive(Debug)]
pub enum PbftError {
    /// An error occurred while serializing or deserializing a Protobuf message (description,
    /// `ProtobufError`)
    SerializationError(String, ProtobufError),

    /// An error occurred while making a call to the consensus service (description, `ServError`)
    ServiceError(String, ServError),

    /// An error occurred while verifying a cryptographic signature
    SigningError(String),

    /// The node detected a faulty primary and started a view change
    FaultyPrimary(String),

    /// An invalid message was received
    InvalidMessage(String),

    /// Internal PBFT error (description)
    InternalError(String),
}

impl Error for PbftError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PbftError::SerializationError(_, err) => Some(err),
            PbftError::ServiceError(_, err) => Some(err),
            PbftError::SigningError(_) => None,
            PbftError::FaultyPrimary(_) => None,
            PbftError::InvalidMessage(_) => None,
            PbftError::InternalError(_) => None,
        }
    }
}

impl fmt::Display for PbftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PbftError::SerializationError(desc, pb_err) => write!(f, "{} due to: {}", desc, pb_err),
            PbftError::ServiceError(desc, serv_err) => write!(f, "{} due to: {}", desc, serv_err),
            PbftError::SigningError(description) => write!(f, "{}", description),
            PbftError::FaultyPrimary(description) => write!(
                f,
                "Node has detected a faulty primary and started a view change: {}",
                description
            ),
            PbftError::InvalidMessage(description) => write!(f, "{}", description),
            PbftError::InternalError(description) => write!(f, "{}", description),
        }
    }
}
