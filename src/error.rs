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

/// Errors that might occur in a PbftNode
#[derive(Debug)]
pub enum PbftError {
    /// An error occured while serializing or deserializing a Protobuf message
    SerializationError(ProtobufError),

    /// Internal PBFT error (description)
    InternalError(String),

    /// The message should only come from the primary, but was sent by a secondary node
    NotFromPrimary,
}

impl Error for PbftError {
    fn description(&self) -> &str {
        use self::PbftError::*;
        match self {
            SerializationError(_) => "SerializationError",
            InternalError(_) => "InternalError",
            NotFromPrimary => "NotFromPrimary",
        }
    }
}

impl fmt::Display for PbftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: ", self.description())?;
        match self {
            PbftError::SerializationError(pb_err) => pb_err.fmt(f),
            PbftError::InternalError(description) => write!(f, "{}", description),
            PbftError::NotFromPrimary => write!(
                f,
                "Message should be from primary, but was sent by secondary"
            ),
        }
    }
}
