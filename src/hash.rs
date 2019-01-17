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

/// Contains common hashing functions
use openssl::sha::{Sha256, Sha512};

use crate::error::PbftError;

/// Hashes the given bytes with SHA-256
pub fn hash_sha256(bytes: &[u8]) -> Vec<u8> {
    let mut sha = Sha256::new();
    sha.update(bytes);
    let mut bytes = Vec::new();
    bytes.extend(sha.finish().iter());
    bytes
}

/// Hashes the given bytes with SHA-512
pub fn hash_sha512(bytes: &[u8]) -> Vec<u8> {
    let mut sha = Sha512::new();
    sha.update(bytes);
    let mut bytes = Vec::new();
    bytes.extend(sha.finish().iter());
    bytes
}

/// Verifies that the SHA-512 hash of the given content matches the given hash
pub fn verify_sha512(content: &[u8], content_hash: &[u8]) -> Result<(), PbftError> {
    let computed_sha512 = hash_sha512(&content);

    if computed_sha512 != content_hash {
        Err(PbftError::SigningError(format!(
            "Hash verification failed - Content: `{:?}`, Hash: `{:?}`",
            content, content_hash
        )))
    } else {
        Ok(())
    }
}
