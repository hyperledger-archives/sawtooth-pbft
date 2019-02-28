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
use openssl::sha::Sha512;

use crate::error::PbftError;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Nodes must be able to verify SHA-512 hashes to properly validate consensus messages from
    /// other peers, especially those that are used in consensus seals. This allows the network to
    /// verify the origin of the messages and prevents a malicious node from forging messages.
    ///
    /// This test will verify that the `verify_sha512` function properly verifies a SHA-512 hash.
    #[test]
    fn test_sha512_verification() {
        let bytes = b"abc";
        let correct_hash = [
            221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230, 250,
            78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42, 39, 79,
            193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60, 232, 14, 42,
            154, 201, 79, 165, 76, 164, 159,
        ];
        let incorrect_hash = [
            216, 2, 47, 32, 96, 173, 110, 253, 41, 122, 183, 61, 204, 83, 85, 201, 178, 20, 5, 75,
            13, 23, 118, 161, 54, 166, 105, 210, 106, 125, 59, 20, 247, 58, 160, 208, 235, 255, 25,
            238, 51, 51, 104, 240, 22, 75, 100, 25, 169, 109, 164, 158, 62, 72, 23, 83, 231, 233,
            107, 113, 107, 220, 203, 111,
        ];

        assert!(verify_sha512(bytes, &correct_hash).is_ok());
        assert!(verify_sha512(bytes, &incorrect_hash).is_err());
    }
}
