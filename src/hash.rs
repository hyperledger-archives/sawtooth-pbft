/// Contains common hashing functions
use openssl::sha::{Sha256, Sha512};

use error::PbftError;

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
        Err(PbftError::InternalError(format!(
            "Hash verification failed! Content: `{:?}`, Hash: `{:?}`",
            content, content_hash
        )))
    } else {
        Ok(())
    }
}
