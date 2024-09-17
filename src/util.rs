use atrium_api::types::string::Did;
use sha2::{Digest, Sha256};

pub(crate) fn derive_did(signed_genesis_op: &[u8]) -> Did {
    Did::new(format!(
        "did:plc:{}",
        &base32::encode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            &Sha256::digest(signed_genesis_op),
        )[..24]
    ))
    .expect("valid")
}
