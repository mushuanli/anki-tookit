// src/common/crypto.rs

// --- FIX: Remove unused `Signer` import ---
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
// --- END FIX ---
use rand::rngs::OsRng;
use crate::error::{AppError, Result};

pub struct KeyPair {
    pub signing_key: SigningKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    pub fn private_key_to_bs58(&self) -> String {
        bs58::encode(self.signing_key.to_bytes())
            .with_check_version(0)
            .into_string()
    }

    pub fn public_key_to_bs58(&self) -> String {
        bs58::encode(self.signing_key.verifying_key().to_bytes()).with_check_version(1).into_string()
    }
}

pub fn verify_signature(public_key_bs58: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let pub_key_bytes_with_version = bs58::decode(public_key_bs58)
        .with_check(Some(1))
        .into_vec()
        .map_err(|e| AppError::AuthError(format!("Invalid public key format or checksum: {}", e)))?;

    let pub_key_bytes_slice = &pub_key_bytes_with_version[1..];

    // --- FIX: Convert the slice to a fixed-size array reference ---
    let pub_key_array: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = pub_key_bytes_slice
        .try_into()
        .map_err(|_| AppError::AuthError(format!(
            "Invalid public key length. Expected 32 bytes, got {}.",
            pub_key_bytes_slice.len()
        )))?;
    // --- END FIX ---

    let verifying_key = VerifyingKey::from_bytes(pub_key_array)
        .map_err(|e| AppError::AuthError(format!("Invalid public key bytes: {}", e)))?;
    
    let signature = Signature::from_slice(signature)
        .map_err(|_| AppError::AuthError("Invalid signature format".to_string()))?;

    verifying_key.verify(message, &signature)
        .map_err(|_| AppError::AuthError("Signature verification failed".to_string()))?;

    Ok(())
}
