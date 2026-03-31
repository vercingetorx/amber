use std::fs::File;
use std::io::Read;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};

use crate::error::{AmberError, AmberResult};

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;

pub const ARGON_TIME_COST: u32 = 3;
pub const ARGON_MEMORY_COST_KIB: u32 = 256 * 1024;
pub const ARGON_PARALLELISM: u32 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionParams {
    pub salt: [u8; SALT_SIZE],
    pub time_cost: u32,
    pub memory_cost_kib: u32,
    pub parallelism: u32,
}

#[derive(Clone)]
pub struct EncryptionContext {
    key: [u8; KEY_SIZE],
    params: EncryptionParams,
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionContext")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl EncryptionContext {
    pub fn create_from_secret(secret: &[u8]) -> AmberResult<Self> {
        let mut salt = [0u8; SALT_SIZE];
        getrandom::fill(&mut salt).map_err(|err| {
            AmberError::Invalid(format!("failed to generate encryption salt: {err}"))
        })?;
        Self::create_from_secret_with_salt(secret, salt)
    }

    pub fn create_from_secret_with_salt(secret: &[u8], salt: [u8; SALT_SIZE]) -> AmberResult<Self> {
        let params = EncryptionParams {
            salt,
            time_cost: ARGON_TIME_COST,
            memory_cost_kib: ARGON_MEMORY_COST_KIB,
            parallelism: ARGON_PARALLELISM,
        };
        Self::from_params_secret(secret, params)
    }

    pub fn from_params_secret(secret: &[u8], params: EncryptionParams) -> AmberResult<Self> {
        if params.time_cost != ARGON_TIME_COST
            || params.memory_cost_kib != ARGON_MEMORY_COST_KIB
            || params.parallelism != ARGON_PARALLELISM
        {
            return Err(AmberError::Invalid(
                "Unsupported Argon2 parameters in archive".into(),
            ));
        }
        let argon_params = Params::new(
            params.memory_cost_kib,
            params.time_cost,
            params.parallelism,
            Some(KEY_SIZE),
        )
        .map_err(|err| AmberError::Invalid(format!("invalid Argon2 params: {err}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
        let mut key = [0u8; KEY_SIZE];
        argon2
            .hash_password_into(secret, &params.salt, &mut key)
            .map_err(|err| AmberError::Invalid(format!("Argon2 failed: {err}")))?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        Ok(Self {
            key,
            params,
            cipher,
        })
    }

    pub fn encrypt(
        &self,
        aad: &[u8],
        plaintext: &[u8],
        nonce_material: &[u8],
    ) -> AmberResult<Vec<u8>> {
        let nonce = self.derive_nonce(nonce_material)?;
        let mut buffer = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut buffer)
            .map_err(|_| AmberError::Invalid("encryption failed".into()))?;
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    pub fn decrypt(
        &self,
        aad: &[u8],
        payload: &[u8],
        nonce_material: &[u8],
    ) -> AmberResult<Vec<u8>> {
        if payload.len() < TAG_SIZE {
            return Err(AmberError::Invalid("Encrypted payload too short".into()));
        }
        let nonce = self.derive_nonce(nonce_material)?;
        let split = payload.len() - TAG_SIZE;
        let mut buffer = payload[..split].to_vec();
        let tag = Tag::from_slice(&payload[split..]);
        self.cipher
            .decrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut buffer, tag)
            .map_err(|_| AmberError::Invalid("decryption failed".into()))?;
        Ok(buffer)
    }

    pub fn overhead(&self) -> usize {
        TAG_SIZE
    }

    pub fn export_params(&self) -> EncryptionParams {
        self.params.clone()
    }

    fn derive_nonce(&self, nonce_material: &[u8]) -> AmberResult<[u8; NONCE_SIZE]> {
        let mut hasher = Hasher::new_keyed(&self.key);
        hasher.update(b"AMBER_REC_NONCE");
        hasher.update(nonce_material);
        let digest = hasher.finalize();
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&digest.as_bytes()[..NONCE_SIZE]);
        Ok(nonce)
    }
}

pub fn derive_user_secret(
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<Option<[u8; 32]>> {
    if password.is_none() && keyfile.is_none() {
        return Ok(None);
    }
    let mut hasher = Hasher::new();
    match (password, keyfile) {
        (Some(password), None) => {
            hasher.update(b"AMBER_USERSEC\0PW\0");
            hasher.update(password.as_bytes());
        }
        (None, Some(keyfile)) => {
            hasher.update(b"AMBER_USERSEC\0KF\0");
            hasher.update(&keyfile_digest(keyfile)?);
        }
        (Some(password), Some(keyfile)) => {
            hasher.update(b"AMBER_USERSEC\0PWKF\0");
            hasher.update(password.as_bytes());
            hasher.update(&[0]);
            hasher.update(&keyfile_digest(keyfile)?);
        }
        (None, None) => unreachable!(),
    }
    Ok(Some(*hasher.finalize().as_bytes()))
}

fn keyfile_digest(path: &Path) -> AmberResult<[u8; 32]> {
    let mut hasher = Hasher::new();
    hasher.update(b"AMBER_KEYFILE\0");
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
#[path = "tests/encryption.rs"]
mod tests;
