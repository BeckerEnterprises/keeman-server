//! Argon2id hashes of auth keys and backup codes, computed on
//! blocking threads and limited to one calculation per CPU core.

use argon2::password_hash::Error as HashError;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use tokio::sync::Semaphore;

use crate::crypto::random_bytes;
use crate::error::{ApiError, ApiResult};

pub struct Passwords {
    params: Params,
    permits: Semaphore,
    /// Hash of random bytes; unknown e-mails are verified against it so the
    /// response time does not reveal whether an account exists.
    dummy: String,
}

fn argon(params: Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_blocking(params: Params, key: &[u8]) -> Result<String, String> {
    let salt = random_bytes::<16>().map_err(|e| e.to_string())?;
    argon(params)
        .hash_password_with_salt(key, &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

impl Passwords {
    pub fn new() -> Result<Self, String> {
        let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| e.to_string())?;
        let dummy_key = random_bytes::<32>().map_err(|e| e.to_string())?;
        let dummy = hash_blocking(params.clone(), &dummy_key)?;
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        Ok(Self {
            params,
            permits: Semaphore::new(cores),
            dummy,
        })
    }

    pub async fn hash(&self, key: &[u8; 32]) -> ApiResult<String> {
        let mut hashes = self.hash_all(vec![key.to_vec()]).await?;
        hashes.pop().ok_or_else(|| ApiError::internal("no hash"))
    }

    /// Hashes several inputs (the backup codes) one after another on one
    /// blocking thread.
    pub async fn hash_all(&self, inputs: Vec<Vec<u8>>) -> ApiResult<Vec<String>> {
        let _permit = self.permits.acquire().await.map_err(ApiError::internal)?;
        let params = self.params.clone();
        tokio::task::spawn_blocking(move || {
            inputs
                .iter()
                .map(|input| hash_blocking(params.clone(), input))
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
    }

    /// Verifies `key` against `hash`, or against the dummy hash if there is no
    /// account; the parameters come from the PHC string.
    pub async fn verify(&self, key: &[u8; 32], hash: Option<&str>) -> ApiResult<bool> {
        let _permit = self.permits.acquire().await.map_err(ApiError::internal)?;
        let known = hash.is_some();
        let phc = hash.unwrap_or(&self.dummy).to_string();
        let params = self.params.clone();
        let key = *key;
        let result =
            tokio::task::spawn_blocking(move || argon(params).verify_password(&key, phc.as_str()))
                .await
                .map_err(ApiError::internal)?;
        match result {
            Ok(()) => Ok(known),
            Err(HashError::PasswordInvalid) => Ok(false),
            Err(error) => Err(ApiError::internal(error)),
        }
    }

    /// Index of the first hash that `input` matches (a backup code against
    /// the unused codes of an account), checked on one blocking thread.
    pub async fn find(&self, input: &[u8], hashes: Vec<String>) -> ApiResult<Option<usize>> {
        let _permit = self.permits.acquire().await.map_err(ApiError::internal)?;
        let params = self.params.clone();
        let input = input.to_vec();
        tokio::task::spawn_blocking(move || {
            let argon = argon(params);
            for (index, phc) in hashes.iter().enumerate() {
                match argon.verify_password(&input, phc.as_str()) {
                    Ok(()) => return Ok(Some(index)),
                    Err(HashError::PasswordInvalid) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(None)
        })
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_and_verifies() {
        let passwords = Passwords::new().unwrap();
        let hash = passwords.hash(&[1u8; 32]).await.unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(passwords.verify(&[1u8; 32], Some(&hash)).await.unwrap());
        assert!(!passwords.verify(&[2u8; 32], Some(&hash)).await.unwrap());
        assert!(!passwords.verify(&[1u8; 32], None).await.unwrap());
    }

    #[tokio::test]
    async fn finds_one_of_several_codes() {
        let passwords = Passwords::new().unwrap();
        let codes = vec![b"AAAAAAAAAA".to_vec(), b"BBBBBBBBBB".to_vec()];
        let hashes = passwords.hash_all(codes).await.unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            passwords.find(b"BBBBBBBBBB", hashes.clone()).await.unwrap(),
            Some(1)
        );
        assert_eq!(passwords.find(b"CCCCCCCCCC", hashes).await.unwrap(), None);
        assert_eq!(
            passwords.find(b"AAAAAAAAAA", Vec::new()).await.unwrap(),
            None
        );
    }
}
