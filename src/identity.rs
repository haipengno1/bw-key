use crate::prelude::*;
use crate::core::locked::{Keys,Password,PasswordHash,Vec};

pub struct Identity {
    pub email: String,
    pub keys: Keys,
    pub master_password_hash: PasswordHash,
}

impl Identity {
    pub fn new(
        email: &str,
        password: &Password,
        iterations: u32,
    ) -> Result<Self> {
        let iterations = std::num::NonZeroU32::new(iterations)
            .context(crate::error::Pbkdf2ZeroIterationsSnafu)?;

        let mut keys = Vec::new();
        keys.extend(std::iter::repeat(0).take(64));

        let enc_key = &mut keys.data_mut()[0..32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            email.as_bytes(),
            password.password(),
            enc_key,
        );

        let mut hash = Vec::new();
        hash.extend(std::iter::repeat(0).take(32));
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(1).unwrap(),
            password.password(),
            enc_key,
            hash.data_mut(),
        );

        let hkdf =
            ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, enc_key);
        hkdf.expand(&[b"enc"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| Error::HkdfExpand)?
            .fill(enc_key)
            .map_err(|_| Error::HkdfExpand)?;

        let mac_key = &mut keys.data_mut()[32..64];
        hkdf.expand(&[b"mac"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| Error::HkdfExpand)?
            .fill(mac_key)
            .map_err(|_| Error::HkdfExpand)?;

        let keys = Keys::new(keys);
        let master_password_hash = PasswordHash::new(hash);

        Ok(Self {
            email: email.to_string(),
            keys,
            master_password_hash,
        })
    }
}
