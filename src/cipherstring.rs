use crate::prelude::*;

use block_modes::BlockMode as _;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub enum CipherString {
    Symmetric {
        // ty: 2 (AES_256_CBC_HMAC_SHA256)
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Option<Vec<u8>>,
    },
    Asymmetric {
        // ty: 4 (RSA_2048_OAEP_SHA1)
        ciphertext: Vec<u8>,
    },
}

impl CipherString {
    pub fn new(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidCipherString {
                reason: "couldn't find type".to_string(),
            });
        }

        let ty = parts[0].as_bytes();
        if ty.len() != 1 {
            return Err(Error::UnimplementedCipherStringType {
                ty: parts[0].to_string(),
            });
        }

        let ty = ty[0] - b'0';
        let contents = parts[1];

        match ty {
            2 => {
                let parts: Vec<&str> = contents.split('|').collect();
                if parts.len() < 2 || parts.len() > 3 {
                    return Err(Error::InvalidCipherString {
                        reason: format!(
                            "type 2 cipherstring with {} parts",
                            parts.len()
                        ),
                    });
                }

                let iv = STANDARD.decode(parts[0])
                    .context(crate::error::InvalidBase64Snafu)?;
                let ciphertext = STANDARD.decode(parts[1])
                    .context(crate::error::InvalidBase64Snafu)?;
                let mac = if parts.len() > 2 {
                    Some(
                        STANDARD.decode(parts[2])
                            .context(crate::error::InvalidBase64Snafu)?,
                    )
                } else {
                    None
                };

                Ok(Self::Symmetric {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            4 | 6 => {
                // the only difference between 4 and 6 is the HMAC256
                // signature appended at the end
                // https://github.com/bitwarden/jslib/blob/785b681f61f81690de6df55159ab07ae710bcfad/src/enums/encryptionType.ts#L8
                // format is: <cipher_text_b64>|<hmac_sig>
                let contents = contents.split('|').next().unwrap();
                let ciphertext = STANDARD.decode(contents)
                    .context(crate::error::InvalidBase64Snafu)?;
                Ok(Self::Asymmetric { ciphertext })
            }
            _ => Err(Error::UnimplementedCipherStringType {
                ty: ty.to_string(),
            }),
        }
    }
    pub fn from_raw_bytes(s: &[u8]) -> Result<Self> {
        let enc_type =s[0];
        match enc_type {
            2 => {
                if s.len() <= 49 { // 1 + 16 + 32 + ctLength
                    return Err(Error::InvalidCipherString {
                        reason: format!(
                            "type 2 cipherstring with {} error length",
                            s.len()
                        ),
                    });
                }
                let iv=s[1 .. 17].to_vec();
                let mac: Option<Vec<u8>>=Some(s[17 .. 49].to_vec());
                let ciphertext=s[49..].to_vec();

                Ok(Self::Symmetric {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            _ => Err(Error::UnimplementedCipherStringType {
                ty: enc_type.to_string(),
            }),
        }
    }

    pub fn decrypt_symmetric(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Symmetric {
                iv,
                ciphertext,
                mac,
            } => {
                let cipher = decrypt_common_symmetric(
                    keys,
                    iv,
                    ciphertext,
                    mac.as_deref(),
                )?;
                cipher
                    .decrypt_vec(ciphertext)
                    .context(crate::error::DecryptSnafu)
            }
            _ => Err(Error::InvalidCipherString {
                reason:
                    "found an asymmetric cipherstring, expecting symmetric"
                        .to_string(),
            }),
        }
    }

    pub fn decrypt_locked_symmetric(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<crate::locked::Vec> {
        match self {
            Self::Symmetric {
                iv,
                ciphertext,
                mac,
            } => {
                let mut res = crate::locked::Vec::new();
                res.extend(ciphertext.iter().copied());
                let cipher = decrypt_common_symmetric(
                    keys,
                    iv,
                    ciphertext,
                    mac.as_deref(),
                )?;
                cipher
                    .decrypt(res.data_mut())
                    .context(crate::error::DecryptSnafu)?;
                Ok(res)
            }
            _ => Err(Error::InvalidCipherString {
                reason:
                    "found an asymmetric cipherstring, expecting symmetric"
                        .to_string(),
            }),
        }
    }
}

fn decrypt_common_symmetric(
    keys: &crate::locked::Keys,
    iv: &[u8],
    ciphertext: &[u8],
    mac: Option<&[u8]>,
) -> Result<block_modes::Cbc<aes::Aes256, block_modes::block_padding::Pkcs7>>
{
    if let Some(mac) = mac {
        let key =
            ring::hmac::Key::new(ring::hmac::HMAC_SHA256, keys.mac_key());
        // it'd be nice to not have to pull this into a vec, but ring
        // doesn't currently support non-contiguous verification. see
        // https://github.com/briansmith/ring/issues/615
        let data: Vec<_> =
            iv.iter().chain(ciphertext.iter()).copied().collect();

        if ring::hmac::verify(&key, &data, mac).is_err() {
            return Err(Error::InvalidMac);
        }
    }

    // ring doesn't currently support CBC ciphers, so we have to do it
    // manually. see https://github.com/briansmith/ring/issues/588
    Ok(block_modes::Cbc::<
            aes::Aes256,
            block_modes::block_padding::Pkcs7,
        >::new_from_slices(keys.enc_key(), iv)
        .context(crate::error::CreateBlockModeSnafu)?)
}

impl std::fmt::Display for CipherString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Symmetric {
                iv,
                ciphertext,
                mac,
            } => {
                let iv = STANDARD.encode(&iv);
                let ciphertext = STANDARD.encode(&ciphertext);
                if let Some(mac) = &mac {
                    let mac = STANDARD.encode(&mac);
                    write!(f, "2.{}|{}|{}", iv, ciphertext, mac)
                } else {
                    write!(f, "2.{}|{}", iv, ciphertext)
                }
            }
            Self::Asymmetric { ciphertext } => {
                let ciphertext = STANDARD.encode(&ciphertext);
                write!(f, "4.{}", ciphertext)
            }
        }
    }
}
