use std::io::{Cursor, Read, Write};
use std::ops::Deref;
use std::str::FromStr;

use bcrypt_pbkdf::bcrypt_pbkdf;
use byteorder::WriteBytesExt;
use cryptovec::CryptoVec;
use rand::prelude::*;
use rand::rngs::StdRng;
use zeroize::Zeroizing;

use crate::cipher::Cipher;
use crate::error::{Error, Result};
use crate::PrivateKey::Ed25519;
use crate::proto::{DssPrivateKey, EcDsaPrivateKey, Ed25519PrivateKey, PrivateKey, RsaPrivateKey};
use crate::sshbuf::{SshBuf, SshReadExt};

const KEY_MAGIC: &[u8] = b"openssh-key-v1\0";
const KDF_BCRYPT: &str = "bcrypt";
const KDF_NONE: &str = "none";
const DEFAULT_ROUNDS: u32 = 16;
const SALT_LEN: usize = 16;

pub const RSA_NAME: &str = "ssh-rsa";
pub const RSA_SHA256_NAME: &str = "rsa-sha2-256";
pub const RSA_SHA512_NAME: &str = "rsa-sha2-512";
pub const ED25519_NAME: &str = "ssh-ed25519";
pub const DSA_NAME: &str = "ssh-dss";
pub const NIST_P256_NAME: &str = "ecdsa-sha2-nistp256";
pub const NIST_P384_NAME: &str = "ecdsa-sha2-nistp384";
pub const NIST_P521_NAME: &str = "ecdsa-sha2-nistp521";

pub fn parse_keystr(pem: &[u8], passphrase: Option<&str>) -> Result<PrivateKey> {
    // HACK: Fix parsing problem of CRLF in nom_pem
    let s;
    let pemdata = if cfg!(windows) {
        s = std::str::from_utf8(pem)
            .map_err(|e| Error::InvalidPemFormat)?
            .replace("\r\n", "\n");
        nom_pem::decode_block(s.as_bytes()).map_err(|e| Error::InvalidPemFormat)?
    } else {
        nom_pem::decode_block(pem).map_err(|e| Error::InvalidPemFormat)?
    };

    match pemdata.block_type {
        "OPENSSH PRIVATE KEY" => {
            // Openssh format
            decode_ossh_priv(&pemdata.data, passphrase)
        }
        _ => Err(Error::UnsupportType),
    }
}

pub fn decode_ossh_priv(keydata: &[u8], passphrase: Option<&str>) -> Result<PrivateKey> {
    if keydata.len() >= 16 && &keydata[0..15] == KEY_MAGIC {
        let mut reader = Cursor::new(keydata);
        reader.set_position(15);

        let ciphername = reader.read_utf8()?;
        let kdfname = reader.read_utf8()?;
        let kdf = reader.read_string()?;
        let nkeys = reader.read_uint32()?;
        if nkeys != 1 {
            return Err(Error::InvalidKeyFormat);
        }
        reader.read_string()?; // Skip public keys
        let encrypted = reader.read_string()?;

        let mut secret_reader =
            decrypt_ossh_priv(&encrypted, passphrase, &ciphername, &kdfname, &kdf)?;
        let checksum0 = Zeroizing::new(secret_reader.read_uint32()?);
        let checksum1 = Zeroizing::new(secret_reader.read_uint32()?);
        if *checksum0 != *checksum1 {
            return Err(Error::IncorrectPass);
        }
        let pkey: PrivateKey = decode_key(&mut secret_reader)?;
        Ok(pkey)
    } else {
        Err(Error::InvalidKeyFormat)
    }
}

pub fn decrypt_ossh_priv(
    privkey_data: &[u8],
    passphrase: Option<&str>,
    ciphername: &str,
    kdfname: &str,
    kdf: &[u8],
) -> Result<SshBuf> {
    let cipher = Cipher::from_str(ciphername)?;

    // Check if empty passphrase but encrypted
    if (!passphrase.map_or(false, |pass| !pass.is_empty())) && !cipher.is_null() {
        return Err(Error::IncorrectPass);
    }
    // Check kdf type
    if kdfname != "none" && kdfname != "bcrypt" {
        return Err(Error::UnsupportCipher);
    }
    // Check if no kdf providing but encrypted
    if kdfname == "none" && !cipher.is_null() {
        return Err(Error::InvalidKeyFormat);
    }

    let blocksize = cipher.block_size();
    if privkey_data.len() < blocksize || privkey_data.len() % blocksize != 0 {
        return Err(Error::InvalidKeyFormat);
    }

    if !cipher.is_null() {
        let keyder = match kdfname {
            "bcrypt" => {
                if let Some(pass) = passphrase {
                    let mut kdfreader = Cursor::new(kdf);
                    let salt = kdfreader.read_string()?;
                    let round = kdfreader.read_uint32()?;
                    let mut output = Zeroizing::new(vec![0u8; cipher.key_len() + cipher.iv_len()]);
                    bcrypt_pbkdf(pass, &salt, round, &mut output).map_err(|e| Error::InvalidKey)?;
                    output
                } else {
                    // Should have already checked passphrase
                    return Err(Error::Unknown);
                }
            }
            _ => {
                return Err(Error::UnsupportCipher);
            }
        };

        // Splitting key & iv
        let key = &keyder[..cipher.key_len()];
        let iv = &keyder[cipher.key_len()..];

        // Decrypt
        let mut cvec = CryptoVec::new();
        cvec.resize(cipher.calc_buffer_len(privkey_data.len()));
        let n = cipher.decrypt_to(&mut cvec, privkey_data, key, iv)?;
        cvec.resize(n);

        Ok(SshBuf::with_vec(cvec))
    } else {
        let cvec = CryptoVec::from_slice(privkey_data);
        Ok(SshBuf::with_vec(cvec))
    }
}

#[allow(clippy::many_single_char_names)]
fn decode_key(reader: &mut SshBuf) -> Result<PrivateKey> {
    let keystring = Zeroizing::new(reader.read_utf8()?);
    let keyname: &str = keystring.as_str();
    let key = match keyname {
        RSA_NAME | RSA_SHA256_NAME | RSA_SHA512_NAME => {
            let n = reader.read_mpint()?;
            let e = reader.read_mpint()?;
            let d = reader.read_mpint()?;
            let iqmp = reader.read_mpint()?;
            let p = reader.read_mpint()?;
            let q = reader.read_mpint()?;
            // let one = BigNum::from_u32(1) .map_err(|e|Error::InvalidKey)?;
            // let dmp1 = &d % &(&p - &one);
            // let dmq1 = &d % &(&q - &one);
            let key = RsaPrivateKey {
                n,
                e,
                d,
                iqmp,
                p,
                q,
            };
            PrivateKey::Rsa(key)
        }
        DSA_NAME => {
            let p = reader.read_mpint()?;
            let q = reader.read_mpint()?;
            let g = reader.read_mpint()?;
            let pubkey = reader.read_mpint()?;
            let privkey = reader.read_mpint()?;
            let key = DssPrivateKey {
                p,
                q,
                g,
                y: pubkey,
                x: privkey,
            };
            PrivateKey::Dss(key)
        }
        NIST_P256_NAME | NIST_P384_NAME | NIST_P521_NAME => {
            let curvename = Zeroizing::new(reader.read_utf8()?);

            let pubkey = Zeroizing::new(reader.read_string()?);
            let privkey = reader.read_mpint()?;

            let key = EcDsaPrivateKey {
                identifier: curvename.deref().clone(),
                q: pubkey.to_vec(),
                d: privkey,
            };
            PrivateKey::EcDsa(key)
        }
        ED25519_NAME => {
            let pk = Zeroizing::new(reader.read_string()?).to_vec();
            let sk = Zeroizing::new(reader.read_string()?).to_vec(); // Actually is an ed25519 keypair
            let k = Ed25519PrivateKey {
                enc_a: pk,
                k_enc_a: sk,
            };
            PrivateKey::Ed25519(k)
        }
        _ => return Err(Error::UnsupportType),
    };
    Ok(key)
}