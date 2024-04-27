use std::io::Cursor;
use std::ops::Deref;
use std::str::FromStr;

use bcrypt_pbkdf::bcrypt_pbkdf;
use cryptovec::CryptoVec;
use openssl::bn::BigNumRef;
use openssl::dsa::Dsa;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use zeroize::Zeroizing;

use crate::cipher::Cipher;
use crate::error::{Error, Result};
use crate::proto::{DssPrivateKey, EcDsaPrivateKey, Ed25519PrivateKey, PrivateKey, RsaPrivateKey};
use crate::sshbuf::{SshBuf, SshReadExt};

const KEY_MAGIC: &[u8] = b"openssh-key-v1\0";

pub const RSA_NAME: &str = "ssh-rsa";
pub const RSA_SHA256_NAME: &str = "rsa-sha2-256";
pub const RSA_SHA512_NAME: &str = "rsa-sha2-512";
pub const ED25519_NAME: &str = "ssh-ed25519";
pub const DSA_NAME: &str = "ssh-dss";
pub const NIST_P256_NAME: &str = "ecdsa-sha2-nistp256";
pub const NIST_P384_NAME: &str = "ecdsa-sha2-nistp384";
pub const NIST_P521_NAME: &str = "ecdsa-sha2-nistp521";

fn padded_elem(elem: &BigNumRef)->Result<Vec<u8>>{
    let e=elem.to_vec();
    let e_len=e.len()+1;
    elem.to_vec_padded(e_len as i32).map_err(|_|Error::InvalidKey)
}
impl TryInto<PrivateKey> for PKey<Private> {
    type Error = Error;

    fn try_into(self) -> Result<PrivateKey> {
        match self.id() {
            Id::RSA => {
                let rsa_key:Rsa<Private>= Rsa::try_from(self).unwrap();
                let n = padded_elem(rsa_key.n())?;
                let e = padded_elem(rsa_key.e())?;
                let d = padded_elem(rsa_key.d())?;
                let iqmp = padded_elem(rsa_key.iqmp().unwrap())?;
                let p = padded_elem(rsa_key.p().unwrap())?;
                let q = padded_elem(rsa_key.q().unwrap())?;
                let key = RsaPrivateKey{
                    n,
                    e,
                    d,
                    iqmp,
                    p,
                    q
                };
                Ok(PrivateKey::Rsa(key))
            }
            Id::DSA => {
                let dsa_key:Dsa<Private>= Dsa::try_from(self).unwrap();
                let p = padded_elem(dsa_key.p())?;
                let q = padded_elem(dsa_key.q())?;
                let g = padded_elem(dsa_key.g())?;
                let pubkey = padded_elem(dsa_key.pub_key())?;
                let privkey =padded_elem(dsa_key.priv_key())?;
                let key = DssPrivateKey{
                    p,
                    q,
                    g,
                    y: pubkey,
                    x: privkey
                };
                Ok(PrivateKey::Dss(key))
            },
            Id::EC => {
                Err(Error::UnsupportFormat)
            },
            _ =>   Err(Error::InvalidKeyFormat)
        }
    }
}

pub fn parse_keystr(pem: &[u8], passphrase: Option<&str>) -> Result<PrivateKey> {
    let pemdata= pem::parse(pem).unwrap();
    match pemdata.tag() {
        "OPENSSH PRIVATE KEY" => {
            // Openssh format
            decode_ossh_priv(&pemdata.contents(), passphrase)
        }
        "PRIVATE KEY" |
        "ENCRYPTED PRIVATE KEY" |//PKCS#8 format
        "DSA PRIVATE KEY" |//  Openssl DSA Key
        "EC PRIVATE KEY"  |//  Openssl EC Key
        "BEGIN PRIVATE KEY"  |//  Openssl Ed25519 Key
        "RSA PRIVATE KEY" => {
            // Openssl RSA Key
            let pkey:PKey<Private>=match passphrase {
                Some(passphrase)=>{
                    PKey::private_key_from_pem_passphrase(pem, passphrase.as_bytes())
                        .map_err(|_| Error::IncorrectPass)?
                }
                _ => {PKey::private_key_from_pem(pem).map_err(|_| Error::InvalidKeyFormat)?}
            };
            Ok(pkey.try_into()?)
        }
        _ => Err(Error::UnsupportType),
    }
}

 fn decode_ossh_priv(keydata: &[u8], passphrase: Option<&str>) -> Result<PrivateKey> {
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

fn decrypt_ossh_priv(
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
                    bcrypt_pbkdf(pass, &salt, round, &mut output).map_err(|_| Error::InvalidKey)?;
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