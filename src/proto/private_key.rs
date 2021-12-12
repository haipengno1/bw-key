use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Error};
use serde::ser::{Serializer, SerializeTuple};
use super::error::ProtoError;
use super::key_type::{KeyType, KeyTypeEnum};

pub type MpInt = Vec<u8>;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DssPrivateKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt,
    pub x: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Ed25519PrivateKey {
    pub enc_a: Vec<u8>,
    pub k_enc_a: Vec<u8>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateKey {
    pub n: MpInt,
    pub e: MpInt,
    pub d: MpInt,
    pub iqmp: MpInt,
    pub p: MpInt,
    pub q: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EcDsaPrivateKey {
    pub identifier: String,
    pub q: MpInt,
    pub d: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PrivateKey {
    Dss(DssPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Rsa(RsaPrivateKey),
    EcDsa(EcDsaPrivateKey)
}
impl TryFrom<PKey<Private>> for PrivateKey {
    type Error = &'static str;

    fn try_from(pkey: PKey<Private>) -> Result<Self, Self::Error> {
        match pkey.id() {
            openssl::pkey::Id::RSA => {
                let rsa_key:Rsa<Private>= Rsa::try_from(pkey).unwrap();
                let n = rsa_key.n().to_vec_padded(257).unwrap();
                let e = rsa_key.e().to_vec();
                let d = rsa_key.d().to_vec();
                let p = rsa_key.p().unwrap().to_vec_padded(129).unwrap();
                let q = rsa_key.q().unwrap().to_vec_padded(129).unwrap();

                let key = RsaPrivateKey{
                    n,
                    e,
                    d,
                    iqmp: Vec::new(),
                    p,
                    q
                };
                Ok(PrivateKey::Rsa(key))
            }
            openssl::pkey::Id::HMAC => Err("not support type"),
            openssl::pkey::Id::DSA => Err("not support type"),
            openssl::pkey::Id::DH => Err("not support type"),
            openssl::pkey::Id::EC =>Err("not support type"),
            #[cfg(ossl111)]
            Id::ED25519 => Err("not support type"),
            #[cfg(ossl111)]
            Id::ED448 => Err("not support type"),
            _ =>  Err("unknown type"),
        }
    }
}
impl KeyType for RsaPrivateKey {
    const KEY_TYPE: &'static str = "ssh-rsa";
}

impl KeyType for DssPrivateKey {
    const KEY_TYPE: &'static str = "ssh-dss";
}

impl KeyType for Ed25519PrivateKey {
    const KEY_TYPE: &'static str = "ssh-ed25519";
}

impl KeyType for EcDsaPrivateKey {
    const KEY_TYPE: &'static str = "ecdsa-sha2";
    
    fn key_type(&self) -> String {
        format!("{}-{}", Self::KEY_TYPE, self.identifier)
    }
}

impl_key_type_enum_ser_de!(
    PrivateKey,
    (PrivateKey::Dss, DssPrivateKey),
    (PrivateKey::Rsa, RsaPrivateKey),
    (PrivateKey::EcDsa, EcDsaPrivateKey),
    (PrivateKey::Ed25519, Ed25519PrivateKey)
);
