use serde::{Deserialize, Serialize};

use super::private_key::PrivateKey;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub private_key: PrivateKey,
    pub comment: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Message {
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
    Failure,
    Success,
    Reserved7,
    Reserved8,
    Reserved9,
    Reserved10,
    Reserved11,
    Reserved12,
    Reserved13,
    Reserved14,
    Reserved15,
    Reserved16,
    AddIdentity(Identity),
    Reserved18,
    Reserved19,
    Reserved20,
}
