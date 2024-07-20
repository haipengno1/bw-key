pub mod ser;
pub mod de;

#[macro_use]
pub mod key_type;
pub mod private_key;
pub mod message;
pub mod error;

pub use self::ser::to_bytes;
pub use self::de::from_bytes;

pub use self::private_key::*;
pub use self::message::*;
pub use self::error::*;

use serde::{Serialize, Deserialize};

#[allow(dead_code)]
pub trait Blob: Sized {
    fn to_blob(&self) -> ProtoResult<Vec<u8>>;
    fn from_blob(blob: &[u8]) -> ProtoResult<Self>;
}

impl<'a, T: Serialize + Deserialize<'a>> Blob for T {
    fn to_blob(&self) -> ProtoResult<Vec<u8>> {
        to_bytes(self)
    }
    
    fn from_blob(blob: &[u8]) -> ProtoResult<T> {
        from_bytes(blob)
    }
}
