#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde::de::{self, Deserializer, SeqAccess, Visitor, Error};
#[allow(unused_imports)]
use serde::ser::{Serializer, SerializeTuple};
#[allow(unused_imports)]
use super::error::ProtoError;

pub trait KeyType {
    const KEY_TYPE: &'static str;
    fn key_type(&self) -> String {
        Self::KEY_TYPE.to_string()
    }
}

#[allow(dead_code)]
pub trait KeyTypeEnum {
    fn key_type(&self) -> String;
}

#[macro_export]
macro_rules! impl_key_type_enum_ser_de {
    ($class_name:ident, $(($variant_name:path, $variant_class:ty)),*) => {
        impl KeyTypeEnum for $class_name {
            fn key_type(&self) -> String {
                match self {
                    $(
                        $variant_name(key) => key.key_type(),
                    )*
                }
            }
        }
        
        impl Serialize for $class_name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut serialize_tuple = serializer.serialize_tuple(2)?;
                
                match self {
                    $(
                        $variant_name(key) => {
                            serialize_tuple.serialize_element(&key.key_type())?;
                            serialize_tuple.serialize_element(key)?;
                        }
                    ),*
                };
                serialize_tuple.end()
            }
        }
        
        impl<'de> Deserialize<'de> for $class_name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct KeyVisitor;
                
                impl<'de> Visitor<'de> for KeyVisitor {
                    type Value = $class_name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("Key with format (type, key)")
                    }

                    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                    where
                        V: SeqAccess<'de>,
                    {
                        let key_type: String = seq.next_element()?
                            .ok_or_else(|| Error::invalid_length(0, &self))?;
                        let key_type_str = key_type.as_str();
                        
                        $(
                            if key_type_str.starts_with(<$variant_class>::KEY_TYPE) {
                                let key: $variant_class = seq.next_element()?
                                    .ok_or_else(|| Error::invalid_length(1, &self))?;
                                return Ok($variant_name(key))
                            }
                        )*
                        
                        Err(Error::custom(ProtoError::UnexpectedVariant))
                    }
                }
                
                deserializer.deserialize_tuple(2, KeyVisitor)
            }
        }
    };
}