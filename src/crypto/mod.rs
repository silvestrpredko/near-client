//! Fast and efficient Rust implementation of ed25519 key generation, signing, and verification
//! Used a [Dalek](https://github.com/dalek-cryptography/ed25519-dalek) cryptography
//! By default near is using two kinds of keys. ed25519 and secp256k1.
//! For simplicity secp256k1 is removed and used ed25519 only.

#[macro_use]
mod serde_impl {
    macro_rules! serde_impl {
        ($key_type: ty) => {
            impl serde::Serialize for $key_type {
                fn serialize<S>(
                    &self,
                    serializer: S,
                ) -> std::result::Result<
                    <S as serde::Serializer>::Ok,
                    <S as serde::Serializer>::Error,
                >
                where
                    S: serde::Serializer,
                {
                    serializer.serialize_str(&Key::string(self))
                }
            }

            impl<'de> serde::Deserialize<'de> for $key_type {
                fn deserialize<D>(
                    deserializer: D,
                ) -> std::result::Result<Self, <D as serde::Deserializer<'de>>::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                    <$key_type>::from_string(&s).map_err(|err| {
                        serde::de::Error::custom(format!("Deserialization failed: `{}`", err))
                    })
                }
            }
        };
    }
}

pub mod dhx;
pub mod ed25519;
/// Crypto prelude
pub mod prelude {
    pub use super::{
        dhx::{PublicKey, SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH},
        ed25519::{
            Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, Keypair,
            ED25519_PUBLIC_KEY_LENGTH, ED25519_SECRET_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
        },
        Error, Key,
    };
}

use itertools::Itertools;

type Result<T> = std::result::Result<T, Error>;

pub(crate) const ED25519: &str = "ed25519";
pub(crate) const X25519: &str = "x25519";

/// ## Key
/// **KEY_LENGTH** - It's a key size for ed25519 or x25519
pub trait Key<const KEY_LENGTH: usize>: Sized {
    /// **KEY_TYPE** - Key type, for internal usage to reduce a boilerplate code.
    /// It's a prefix for a key string serialization. Possible values are ["ed25519", "x25519"]
    const KEY_TYPE: &'static str;

    /// Parse an encoded string to the corresponding [`Key`]
    fn from_string(key: &str) -> Result<Self> {
        let (key_type, bs58_encoded) = split_encoded_str(key)?;

        if key_type != Self::KEY_TYPE {
            return Err(Error::WrongKeyType {
                key_type: key_type.to_owned(),
                expected_key_type: Self::KEY_TYPE,
            });
        }

        let bytes = bs58::decode(bs58_encoded)
            .into_vec()
            .map_err(|err| Error::from_string::<Self>(bs58_encoded.to_owned(), err.to_string()))?;
        Self::try_from_bytes(&bytes)
    }

    /// Return a string representation of a [`Key`]
    /// The string is split with a delimiter ":"
    /// The first part is a `X25519` or `ED25519` prefix
    /// The second part is a bs58 encoded key
    fn string(&self) -> String {
        format!(
            "{}:{}",
            Self::KEY_TYPE,
            bs58::encode(self.to_bytes()).into_string()
        )
    }

    /// Parse a bytes slice to the corresponding [`Key`]
    fn try_from_bytes(buf: &[u8]) -> Result<Self>;

    /// Return a byte representation of a [`Key`]
    /// The size of a slice defined with a `KEY_LENGTH`
    fn to_bytes(&self) -> [u8; KEY_LENGTH];
}

/// Errors that happens during crypto operations
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Convert Error, happens during conversion from a bytes
    #[error("Couldn't convert key from bytes \"{data}\" into \"{key_name}\", because of: {cause}")]
    ConvertFromBytes {
        /// Key type ed25519 or x25519
        key_name: &'static str,
        /// Data that cause an error
        data: String,
        /// Actual cause
        cause: String,
    },
    /// Convert Error, happens during conversion from a string
    #[error(
        "Couldn't convert key from string \"{data}\" into \"{key_name}\", because of: {cause}"
    )]
    ConvertFromString {
        /// Key type ed25519 or x25519
        key_name: &'static str,
        /// Data that cause an error
        data: String,
        /// Actual cause
        cause: String,
    },
    /// Used an unknown key prefix
    #[error("The key format \"{0}\" seems different from ed25519 or x25519 format")]
    UnknownKeyType(String),
    /// Key type error
    #[error(
        "The expected key type \"{expected_key_type}\" is different from actual \"{key_type}\""
    )]
    WrongKeyType {
        /// Something different than ed25519 or x25519
        key_type: String,
        /// Key type ed25519 or x25519
        expected_key_type: &'static str,
    },
    /// Signature verification Error
    #[error("Signature \"{0}\" verification failed")]
    Verification(String),
}

impl Error {
    pub(crate) fn from_string<T>(data: String, cause: String) -> Self {
        Self::ConvertFromString {
            key_name: std::any::type_name::<T>()
                .rsplit("::")
                .next()
                .unwrap_or_default(),
            data,
            cause,
        }
    }

    pub(crate) fn from_bytes<T>(data: &[u8], cause: String) -> Self {
        Self::ConvertFromBytes {
            key_name: std::any::type_name::<T>()
                .rsplit("::")
                .next()
                .unwrap_or_default(),
            data: bs58::encode(data).into_string(),
            cause,
        }
    }
}

/// Split encoded [`str`] to key prefix and bs58 encoded string
fn split_encoded_str(encoded: &str) -> Result<(&str, &str)> {
    match encoded.split(':').next_tuple() {
        Some((key_type @ ED25519, bs58_encoded) | (key_type @ X25519, bs58_encoded)) => {
            Ok((key_type, bs58_encoded))
        }
        _ => Err(Error::UnknownKeyType(encoded.to_owned())),
    }
}

#[cfg(test)]
mod tests {

    use super::{split_encoded_str, Error, ED25519, X25519};

    #[test]
    fn split_encoded() {
        let bs58_str = bs58::encode(vec![0, 0, 0]).into_string();
        assert!(matches!(
                split_encoded_str(&format!("ed25519:{bs58_str}")),
                Ok((key_type, s)) if key_type == ED25519 && s == bs58_str));
        assert!(matches!(
                split_encoded_str(&format!("x25519:{bs58_str}")),
                Ok((key_type, s)) if key_type == X25519 && s == bs58_str));
        assert!(matches!(
            split_encoded_str(&bs58_str),
            Err(Error::UnknownKeyType(..))
        ));
    }
}
