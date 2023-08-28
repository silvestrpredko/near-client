//! ### Diffie–Hellman key exchange with ed25519 elliptic curves algorithm
//! ---
//! Used Dalek cryptography, and implemented [`Borsh`](https://borsh.io/) serialization for it

use super::{
    ed25519::{Ed25519PublicKey, Ed25519SecretKey},
    Error, Key, Result, X25519,
};
use curve25519_dalek::{
    scalar::{clamp_integer, Scalar},
    MontgomeryPoint,
};
use std::{
    fmt::Display,
    io::{Error as IoError, ErrorKind},
};

use borsh::{BorshDeserialize, BorshSerialize};

/// The public key size for Diffie-Hellman
pub const PUBLIC_KEY_LENGTH: usize = 32_usize;
/// The secret key size for Diffie-Hellman
pub const SECRET_KEY_LENGTH: usize = 32_usize;

/// The secret key for Diffie-Hellman
pub struct SecretKey(Scalar);

impl BorshSerialize for SecretKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let secret_key = Self::try_from_bytes(std::mem::take(buf))
            .map_err(|err| IoError::new(ErrorKind::InvalidData, err))?;
        Ok(secret_key)
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Self::deserialize(&mut &buf[..])
    }
}

/// The public key for Diffie-Hellman
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PublicKey(MontgomeryPoint);

impl BorshSerialize for PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.0.as_bytes())
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let public_key = Self::try_from_bytes(std::mem::take(buf))
            .map_err(|err| IoError::new(ErrorKind::InvalidData, err))?;
        Ok(public_key)
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Self::deserialize(&mut &buf[..])
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl Key<SECRET_KEY_LENGTH> for SecretKey {
    const KEY_TYPE: &'static str = X25519;

    #[inline]
    fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != SECRET_KEY_LENGTH {
            return Err(Error::from_bytes::<PublicKey>(
                buf,
                format!(
                    "input buffer size \"{}\" not equal to secret key size \"{SECRET_KEY_LENGTH}\"",
                    buf.len()
                ),
            ));
        }

        let mut temp_buf = [0_u8; SECRET_KEY_LENGTH];
        temp_buf.copy_from_slice(buf);

        Ok(Self(Scalar::from_bytes_mod_order(clamp_integer(temp_buf))))
    }
}

impl Key<PUBLIC_KEY_LENGTH> for PublicKey {
    const KEY_TYPE: &'static str = X25519;

    #[inline]
    fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != PUBLIC_KEY_LENGTH {
            return Err(Error::from_bytes::<PublicKey>(
                buf,
                format!(
                    "input buffer size \"{}\" not equal to public key size \"{PUBLIC_KEY_LENGTH}\"",
                    buf.len()
                ),
            ));
        }

        let mut temp_buf = [0_u8; PUBLIC_KEY_LENGTH];
        temp_buf.copy_from_slice(buf);

        Ok(Self(MontgomeryPoint(temp_buf)))
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(secret: &'a SecretKey) -> PublicKey {
        Self(MontgomeryPoint::mul_base(&secret.0))
    }
}

impl SecretKey {
    /// Creates a secret part from other participant public part of keypair
    ///
    /// ## Arguments
    /// - **other_public** - Another public part [`PublicKey`] of the key exchange process
    ///
    /// ## Returns
    /// Byte array with a shared secret key
    ///
    pub fn exchange(&self, other_public: &PublicKey) -> [u8; SECRET_KEY_LENGTH] {
        (self.0 * other_public.0).to_bytes()
    }
}

impl From<Ed25519PublicKey> for PublicKey {
    fn from(key: Ed25519PublicKey) -> Self {
        PublicKey(key.0.to_montgomery())
    }
}

impl From<Ed25519SecretKey> for SecretKey {
    fn from(key: Ed25519SecretKey) -> Self {
        use ed25519_dalek::SigningKey;
        SecretKey(SigningKey::from_bytes(key.as_bytes()).to_scalar())
    }
}

serde_impl!(SecretKey);
serde_impl!(PublicKey);
