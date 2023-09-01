//! ### ed25519 elliptic curve signing algorithm
//! ---
//! Used Dalek cryptography, and implemented [`Borsh`](https://borsh.io/) serialization for them

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    hash::{Hash, Hasher},
    io::{Error as IoError, ErrorKind},
    str::FromStr,
};

use super::{split_encoded_str, Error, Key, Result, ED25519};

pub use ed25519_dalek::{
    KEYPAIR_LENGTH as ED25519_KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH, SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};

/// The public key wrapper around ed25519-dalek public key
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Ed25519PublicKey(pub(super) VerifyingKey);

impl Ed25519PublicKey {
    /// Verifies the signature of the data
    pub fn verify(&self, data: &[u8], signature: &Ed25519Signature) -> Result<()> {
        self.0
            .verify(data, &signature.0)
            .map_err(|_| Error::Verification(signature.string()))
    }

    /// Returns a key in the raw bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }
}

impl Key<ED25519_PUBLIC_KEY_LENGTH> for Ed25519PublicKey {
    const KEY_TYPE: &'static str = ED25519;

    #[inline]
    fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(buf: &[u8]) -> Result<Self> {
        VerifyingKey::try_from(buf)
            .map(Self)
            .map_err(|err| Error::from_bytes::<Ed25519PublicKey>(buf, err.to_string()))
    }
}

impl BorshDeserialize for Ed25519PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // The first byte is a key type, let's skip it because currently is used ed25519 only
        // This implementation of [`Ed25519PublicKey`] is required by Near protocol
        let temp_buf = std::mem::take(buf)
            .split_first()
            .map(|(.., key)| key)
            .unwrap_or_default();
        Ed25519PublicKey::try_from_bytes(temp_buf)
            .map_err(|err| IoError::new(ErrorKind::InvalidData, err))
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        BorshDeserialize::deserialize(&mut &buf[..])
    }
}

impl BorshSerialize for Ed25519PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&0_u8, writer)?;
        writer.write_all(self.0.as_bytes())
    }
}

impl From<&Ed25519SecretKey> for Ed25519PublicKey {
    fn from(sk: &Ed25519SecretKey) -> Self {
        Self(VerifyingKey::from(&SigningKey::from(sk.0)))
    }
}

// This `Hash` implementation is safe since it retains the property
// `k1 == k2 ⇒ hash(k1) == hash(k2)`.
#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for Ed25519PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u8(0u8);
        state.write(self.0.as_bytes());
    }
}

impl Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

/// The secret key wrapper around ed25519-dalek secret key
pub struct Ed25519SecretKey(SecretKey);

impl Ed25519SecretKey {
    /// Sign a `data` with a private key
    pub fn sign(&self, data: &[u8]) -> Ed25519Signature {
        Ed25519Signature(SigningKey::from(self.0).sign(data))
    }

    /// Get a [`Ed25519SecretKey`] from a [`str`]
    pub fn from_expanded(key: &str) -> Result<Self> {
        let (key_type, bs58_encoded) = split_encoded_str(key)?;

        if key_type != Self::KEY_TYPE {
            return Err(Error::WrongKeyType {
                key_type: key_type.to_owned(),
                expected_key_type: Self::KEY_TYPE,
            });
        }

        let expanded_key_bytes = bs58::decode(bs58_encoded)
            .into_vec()
            .map_err(|err| {
                Error::from_string::<Ed25519SecretKey>(bs58_encoded.to_owned(), err.to_string())
            })?
            .into_iter()
            .take(ED25519_SECRET_KEY_LENGTH)
            .collect_vec();
        Self::try_from_bytes(&expanded_key_bytes)
    }

    /// Returns a key in the raw bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; ED25519_SECRET_KEY_LENGTH] {
        &self.0
    }
}

impl Key<ED25519_SECRET_KEY_LENGTH> for Ed25519SecretKey {
    const KEY_TYPE: &'static str = ED25519;

    #[inline]
    fn to_bytes(&self) -> [u8; ED25519_SECRET_KEY_LENGTH] {
        self.0.to_owned()
    }

    fn try_from_bytes(buf: &[u8]) -> Result<Self> {
        SigningKey::try_from(buf)
            .map(|key| Ed25519SecretKey(key.to_bytes()))
            .map_err(|err| Error::from_bytes::<Ed25519SecretKey>(buf, err.to_string()))
    }
}

impl BorshDeserialize for Ed25519SecretKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        Ed25519SecretKey::try_from_bytes(std::mem::take(buf))
            .map_err(|err| IoError::new(ErrorKind::InvalidData, err))
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        BorshDeserialize::deserialize(&mut &buf[..])
    }
}

impl BorshSerialize for Ed25519SecretKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// The signature wrapper around ed25519-dalek signature
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ed25519Signature(Signature);

impl Key<ED25519_SIGNATURE_LENGTH> for Ed25519Signature {
    const KEY_TYPE: &'static str = ED25519;

    #[inline]
    fn to_bytes(&self) -> [u8; ED25519_SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(buf: &[u8]) -> Result<Self> {
        Signature::try_from(buf)
            .map(Self)
            .map_err(|err| Error::from_bytes::<Ed25519Signature>(buf, err.to_string()))
    }
}

impl BorshDeserialize for Ed25519Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // The first byte is a key type, let's skip it because currently is used ed25519 only
        // This implementation of [`Ed25519Signature`] is required by Near protocol
        let temp_buf = std::mem::take(buf)
            .split_first()
            .map(|(.., key)| key)
            .unwrap_or_default();
        Ed25519Signature::try_from_bytes(temp_buf)
            .map_err(|err| IoError::new(ErrorKind::InvalidData, err))
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        BorshDeserialize::deserialize(&mut &buf[..])
    }
}

impl BorshSerialize for Ed25519Signature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&0_u8, writer)?;
        writer.write_all(&self.0.to_bytes())
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for Ed25519Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

/// Contains public and secret user keys
#[derive(Serialize, Deserialize)]
pub struct Keypair {
    public_key: Ed25519PublicKey,
    secret_key: Ed25519SecretKey,
}

impl Keypair {
    /// Creates a new keypair from the [`Ed25519SecretKey`]
    pub fn new(secret_key: Ed25519SecretKey) -> Self {
        let public_key = Ed25519PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Creates a new keypair from the string representation
    ///
    /// **Example**: ```ed25519:5nEtNZTBUPJUwB7v9tfCgm1xfp1E7wXcZdWDpz1JwKckqG5pqstumaqRHJjtfFZMtik4TpgCVmmpvpxjEcq3CTLx```
    pub fn from_expanded_secret(expanded: &str) -> Result<Self> {
        let secret_key = Ed25519SecretKey::from_expanded(expanded)?;
        let public_key = Ed25519PublicKey::from(&secret_key);
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Sign the data with a private key
    pub fn sign(&self, data: &[u8]) -> Ed25519Signature {
        self.secret_key.sign(data)
    }

    /// Verify the signed data
    ///
    /// ## Arguments
    ///
    /// - signature - The signature that is an output of [sign](#Keypair::sign())
    ///
    /// ## Returns
    ///
    /// - ```Ok(())```, If the signature valid
    /// - ```Err```, if signature verification failed
    pub fn verify(&self, data: &[u8], signature: &Ed25519Signature) -> Result<()> {
        self.public_key.verify(data, signature)
    }

    /// Returns the public key from the keypair
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// Returns the secret key from the keypair
    pub fn secret_key(&self) -> &Ed25519SecretKey {
        &self.secret_key
    }
}

impl ToString for Keypair {
    fn to_string(&self) -> String {
        let keypair_bytes = self
            .secret_key()
            .as_bytes()
            .iter()
            .chain(self.public_key().as_bytes().iter())
            .copied()
            .collect_vec();

        format!("{ED25519}:{}", bs58::encode(keypair_bytes).into_string())
    }
}

impl FromStr for Keypair {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (key_type, data) = split_encoded_str(s)?;

        if key_type != ED25519 {
            return Err(Error::WrongKeyType {
                key_type: key_type.to_owned(),
                expected_key_type: ED25519,
            });
        }

        let byte_data = bs58::decode(data)
            .into_vec()
            .map_err(|err| Error::from_string::<Keypair>(data.to_owned(), err.to_string()))?;

        if byte_data.len() != ED25519_KEYPAIR_LENGTH {
            return Err(Error::from_bytes::<Keypair>(
                &byte_data,
                format!(
                    "Keypair byte array length doesn't equal\
                     to requested length {ED25519_KEYPAIR_LENGTH}"
                ),
            ));
        }

        Ok(Self {
            secret_key: Ed25519SecretKey::try_from_bytes(&byte_data[..ED25519_SECRET_KEY_LENGTH])?,
            public_key: Ed25519PublicKey::try_from_bytes(&byte_data[ED25519_SECRET_KEY_LENGTH..])?,
        })
    }
}

serde_impl!(Ed25519PublicKey);
serde_impl!(Ed25519SecretKey);
serde_impl!(Ed25519Signature);
