use std::str::FromStr;

use borsh::BorshDeserialize;
use ed25519_dalek::SigningKey;
use near_client::crypto::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

#[test]
fn try_from_bytes_ed25519() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);
    let _ = Ed25519PublicKey::try_from_bytes(pk.as_bytes()).unwrap();

    assert!(matches!(
        Ed25519PublicKey::try_from_bytes(&[0, 0, 0]),
        Err(Error::ConvertFromBytes { .. })
    ));

    assert!(matches!(
        Ed25519SecretKey::try_from_bytes(&[0, 0, 0]),
        Err(Error::ConvertFromBytes { .. })
    ));
}

#[test]
fn to_string_ed25519() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);

    assert_eq!(
        format!("ed25519:{}", bs58::encode(sk.as_bytes()).into_string()),
        sk.string()
    );
    assert_eq!(
        format!("ed25519:{}", bs58::encode(pk.as_bytes()).into_string()),
        pk.string()
    );
}

#[test]
fn from_string_ed25519() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);

    let _ = Ed25519SecretKey::from_string(
        format!("ed25519:{}", bs58::encode(sk.as_bytes()).into_string()).as_str(),
    )
    .unwrap();

    let _ = Ed25519PublicKey::from_string(
        format!("ed25519:{}", bs58::encode(pk.as_bytes()).into_string()).as_str(),
    )
    .unwrap();

    assert!(matches!(
        Ed25519PublicKey::from_string(
            format!("x25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str()
        ),
        Err(Error::WrongKeyType { .. })
    ));

    assert!(matches!(
        Ed25519SecretKey::from_string(
            format!("x25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str(),
        ),
        Err(Error::WrongKeyType { .. })
    ));

    assert!(matches!(
        Ed25519SecretKey::from_string(format!("ed25519:{}", "==1234%#").as_str(),),
        Err(Error::ConvertFromString { .. })
    ));

    assert!(matches!(
        Ed25519PublicKey::from_string(
            format!("ed25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str(),
        ),
        Err(Error::ConvertFromBytes { .. })
    ));

    assert!(matches!(
        Ed25519PublicKey::from_string(format!("ed25519:{}", "==1234%#").as_str(),),
        Err(Error::ConvertFromString { .. })
    ));
}

#[test]
fn from_expanded() {
    let sk = SigningKey::from_bytes(&random_bits());
    let exp_str = format!("ed25519:{}", bs58::encode(sk.to_bytes()).into_string());
    let sk = Ed25519SecretKey::from_expanded(&exp_str).unwrap();

    assert_eq!(sk.as_bytes(), &sk.to_bytes());
}

#[test]
fn from_expanded_fail() {
    let sk = SigningKey::from_bytes(&random_bits());
    let exp_str = bs58::encode(sk.to_bytes()).into_string();
    assert!(matches!(
        Ed25519SecretKey::from_expanded(&exp_str),
        Err(Error::UnknownKeyType { .. })
    ));

    let exp_str = format!("ed25519:{}", bs58::encode(vec![0, 0, 0]).into_string());
    assert!(matches!(
        Ed25519SecretKey::from_expanded(&exp_str),
        Err(Error::ConvertFromBytes { .. })
    ));

    let exp_str = format!("ed25519:{}", "===%123@@#31");
    assert!(matches!(
        Ed25519SecretKey::from_expanded(&exp_str),
        Err(Error::ConvertFromString { .. })
    ));
}

#[test]
fn try_from_bytes_x25519() {
    let sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = PublicKey::from(&sk);
    let _ = PublicKey::try_from_bytes(&pk.to_bytes()).unwrap();

    assert!(matches!(
        PublicKey::try_from_bytes(&[0, 0, 0]),
        Err(Error::ConvertFromBytes { .. })
    ));

    assert!(matches!(
        SecretKey::try_from_bytes(&[0, 0, 0]),
        Err(Error::ConvertFromBytes { .. })
    ));
}

#[test]
fn to_string_x25519() {
    let sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = PublicKey::from(&sk);

    assert_eq!(
        format!("x25519:{}", bs58::encode(&sk.to_bytes()).into_string()),
        sk.string()
    );
    assert_eq!(
        format!("x25519:{}", bs58::encode(&pk.to_bytes()).into_string()),
        pk.string()
    );
}

#[test]
fn from_string_x25519() {
    let sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = PublicKey::from(&sk);

    let _ = SecretKey::from_string(
        format!("x25519:{}", bs58::encode(&sk.to_bytes()).into_string()).as_str(),
    )
    .unwrap();

    let _ = PublicKey::from_string(
        format!("x25519:{}", bs58::encode(&pk.to_bytes()).into_string()).as_str(),
    )
    .unwrap();

    assert!(matches!(
        PublicKey::from_string(
            format!("ed25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str()
        ),
        Err(Error::WrongKeyType { .. })
    ));

    assert!(matches!(
        SecretKey::from_string(
            format!("ed25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str(),
        ),
        Err(Error::WrongKeyType { .. })
    ));

    assert!(matches!(
        SecretKey::from_string(
            format!("x25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str(),
        ),
        Err(Error::ConvertFromBytes { .. })
    ));

    assert!(matches!(
        SecretKey::from_string(format!("x25519:{}", "==1234%#").as_str(),),
        Err(Error::ConvertFromString { .. })
    ));

    assert!(matches!(
        PublicKey::from_string(
            format!("x25519:{}", bs58::encode(vec![0, 0, 0]).into_string()).as_str(),
        ),
        Err(Error::ConvertFromBytes { .. })
    ));

    assert!(matches!(
        PublicKey::from_string(format!("x25519:{}", "==1234%#").as_str(),),
        Err(Error::ConvertFromString { .. })
    ));
}

#[test]
fn public_key_verify() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);

    let signature = sk.sign(b"message");
    pk.verify(b"message", &signature).unwrap();
}

#[test]
fn keypair_verify() {
    let keypair = Keypair::new(Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap());
    let signature = keypair.sign(b"message");
    keypair.verify(b"message", &signature).unwrap();
}

#[test]
fn key_exchange() {
    let alice_sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let alice_pk = PublicKey::from(&alice_sk);

    let bob_sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let bob_pk = PublicKey::from(&bob_sk);

    assert_eq!(alice_sk.exchange(&bob_pk), bob_sk.exchange(&alice_pk));
}

#[test]
fn key_exchange_multiple() {
    let alice_sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let alice_pk = PublicKey::from(&alice_sk);

    let bob_sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let bob_pk = PublicKey::from(&bob_sk);

    let karl_sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let karl_pk = PublicKey::from(&karl_sk);

    assert_ne!(karl_sk.exchange(&alice_pk), bob_sk.exchange(&alice_pk));
    assert_ne!(karl_sk.exchange(&karl_pk), karl_sk.to_bytes());
    assert_eq!(alice_sk.exchange(&karl_pk), karl_sk.exchange(&alice_pk));
    assert_eq!(alice_sk.exchange(&bob_pk), bob_sk.exchange(&alice_pk));
}

#[test]
fn borsh_ed25519() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let sk_bytes = borsh::to_vec(&sk).unwrap();
    let pk = Ed25519PublicKey::from(&sk);
    let pk_bytes = borsh::to_vec(&pk).unwrap();

    assert_eq!(pk_bytes.len(), pk.as_bytes().len() + 1);
    assert_eq!(pk_bytes[0], 0);
    assert_eq!(sk_bytes.len(), sk.as_bytes().len());

    let sk = Ed25519SecretKey::try_from_slice(&sk_bytes).unwrap();
    let pk = Ed25519PublicKey::try_from_slice(&pk_bytes).unwrap();

    let signature_bytes = borsh::to_vec(&sk.sign(b"message")).unwrap();
    pk.verify(
        b"message",
        &Ed25519Signature::try_from_slice(&signature_bytes).unwrap(),
    )
    .unwrap();
}

#[test]
fn borsh_x25519() {
    let sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let sk_bytes = borsh::to_vec(&sk).unwrap();
    let pk = PublicKey::from(&sk);
    let pk_bytes = borsh::to_vec(&pk).unwrap();

    // just try to serialize and deserialize. We doesn't support key-exchange for now
    let _ = SecretKey::try_from_slice(&sk_bytes).unwrap();
    let _ = PublicKey::try_from_slice(&pk_bytes).unwrap();
}

#[test]
fn keypair_from_str() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);

    let mut sk_bytes = sk.to_bytes().to_vec();
    sk_bytes.extend_from_slice(&pk.to_bytes());

    let keypair_bs58 = format!("ed25519:{}", bs58::encode(sk_bytes).into_string());

    let keypair = Keypair::from_str(&keypair_bs58).unwrap();

    assert_eq!(keypair.secret_key().to_bytes(), sk.to_bytes());
    assert_eq!(keypair.public_key().to_bytes(), pk.to_bytes());
}

#[test]
fn keypair_to_string() {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);

    let mut sk_bytes = sk.to_bytes().to_vec();
    sk_bytes.extend_from_slice(&pk.to_bytes());

    let keypair_bs58 = format!("ed25519:{}", bs58::encode(sk_bytes).into_string());
    let keypair = Keypair::new(sk);

    assert_eq!(keypair_bs58, keypair.to_string());
}

#[test]
fn convert_from_edwards_to_montgomery() {
    let alice_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let bob_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();

    let alice_pk = Ed25519PublicKey::from(&alice_sk);
    let bob_pk = Ed25519PublicKey::from(&bob_sk);

    let alice_sk_dhx = SecretKey::try_from(alice_sk).unwrap();
    let bob_sk_dhx = SecretKey::try_from(bob_sk).unwrap();

    let alice_pk_dhx = PublicKey::try_from(alice_pk).unwrap();
    let bob_pk_dhx = PublicKey::try_from(bob_pk).unwrap();

    assert_eq!(
        alice_sk_dhx.exchange(&bob_pk_dhx),
        bob_sk_dhx.exchange(&alice_pk_dhx)
    );
}

#[test]
fn convert_from_edwards_to_montgomery_partially() {
    let alice_sk = SecretKey::try_from_bytes(&random_bits()).unwrap();
    let bob_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();

    let alice_pk = PublicKey::from(&alice_sk);
    let bob_pk = Ed25519PublicKey::from(&bob_sk);

    let bob_sk_dhx = SecretKey::try_from(bob_sk).unwrap();
    let bob_pk_dhx = PublicKey::try_from(bob_pk).unwrap();

    assert_eq!(
        alice_sk.exchange(&bob_pk_dhx),
        bob_sk_dhx.exchange(&alice_pk)
    );
}

fn random_bits() -> [u8; ED25519_SECRET_KEY_LENGTH] {
    let mut chacha = ChaChaRng::from_entropy();
    let mut secret_bytes = [0_u8; ED25519_SECRET_KEY_LENGTH];
    chacha.fill_bytes(&mut secret_bytes);
    secret_bytes
}
