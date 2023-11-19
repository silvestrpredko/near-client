mod api;
mod components;
mod header;
mod login;
mod wallet;
mod footer;

use crate::login::RecoverButtonState;
use gloo_storage::{LocalStorage, Storage};
use header::Header;
use leptos::*;
use leptos_meta::*;
use login::Login;
use footer::Footer;
use near_client::prelude::*;
use serde::{Deserialize, Serialize};
use std::{rc::Rc, str::FromStr};
use url::Url;
use wallet::Wallet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum NetworkType {
    Mainnet,
    Testnet,
}

#[derive(Serialize, Deserialize)]
struct User {
    account_id: AccountId,
    secret_key: Ed25519SecretKey,
    network_type: NetworkType,
    nonce: Nonce,
}

fn main() {
    _ = console_log::init();
    console_error_panic_hook::set_once();
    provide_meta_context();

    let (on_signer, signer_setter) = create_signal(None);
    let on_login = on_login(signer_setter);

    let signer = read_user().map(|user| {
        Rc::new(Signer::from_secret(
            user.secret_key,
            user.account_id,
            user.nonce,
        ))
    });

    if let Some(signer) = signer.clone() {
        signer_setter.set(Some(signer));
    }

    mount_to_body(move || {
        view! {
            <Header signer=on_signer.into() signer_setter/>
            { move || {
                if let Some(signer) = on_signer.get() {
                    view! {
                        <Wallet signer/>
                    }
                } else {
                    view! {
                        <Login on_login/>
                    }
                }
              }
            }
            <Footer/>
        }
    });
}

fn on_login(
    signer_setter: WriteSignal<Option<Rc<Signer>>>,
) -> Callback<(
    AccountId,
    Ed25519SecretKey,
    NetworkType,
    WriteSignal<RecoverButtonState>,
)> {
    Callback::<(
        AccountId,
        Ed25519SecretKey,
        NetworkType,
        WriteSignal<RecoverButtonState>,
    )>::new(move |(account_id, sk, network_type, recover_btn)| {
        spawn_local(async move {
            match api::signer(network_type.into(), account_id, sk).await {
                Ok(signer) => {
                    let sk_copy =
                        Ed25519SecretKey::try_from_bytes(signer.secret_key().as_bytes()).unwrap();
                    let account_id = signer.account().clone();
                    write_user(User {
                        account_id,
                        secret_key: sk_copy,
                        network_type,
                        nonce: signer.nonce(),
                    });
                    signer_setter.set(Some(Rc::new(signer)));
                }
                Err(err) => {
                    log::error!("Can't recover the secret key cause of {err}");
                    recover_btn.set(RecoverButtonState::Ready);
                }
            }
        });
    })
}

fn read_user() -> Option<User> {
    LocalStorage::get::<User>("user").ok()
}

fn write_user(user: User) {
    let _ = LocalStorage::set("user", user);
}

fn clear_user() {
    LocalStorage::clear();
}

impl From<NetworkType> for Url {
    fn from(value: NetworkType) -> Self {
        match value {
            NetworkType::Mainnet => Self::from_str("https://rpc.mainnet.near.org").unwrap(),
            NetworkType::Testnet => Self::from_str("https://rpc.testnet.near.org").unwrap(),
        }
    }
}
