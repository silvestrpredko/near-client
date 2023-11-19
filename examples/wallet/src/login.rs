use crate::{NetworkType, components::EditText};
use leptos::{html::Input, *};
use near_client::prelude::*;
use std::str::FromStr;
use web_sys::MouseEvent;

#[component]
pub(crate) fn Login(
    #[prop(into)] on_login: Callback<(AccountId, Ed25519SecretKey, NetworkType, WriteSignal<RecoverButtonState>)>,
) -> impl IntoView {
    let (network_btn, on_button_click) = create_signal(ButtonSelected::Testnet);
    let (on_error_account_id, on_error_account_id_setter) = create_signal(None);
    let (on_error_private_key, on_error_private_key_setter) = create_signal(None);
    let (recover_btn_state, recover_btn_state_setter) = create_signal(RecoverButtonState::Ready);
    let account_id_input = create_node_ref::<Input>();
    let private_key_input = create_node_ref::<Input>();

    let on_click = move |_| {
        recover_btn_state_setter.set(RecoverButtonState::InProgress);
        let account_input = account_id_input
            .get()
            .expect("input_ref should be loaded by now");
        let private_key_input = private_key_input
            .get()
            .expect("input_ref should be loaded by now");

        if let Ok(account_id) = AccountId::from_str(&account_input.value()) {
            if let Ok(sk) = Ed25519SecretKey::from_expanded(&private_key_input.value()) {
                on_login.call((account_id, sk, network_btn.get().into(), recover_btn_state_setter));
            } else {
                on_error_private_key_setter
                    .update(|value| *value = Some("Wrong secret key or network!".to_owned()));
                recover_btn_state_setter.set(RecoverButtonState::Ready);
            }
        } else {
            on_error_account_id_setter.update(|value| *value = Some("Bad AccountId!".to_owned()));
            recover_btn_state_setter.set(RecoverButtonState::Ready);
        }
    };

    view! {
        <div class="flex h-screen justify-center bg-gray-100">
            <div class="mt-20 max-h-full h-fit rounded bg-white px-9 py-10 shadow-xl">
                <div>
                    <p class="mt-2 font-sans text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">Recover using Private Key</p>
                </div>

                <div class="mb-5"></div>

                <div class="flex justify-center">
                    <div class="relative inline-flex rounded-md shadow-sm" role="group">
                        { move || {
                            match network_btn.get() {
                                ButtonSelected::Testnet => {
                                    view! {
                                        <ButtonLeftSelected on_click=on_button_click/>
                                        <ButtonRight on_click=on_button_click/>
                                    }
                                }
                                ButtonSelected::Mainnet => {
                                    view! {
                                        <ButtonLeft on_click=on_button_click/>
                                        <ButtonRightSelected on_click=on_button_click/>
                                    }
                                }
                            }
                          }
                        }
                    </div>
                </div>

                <div class="mb-5"></div>

                <EditText placeholder={"mike.testnet".to_owned() } label={"Account Id:".to_owned()} on_error=on_error_account_id on_error_setter=on_error_account_id_setter input=account_id_input/>
                <EditText placeholder={"ed25519:abc123".to_owned() } label={"Private Key:".to_owned()} on_error=on_error_private_key on_error_setter=on_error_private_key_setter input=private_key_input/>

                { move || {
                    match recover_btn_state.get() {
                        RecoverButtonState::Ready => {
                            view! {
                                <RecoverButton on_click/>
                            }
                        }
                        RecoverButtonState::InProgress => {
                            view! {
                                <RecoverButtonInProgress/>
                            }
                        }
                    }
                  }
                }
            </div>
        </div>
    }
}

#[component]
fn ButtonLeftSelected(on_click: WriteSignal<ButtonSelected>) -> impl IntoView {
    view! {
        <button type="button" class="rounded-s-lg border border-indigo-600 bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            on:click=move |_| {
                on_click.update(|value| *value = ButtonSelected::Testnet);
            }>
            Testnet
        </button>
    }
}

#[component]
fn ButtonLeft(on_click: WriteSignal<ButtonSelected>) -> impl IntoView {
    view! {
        <button type="button" class="rounded-s-lg border border-gray-200 bg-white px-4 py-2 text-sm font-medium text-gray-900 hover:bg-gray-100 hover:text-indigo-700 active:border-indigo-600 active:bg-indigo-600 active:text-white"
            on:click=move |_| {
                on_click.update(|value| *value = ButtonSelected::Testnet);
            }>
            Testnet
        </button>
    }
}

#[component]
fn ButtonRightSelected(on_click: WriteSignal<ButtonSelected>) -> impl IntoView {
    view! {
        <button type="button" class="rounded-e-lg border border-indigo-600 bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            on:click=move |_| {
                on_click.update(|value| *value = ButtonSelected::Mainnet);
            }>
            Mainet
        </button>
    }
}

#[component]
fn ButtonRight(on_click: WriteSignal<ButtonSelected>) -> impl IntoView {
    view! {
        <button type="button" class="rounded-e-lg border border-gray-200 bg-white px-4 py-2 text-sm font-medium text-gray-900 hover:bg-gray-100 hover:text-indigo-700 active:border-indigo-600 active:bg-indigo-600 active:text-white"
            on:click=move |_| {
                on_click.update(|value| *value = ButtonSelected::Mainnet);
            }>
            Mainet
        </button>
    }
}

#[derive(Debug, Clone, Copy)]
enum ButtonSelected {
    Mainnet,
    Testnet,
}

impl From<ButtonSelected> for NetworkType {
    fn from(value: ButtonSelected) -> Self {
        match value {
            ButtonSelected::Mainnet => Self::Mainnet,
            ButtonSelected::Testnet => Self::Testnet,
        }
    }
}

#[component]
fn RecoverButtonInProgress() -> impl IntoView {
    view! {
        <button disabled type="button" class="mt-6 block w-full cursor-pointer rounded bg-indigo-600 px-4 py-2 text-center font-bold text-white hover:bg-indigo-700">
            <svg aria-hidden="true" role="status" class="me-3 inline h-4 w-4 animate-spin text-white" viewBox="0 0 100 101" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z" fill="#E5E7EB" />
                <path d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z" fill="currentColor" />
            </svg>
            Recovering...
        </button>
    }
}

#[component]
fn RecoverButton<F>(on_click: F) -> impl IntoView
where
    F: Fn(MouseEvent) + 'static,
{
    view! {
        <button class="mt-6 block w-full cursor-pointer rounded bg-indigo-600 px-4 py-2 text-center font-bold text-white hover:bg-indigo-700 active:bg-indigo-800" on:click=on_click>Recover</button>
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RecoverButtonState {
    Ready,
    InProgress,
}
