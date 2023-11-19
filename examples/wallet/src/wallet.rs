use crate::{api, components::EditText, read_user};
use leptos::{html::Input, *};
use near_client::{core::hash::CryptoHash, prelude::*};
use std::{rc::Rc, str::FromStr};

#[component]
pub(crate) fn Wallet(signer: Rc<Signer>) -> impl IntoView {
    let (on_error_account_id, on_error_account_id_setter) = create_signal(None);
    let account_id_input = create_node_ref::<Input>();

    let network = read_user().unwrap().network_type;
    let client = NearClient::new(network.into()).unwrap();

    let signer_cp = signer.clone();
    let client_cp = client.clone();
    let balance_res = create_resource(
        move || (),
        move |_| {
            let signer_cp = signer_cp.clone();
            let client_cp = client_cp.clone();
            async move {
                let balance = api::balance(client_cp, signer_cp.account()).await.unwrap();
                near_to_human(balance)
            }
        },
    );

    let (transactions, transactions_setter) = create_signal(Vec::<CryptoHash>::new());

    let send = create_action(move |account_id: &AccountId| {
        let signer_cp = signer.clone();
        let client_cp = client.clone();
        let account_id = account_id.clone();

        async move {
            let fut = api::transfer(client_cp, signer_cp, &account_id, near("1 Near"));
            match fut.await {
                Ok(hash) => {
                    transactions_setter.update(|transactions| transactions.insert(0, hash));
                    balance_res.refetch();
                }
                Err(err) => on_error_account_id_setter.update(|value| {
                    *value = Some(err.to_string());
                }),
            }
        }
    });

    view! {
        <div class="flex h-screen w-full flex-col items-center justify-start bg-gray-100">
            <div class="mt-20 flex h-fit max-h-full w-fit flex-col rounded bg-white px-10 py-10 shadow-2xl">
                <div class="mt-1 flex flex-row items-baseline space-x-1">
                    <div class="text-3xl font-bold text-black">Balance:</div>
                    <div class="text-3xl font-semibold text-gray-700">{ move || { balance_res.get() }}</div>
                </div>
                <div class="mb-6 mt-5">
                    <EditText placeholder={"mike.testnet".to_owned() } label={"Send 1 Near:".to_owned()} on_error=on_error_account_id on_error_setter=on_error_account_id_setter input=account_id_input/>
                    <SendBtn progress=send.pending().into() send on_error_account_id_setter account_id_input/>
                </div>
                <div class="flex w-full flex-col divide-y divide-gray-300 overflow-auto">
                    {
                        move || {
                            view! {
                                {
                                    transactions.get().into_iter().map(|hash| {
                                        view! {
                                            <div class="mb-1">
                                                <div class="mt-2 text-center font-mono text-sm text-gray-700">{ move || { hash.to_string() }}</div>
                                            </div>
                                        }
                                    }).collect::<Vec<_>>()
                                }
                            }
                        }
                    }
                </div>
            </div>
        </div>
    }
}

#[component]
fn SendBtn(
    progress: Signal<bool>,
    send: Action<AccountId, ()>,
    on_error_account_id_setter: WriteSignal<Option<String>>,
    account_id_input: NodeRef<Input>,
) -> impl IntoView {
    view! {
        <button class="mt-3 flex h-fit w-full flex-row items-center justify-center rounded-lg border bg-indigo-600 p-1.5 text-white hover:bg-indigo-700 active:bg-indigo-800"
            on:click={move |_| {
                let input = account_id_input.get().expect("input to exist");
                match AccountId::from_str(&input.value()) {
                    Ok(account_id) => {
                        send.dispatch(account_id);
                    }
                    Err(err) => {
                        on_error_account_id_setter.update(|value| {
                            *value = Some(err.to_string());
                        })
                    }
                }
            }}>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 25" fill="currentColor" class="mr-2 h-8 w-8">
                <path d="M3.478 2.405a.75.75 0 00-.926.94l2.432 7.905H13.5a.75.75 0 010 1.5H4.984l-2.432 7.905a.75.75 0 00.926.94 60.519 60.519 0 0018.445-8.986.75.75 0 000-1.218A60.517 60.517 0 003.478 2.405z" />
            </svg>
            <div class="text-3xl font-bold text-white">Send</div>
            {
                move || {
                    if progress.get() {
                        Some(view! {
                            <svg aria-hidden="true" role="status" class="me-3 ml-3 inline h-6 w-6 animate-spin text-white" viewBox="0 0 100 101" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z" fill="#E5E7EB" />
                                <path d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z" fill="currentColor" />
                            </svg>
                        })
                    } else {
                        None
                    }
                }
            }
        </button>
    }
}
