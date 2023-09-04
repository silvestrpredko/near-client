use itertools::Itertools;
use near_client::{prelude::*, Error, ViewAccessKeyCall};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use reqwest::Url;
use serde_json::json;
use std::{fs::write, str::FromStr};
use workspaces::{network::Sandbox, types::SecretKey, Worker};

// auxiliary structs and methods
fn near_client(worker: &Worker<Sandbox>) -> NearClient {
    let rpc_url = Url::parse(worker.rpc_addr().as_str()).unwrap();
    NearClient::new(rpc_url).unwrap()
}

async fn create_signer(
    worker: &Worker<Sandbox>,
    client: &NearClient,
    signer_acc_id: &AccountId,
) -> Signer {
    let sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&sk);
    let keypair = Keypair::new(sk).to_string();
    let workspaces_sk = SecretKey::from_str(&keypair).unwrap();
    let _ = worker
        .create_tla(
            workspaces::AccountId::from_str(signer_acc_id).unwrap(),
            workspaces_sk,
        )
        .await
        .unwrap();

    let view_access_key = client
        .view_access_key(signer_acc_id, &pk, Finality::None)
        .await
        .unwrap();

    Signer::from_secret_str(&keypair, signer_acc_id.clone(), view_access_key.nonce).unwrap()
}

async fn download_contract() -> Vec<u8> {
    let target = "https://github.com/near-examples/FT/raw/master/res/fungible_token.wasm";
    let target_path = temp_dir().into_path();
    let fname = "contract.wasm";
    let full_dest = format!("{}/{}", target_path.to_string_lossy(), fname);

    let contract_bytes = reqwest::get(target).await.unwrap().bytes().await.unwrap();
    write(full_dest, &contract_bytes).unwrap();
    contract_bytes.to_vec()
}

async fn clone_and_compile_wasm() -> Vec<u8> {
    let target_path = format!(
        "{}/tests/test-contract",
        std::env::current_dir().unwrap().display()
    );

    workspaces::compile_project(target_path.as_str())
        .await
        .unwrap()
}

fn random_bits() -> [u8; ED25519_SECRET_KEY_LENGTH] {
    let mut chacha = ChaChaRng::from_entropy();
    let mut secret_bytes = [0_u8; ED25519_SECRET_KEY_LENGTH];
    chacha.fill_bytes(&mut secret_bytes);
    secret_bytes
}

// tests themselves
#[tokio::test]
async fn contract_creation() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;
    let wasm = download_contract().await;

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .commit(Finality::None)
        .await
        .unwrap();
}

#[tokio::test]
async fn contract_function_call() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;
    let wasm = download_contract().await;

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .commit(Finality::None)
        .await
        .unwrap();

    client
        .function_call(&signer, &signer_account_id, "new_default_meta")
        .args(json!({
            "owner_id": &signer_account_id,
            "total_supply": "100",
        }))
        .gas(gas("300 T"))
        .commit(Finality::None)
        .await
        .unwrap();
}

#[tokio::test]
async fn contract_function_call_with_wrong_nonce() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;
    let wasm = download_contract().await;

    signer.update_nonce(0);

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .retry(Retry::ONCE)
        .commit(Finality::None)
        .await
        .unwrap();

    signer.update_nonce(0);

    client
        .function_call(&signer, &signer_account_id, "new_default_meta")
        .args(json!({
            "owner_id": &signer_account_id,
            "total_supply": "100",
        }))
        .gas(gas("300 T"))
        .retry(Retry::TWICE)
        .commit(Finality::None)
        .await
        .unwrap();
}

#[tokio::test]
async fn contract_function_call_failed() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;
    let wasm = download_contract().await;

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .commit(Finality::None)
        .await
        .unwrap();

    assert!(client
        .function_call(&signer, &signer_account_id, "new_default_meta")
        .args(json!({
            "owner_id": &signer_account_id,
            "total_suppl": "100",
        }))
        .gas(gas("300 T"))
        .commit(Finality::None)
        .await
        .is_err());

    client
        .function_call(&signer, &signer_account_id, "new_default_meta")
        .args(json!({
            "owner_id": &signer_account_id,
            "total_supply": "100",
        }))
        .gas(gas("300 T"))
        .commit(Finality::None)
        .await
        .unwrap();
}

#[tokio::test]
async fn errors() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;
    let wasm = download_contract().await;

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .commit(Finality::None)
        .await
        .unwrap();

    signer.update_nonce(0);

    // wrong nonce
    assert!(matches!(
        client
            .function_call(&signer, &signer_account_id, "new_default_meta")
            .args(json!({
                "owner_id": &signer_account_id,
                "total_supply": "100",
            }))
            .gas(gas("300 T"))
            .retry(Retry::NONE)
            .commit(Finality::None)
            .await,
        Err(Error::TxExecution(
            TxExecutionError::InvalidTxError(InvalidTxError::InvalidNonce { .. }),
            ..
        ))
    ));

    // wrong arguments
    assert!(matches!(
        client
            .function_call(&signer, &signer_account_id, "new_default_meta")
            .args(json!({
                "owner_id": &signer_account_id,
                "total_suppl": "100",
            }))
            .gas(gas("300 T"))
            .retry(Retry::ONCE)
            .commit(Finality::None)
            .await,
        Err(Error::TxExecution(
            TxExecutionError::ActionError(ActionError {
                kind: ActionErrorKind::FunctionCallError(
                    transaction_errors::FunctionCallError::ExecutionError(..)
                ),
                ..
            }),
            ..
        ))
    ));

    // wrong method
    assert!(matches!(
        client
            .function_call(&signer, &signer_account_id, "new_default_met")
            .args(json!({
                "owner_id": &signer_account_id,
                "total_supply": "100",
            }))
            .gas(gas("300 T"))
            .commit(Finality::None)
            .await,
        Err(Error::TxExecution(
            TxExecutionError::ActionError(ActionError {
                kind: ActionErrorKind::FunctionCallError(
                    transaction_errors::FunctionCallError::MethodResolveError(..)
                ),
                ..
            }),
            ..
        ))
    ));
}

// Temporary ignore tests cause of this issue, https://github.com/near/nearcore/issues/9143
#[ignore]
#[tokio::test]
async fn multiple_tests() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    let wasm = clone_and_compile_wasm().await;

    init_contract(&client, &signer_account_id, &signer, wasm).await;
    fc_no_params(&client, &signer_account_id, &signer).await;
    fc_with_one_param_and_result(&client, &signer_account_id, &signer).await;
    fc_with_param_and_result(&client, &signer_account_id, &signer).await;
    view_no_params(&client, &signer_account_id).await;
    view_with_params(&client, &signer_account_id).await;
}

async fn init_contract(
    client: &NearClient,
    contract_id: &AccountId,
    signer: &Signer,
    wasm: Vec<u8>,
) {
    client
        .deploy_contract(signer, contract_id, wasm)
        .commit(Finality::None)
        .await
        .unwrap();
}

async fn view_no_params(client: &NearClient, contract_id: &AccountId) {
    client
        .view::<u64>(contract_id, Finality::None, "show_id", None)
        .await
        .unwrap();
}

async fn view_with_params(client: &NearClient, contract_id: &AccountId) {
    client
        .view::<String>(
            contract_id,
            Finality::None,
            "show_type",
            Some(json!({"is_message": true})),
        )
        .await
        .unwrap();
}

// fc = function call
async fn fc_no_params(client: &NearClient, contract_id: &AccountId, signer: &Signer) {
    client
        .function_call(signer, contract_id, "increment")
        .gas(gas("300 T"))
        .commit(Finality::None)
        .await
        .unwrap();
}

async fn fc_with_one_param_and_result(
    client: &NearClient,
    contract_id: &AccountId,
    signer: &Signer,
) {
    let expected_result = "change message";
    let message = client
        .function_call(signer, contract_id, "change_message")
        .args(json!({ "message": expected_result }))
        .gas(gas("300 T"))
        .commit(Finality::Final)
        .await
        .unwrap()
        .output::<String>()
        .unwrap();

    assert_eq!(message, expected_result);
}

async fn fc_with_param_and_result(client: &NearClient, contract_id: &AccountId, signer: &Signer) {
    let expected_id = 666u64;
    let id = client
        .function_call(signer, contract_id, "change_id")
        .args(json!({ "id": expected_id }))
        .gas(gas("300 T"))
        .commit(Finality::Final)
        .await
        .unwrap()
        .output::<u64>()
        .unwrap();

    assert_eq!(id, expected_id);
}

// Temporary ignore tests cause of this issue, https://github.com/near/nearcore/issues/9143
#[ignore]
#[tokio::test]
async fn async_transaction() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    let wasm = clone_and_compile_wasm().await;

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .commit(Finality::None)
        .await
        .unwrap();

    let expected_result = "change message";
    let transaction_id = client
        .function_call(&signer, &signer_account_id, "change_message")
        .args(json!({ "message": expected_result }))
        .gas(gas("300 T"))
        .commit_async(Finality::Final)
        .await
        .unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await
            .expect("Wait async transaction timeout")
    });

    loop {
        let res = client.view_transaction(&transaction_id, &signer).await;

        if let Err(near_client::Error::ViewTransaction(_)) = &res {
            // try one more time
            continue;
        }

        // cancel timeout
        tx.send(()).unwrap();
        let msg = res.unwrap().output::<String>().unwrap();

        assert_eq!(msg, expected_result);
        break;
    }
}

#[tokio::test]
async fn view_access_key_success() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    let new_acc = AccountId::from_str("one.alice.test.near").unwrap();
    let secret_key = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&secret_key);

    let _ = client
        .create_account(&signer, &new_acc, pk, near_units::parse_near!("3 N"))
        .commit(Finality::None)
        .await
        .unwrap()
        .output::<serde_json::Value>();

    let _ = client
        .view_access_key(&new_acc, &pk, Finality::None)
        .await
        .unwrap();
}

#[tokio::test]
async fn view_access_key_failure() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);

    let new_acc = AccountId::from_str("one.alice.test.near").unwrap();
    let secret_key = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&secret_key);

    let access_key_err = client
        .view_access_key(&new_acc, &pk, Finality::None)
        .await
        .unwrap_err();

    assert!(matches!(
        access_key_err,
        Error::ViewAccessKeyCall(ViewAccessKeyCall::ParseError { .. })
    ));
}

#[tokio::test]
async fn view_contract_state() {
    use base64::{engine::general_purpose, Engine as _};

    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;
    let wasm = download_contract().await;

    client
        .deploy_contract(&signer, &signer_account_id, wasm)
        .commit(Finality::Final)
        .await
        .unwrap();

    client
        .function_call(&signer, &signer_account_id, "new_default_meta")
        .args(json!({
            "owner_id": &signer_account_id,
            "total_supply": "100",
        }))
        .gas(gas("300 T"))
        .commit(Finality::Final)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let state = client
        .view_contract_state(&signer_account_id)
        .await
        .map(|state| {
            state
                .values
                .into_iter()
                .map(|state_item| {
                    (
                        general_purpose::STANDARD_NO_PAD.encode(state_item.key),
                        general_purpose::STANDARD_NO_PAD.encode(state_item.value),
                    )
                })
                .collect_vec()
        })
        .unwrap();

    assert_eq!(
        state[0],
        (
            "U1RBVEU".to_owned(),
            "AQAAAGFkAAAAAAAAAAAAAAAAAAAAfQAAAAAAAAABAAAAbQ".to_owned()
        )
    );

    assert_eq!(
        state[1],
        (
            "YQ8AAABhbGljZS50ZXN0Lm5lYXI".to_owned(),
            "ZAAAAAAAAAAAAAAAAAAAAA".to_owned()
        )
    );

    assert_eq!(
        state[2],
        (
            "bQ".to_owned(),
            "CAAAAGZ0LTEuMC4wGwAAAEV4YW1wbGUgTkVBUiBmdW5naWJsZSB0b2tlbgcA\
            AABFWEFNUExFAX0CAABkYXRhOmltYWdlL3N2Zyt4bWwsJTNDc3ZnIHhtbG5zPSd\
            odHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Zycgdmlld0JveD0nMCAwIDI4OCAyODgnJ\
            TNFJTNDZyBpZD0nbCcgZGF0YS1uYW1lPSdsJyUzRSUzQ3BhdGggZD0nTTE4Ny41OCw3OS\
            44MWwtMzAuMSw0NC42OWEzLjIsMy4yLDAsMCwwLDQuNzUsNC4yTDE5MS44NiwxMDNhMS4yL\
            DEuMiwwLDAsMSwyLC45MXY4MC40NmExLjIsMS4yLDAsMCwxLTIuMTIuNzdMMTAyLjE4LDc3L\
            jkzQTE1LjM1LDE1LjM1LDAsMCwwLDkwLjQ3LDcyLjVIODcuMzRBMTUuMzQsMTUuMzQsMCwwL\
            DAsNzIsODcuODRWMjAxLjE2QTE1LjM0LDE1LjM0LDAsMCwwLDg3LjM0LDIxNi41aDBhMTUuM\
            zUsMTUuMzUsMCwwLDAsMTMuMDgtNy4zMWwzMC4xLTQ0LjY5YTMuMiwzLjIsMCwwLDAtNC43N\
            S00LjJMOTYuMTQsMTg2YTEuMiwxLjIsMCwwLDEtMi0uOTFWMTA0LjYxYTEuMiwxLjIsMCwwL\
            DEsMi4xMi0uNzdsODkuNTUsMTA3LjIzYTE1LjM1LDE1LjM1LDAsMCwwLDExLjcxLDUuNDNoMy\
            4xM0ExNS4zNCwxNS4zNCwwLDAsMCwyMTYsMjAxLjE2Vjg3Ljg0QTE1LjM0LDE1LjM0LDAsMCww\
            LDIwMC42Niw3Mi41aDBBMTUuMzUsMTUuMzUsMCwwLDAsMTg3LjU4LDc5LjgxWicvJTNFJTNDL2c\
            lM0UlM0Mvc3ZnJTNFAAAY"
                .to_owned()
        )
    );
}

#[tokio::test]
async fn create_account() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    let new_acc = AccountId::from_str("one.alice.test.near").unwrap();
    let secret_key = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&secret_key);

    let _ = client
        .create_account(&signer, &new_acc, pk, near_units::parse_near!("3 N"))
        .commit(Finality::Final)
        .await
        .unwrap()
        .output::<serde_json::Value>();

    let _ = client
        .view_access_key(&new_acc, &pk, Finality::None)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_account() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    let new_acc = AccountId::from_str("one.alice.test.near").unwrap();
    let secret_key = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let pk = Ed25519PublicKey::from(&secret_key);

    client
        .create_account(&signer, &new_acc, pk, near_units::parse_near!("3 N"))
        .commit(Finality::Final)
        .await
        .unwrap();

    let access_key = client
        .view_access_key(&new_acc, &pk, Finality::None)
        .await
        .unwrap();

    let acc_signer = Signer::from_secret(secret_key, new_acc.clone(), access_key.nonce);

    client
        .delete_account(&acc_signer, &new_acc, &signer_account_id)
        .commit(Finality::Final)
        .await
        .unwrap();

    let access_key_err = client
        .view_access_key(&new_acc, &pk, Finality::None)
        .await
        .unwrap_err();

    assert!(matches!(
        access_key_err,
        Error::ViewAccessKeyCall(ViewAccessKeyCall::ParseError { .. })
    ));
}

#[tokio::test]
async fn add_access_key_success() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    // add full access key permission
    let new_acc_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let new_acc_pk = Ed25519PublicKey::from(&new_acc_sk);
    let permission = AccessKeyPermission::FullAccess;

    client
        .add_access_key(&signer, &signer_account_id, new_acc_pk, permission.clone())
        .commit(Finality::None)
        .await
        .unwrap();

    let view_access_key = client
        .view_access_key(&signer_account_id, &new_acc_pk, Finality::None)
        .await
        .unwrap();

    let viewed_permission: AccessKeyPermission = view_access_key.permission.into();
    assert_eq!(permission, viewed_permission);

    // add permission for a single function execution only
    let new_acc_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let new_acc_pk = Ed25519PublicKey::from(&new_acc_sk);
    let permission = AccessKeyPermission::FunctionCall(FunctionCallPermission {
        allowance: None,
        receiver_id: "some_contract".to_string(),
        method_names: vec!["some_function".to_string()],
    });

    client
        .add_access_key(&signer, &signer_account_id, new_acc_pk, permission.clone())
        .commit(Finality::None)
        .await
        .unwrap();

    let view_access_key = client
        .view_access_key(&signer_account_id, &new_acc_pk, Finality::None)
        .await
        .unwrap();
    let viewed_permission: AccessKeyPermission = view_access_key.permission.into();
    assert_eq!(permission, viewed_permission);
}

#[tokio::test]
async fn add_access_key_failed() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let _ = create_signer(&worker, &client, &signer_account_id).await;

    let impostor_account_id = AccountId::from_str("impostor.test.near").unwrap();
    let impostor_signer = create_signer(&worker, &client, &impostor_account_id).await;

    // will fail due to the lack of permissions
    assert!(client
        .add_access_key(
            &impostor_signer,
            &signer_account_id,
            *impostor_signer.public_key(),
            AccessKeyPermission::FullAccess
        )
        .commit(Finality::None)
        .await
        .is_err());
}

#[tokio::test]
async fn view_access_key_list_success() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    // add full access key permission
    let new_acc_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let new_acc_pk = Ed25519PublicKey::from(&new_acc_sk);
    let permission = AccessKeyPermission::FullAccess;

    client
        .add_access_key(&signer, &signer_account_id, new_acc_pk, permission.clone())
        .commit(Finality::None)
        .await
        .unwrap();

    // add permission for a single function execution only
    let new_acc_sk = Ed25519SecretKey::try_from_bytes(&random_bits()).unwrap();
    let new_acc_pk = Ed25519PublicKey::from(&new_acc_sk);
    let permission = AccessKeyPermission::FunctionCall(FunctionCallPermission {
        allowance: None,
        receiver_id: "some_contract".to_string(),
        method_names: vec!["some_function".to_string()],
    });

    client
        .add_access_key(&signer, &signer_account_id, new_acc_pk, permission.clone())
        .commit(Finality::None)
        .await
        .unwrap();

    // let's count all of the keys
    let access_key_list = client
        .view_access_key_list(&signer_account_id, Finality::None)
        .await
        .unwrap();

    assert_eq!(access_key_list.keys.len(), 3);
}

#[tokio::test]
async fn delete_access_key() {
    let worker = workspaces::sandbox().await.unwrap();
    let client = near_client(&worker);
    let signer_account_id = AccountId::from_str("alice.test.near").unwrap();
    let signer = create_signer(&worker, &client, &signer_account_id).await;

    client
        .delete_access_key(&signer, &signer_account_id, signer.public_key().to_owned())
        .commit(Finality::None)
        .await
        .unwrap();

    let access_key_list = client
        .view_access_key_list(&signer_account_id, Finality::None)
        .await
        .unwrap();

    assert_eq!(access_key_list.keys.len(), 0);
}

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("near-client-test-")
        .tempdir()
        .unwrap()
}
