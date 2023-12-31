use crate::{
    components::{
        CallResult, TransactionInfo, ViewAccessKey, ViewAccessKeyList, ViewAccessKeyListResult,
        ViewAccessKeyResult, ViewResult, ViewStateResult,
    },
    near_primitives_light::{
        transaction::{
            Action, AddKeyAction, CreateAccountAction, DeleteAccountAction, DeleteKeyAction,
            DeployContractAction, FunctionCallAction, TransferAction,
        },
        types::Finality,
        views::{
            AccessKeyListView, AccessKeyView, BlockView, ExecutionOutcomeWithIdView,
            FinalExecutionOutcomeView, FinalExecutionStatus, StatusResponse,
        },
    },
    prelude::{transaction_errors::TxExecutionErrorContainer, InvalidTxError, TxExecutionError},
    rpc::{client::RpcClient, CauseKind, Error as RpcError, NearError, NearErrorVariant},
    utils::{extract_logs, serialize_arguments, serialize_transaction},
    Error, Result, ViewAccessKeyCall,
};
use near_primitives_core::{
    account::{id::AccountId, AccessKey, AccessKeyPermission, Account},
    hash::CryptoHash,
    types::{Balance, Gas, Nonce},
};
use std::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::crypto::prelude::*;
use base64::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use url::Url;

type AtomicNonce = AtomicU64;

/// Used for signing a transactions
pub struct Signer {
    keypair: Keypair,
    account_id: AccountId,
    nonce: AtomicNonce,
}

impl Signer {
    /// Creates a [`Signer`] from [`str`]
    #[allow(clippy::result_large_err)]
    pub fn from_secret_str(secret_key: &str, account_id: AccountId, nonce: Nonce) -> Result<Self> {
        Ok(Self {
            keypair: Keypair::from_expanded_secret(secret_key).map_err(Error::CreateSigner)?,
            account_id,
            nonce: AtomicU64::new(nonce),
        })
    }

    /// Creates a [`Signer`] from [`Ed25519SecretKey`]
    pub fn from_secret(secret_key: Ed25519SecretKey, account_id: AccountId, nonce: Nonce) -> Self {
        Self {
            keypair: Keypair::new(secret_key),
            account_id,
            nonce: AtomicU64::new(nonce),
        }
    }

    /// Sign a transaction
    ///
    /// Arguments
    ///
    /// - data - Serialized transaction with a [Borsh](https://borsh.io/)
    pub fn sign(&self, data: &[u8]) -> Ed25519Signature {
        self.keypair.sign(data)
    }

    /// Returns the [public key](Ed25519PublicKey) of a [`Signer`]
    pub fn public_key(&self) -> &Ed25519PublicKey {
        self.keypair.public_key()
    }

    /// Returns the [secret key](Ed25519SecretKey) of a [`Signer`]
    pub fn secret_key(&self) -> &Ed25519SecretKey {
        self.keypair.secret_key()
    }

    /// Returns an [account](AccountId) of a [`Signer`]
    pub fn account(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the key nonce
    pub fn nonce(&self) -> Nonce {
        self.nonce.load(Ordering::Relaxed)
    }

    /// Update the key nonce
    pub fn update_nonce(&self, nonce: Nonce) {
        self.nonce.store(nonce, Ordering::Relaxed);
    }

    /// Increment the key nonce.
    /// Function is thread safe
    pub fn increment_nonce(&self, value: u64) {
        self.nonce.fetch_add(value, Ordering::AcqRel);
    }
}

/// Near RPC client
#[derive(Clone)]
pub struct NearClient {
    pub(crate) rpc_client: RpcClient,
}

impl NearClient {
    /// Creates a new client
    ///
    /// ## Arguments
    ///
    /// - url - A RPC Endpoint [Url](https://docs.near.org/api/rpc/providers)
    #[allow(clippy::result_large_err)]
    pub fn new(url: Url) -> Result<Self> {
        Ok(Self {
            rpc_client: RpcClient::new(url).map_err(Error::CreateClient)?,
        })
    }

    /// Queries network and returns block for given height or hash
    pub async fn block(&self, finality: Finality) -> Result<CryptoHash> {
        self.rpc_client
            .request("block", Some(json!({ "finality": finality })))
            .await
            .map_err(Error::BlockCall)
            .and_then(|block_res| {
                serde_json::from_value::<BlockView>(block_res).map_err(Error::DeserializeBlock)
            })
            .map(|block_view| block_view.header.hash)
    }

    /// Allows you to call a contract method as a view function.
    ///
    /// Arguments
    ///
    /// - contract_id - The [`AccountId`] where smart contract is located
    /// - finality - [`Finality`]
    /// - method - Function that is declared in a smart contract
    /// - args - Function arguments, could be empty
    pub async fn view<'a, T: DeserializeOwned>(
        &'a self,
        contract_id: &'a AccountId,
        finality: Finality,
        method: &'static str,
        args: Option<Value>,
    ) -> Result<ViewOutput<T>> {
        let args = BASE64_STANDARD_NO_PAD.encode(serialize_arguments(args)?);
        self.rpc_client
            .request(
                "query",
                Some(json!({
                    "request_type": "call_function",
                    "finality": finality,
                    "account_id": contract_id,
                    "method_name": method,
                    "args_base64": args
                })),
            )
            .await
            .map_err(Error::ViewCall)
            .and_then(|it| {
                serde_json::from_value::<ViewResult>(it).map_err(Error::DeserializeViewCall)
            })
            .and_then(|view_res| match view_res.result {
                CallResult::Ok(data) => Ok(ViewOutput {
                    logs: view_res.logs,
                    data: serde_json::from_slice(&data).map_err(Error::DeserializeResponseView)?,
                }),
                CallResult::Err(cause) => Err(Error::ViewCall(RpcError::NearProtocol(
                    NearError::handler(cause),
                ))),
            })
    }

    /// Returns information about a single access key for given account
    ///
    /// Arguments
    ///
    /// - account_id - The user [`AccountId`] in a Near network
    /// - public_key - The user [`Ed25519PublicKey`] in a Near network
    pub async fn view_access_key(
        &self,
        account_id: &AccountId,
        public_key: &Ed25519PublicKey,
        finality: Finality,
    ) -> Result<AccessKeyView> {
        self.rpc_client
            .request(
                "query",
                Some(json!({
                    "request_type": "view_access_key",
                    "finality": finality,
                    "account_id": account_id,
                    "public_key": public_key,
                })),
            )
            .await
            .map_err(|err| Error::ViewAccessKeyCall(ViewAccessKeyCall::Rpc(err)))
            .and_then(|it| {
                serde_json::from_value::<ViewAccessKey>(it)
                    .map_err(Error::DeserializeAccessKeyViewCall)
            })
            .and_then(|view_access_key| match view_access_key.result {
                ViewAccessKeyResult::Ok(access_key_view) => Ok(access_key_view),
                ViewAccessKeyResult::Err { error, logs } => {
                    Err(Error::ViewAccessKeyCall(ViewAccessKeyCall::ParseError {
                        error,
                        logs,
                    }))
                }
            })
    }

    /// Returns list of all access keys for the given account
    ///
    /// Arguments
    /// - account_id - The user [`AccountId`] in a Near network
    pub async fn view_access_key_list(
        &self,
        account_id: &AccountId,
        finality: Finality,
    ) -> Result<AccessKeyListView> {
        self.rpc_client
            .request(
                "query",
                Some(json!({
                    "request_type": "view_access_key_list",
                    "finality": finality,
                    "account_id": account_id
                })),
            )
            .await
            .map_err(|err| Error::ViewAccessKeyListCall(ViewAccessKeyCall::Rpc(err)))
            .and_then(|it| {
                serde_json::from_value::<ViewAccessKeyList>(it)
                    .map_err(Error::DeserializeAccessKeyListViewCall)
            })
            .and_then(|view_access_key_list| match view_access_key_list.result {
                ViewAccessKeyListResult::Ok(access_key_list_view) => Ok(access_key_list_view),
                ViewAccessKeyListResult::Err { error, logs } => Err(Error::ViewAccessKeyListCall(
                    ViewAccessKeyCall::ParseError { error, logs },
                )),
            })
    }

    /// Returns information regarding contract state
    /// in a key-value sequence representation
    ///
    /// Arguments
    ///
    /// - account_id - The contract [`AccountId`] in a Near network
    pub async fn view_contract_state(&self, account_id: &AccountId) -> Result<ViewStateResult> {
        self.rpc_client
            .request(
                "query",
                Some(json!({
                    "request_type": "view_state",
                    "finality": Finality::Final,
                    "account_id": account_id,
                    "prefix_base64": ""
                })),
            )
            .await
            .map_err(Error::ViewCall)
            .and_then(|it| {
                serde_json::from_value::<ViewStateResult>(it).map_err(Error::DeserializeViewCall)
            })
    }

    /// Returns general status of a given node
    /// (sync status, nearcore node version, protocol version, etc),
    /// and the current set of validators.
    pub async fn network_status(&self) -> Result<StatusResponse> {
        self.rpc_client
            .request("status", None)
            .await
            .map_err(Error::RpcError)
            .and_then(|it| {
                serde_json::from_value::<StatusResponse>(it).map_err(Error::DeserializeResponseView)
            })
    }

    /// Queries status of a transaction by hash,
    /// returning the final transaction result and details of all receipts.
    ///
    /// Arguments
    ///
    /// - transaction_id - Transaction [`CryptoHash`]
    /// - signer - [`Signer`] that contain information regarding user [`Keypair`]
    ///
    /// Return
    ///
    /// If a transaction still processing will be returned an error [`Error::ViewTransaction`],
    /// in this case can try to execute [`view_transaction`](NearClient::view_transaction()) one more time, or a several times.
    /// If an error differs from [`Error::ViewTransaction`] that something goes totally wrong and
    /// you should stop to try executing [`view_transaction`](NearClient::view_transaction()) with the same arguments/signer
    pub async fn view_transaction<'a>(
        &'a self,
        transaction_id: &'a CryptoHash,
        signer: &'a Signer,
    ) -> Result<Output> {
        let params = Value::Array(vec![
            serde_json::to_value(transaction_id)
                .map_err(|err| Error::SerializeTxViewArg("transaction_id", err))?,
            serde_json::to_value(signer.account())
                .map_err(|err| Error::SerializeTxViewArg("signer_acc_id", err))?,
        ]);

        let execution_outcome = self
            .rpc_client
            .request("EXPERIMENTAL_tx_status", Some(params))
            .await
            .map_err(Error::ViewTransaction)
            .and_then(|execution_outcome| {
                serde_json::from_value::<FinalExecutionOutcomeView>(execution_outcome)
                    .map_err(Error::DeserializeExecutionOutcome)
            })?;

        proceed_outcome(signer, execution_outcome)
    }

    /// Returns basic account information.
    /// ## Arguments
    ///
    /// - `account_id` - The account ID [`AccountId`] for which to retrieve information.
    ///
    /// ## Returns
    ///
    /// Returns a struct [`Account`] containing basic information about the specified Near account.
    pub async fn view_account(&self, account_id: &AccountId) -> Result<Account> {
        self.rpc_client
            .request(
                "query",
                Some(json!({
                    "request_type": "view_account",
                    "finality": Finality::Final,
                    "account_id": account_id,
                })),
            )
            .await
            .map_err(Error::ViewCall)
            .and_then(|it| {
                serde_json::from_value::<Account>(it).map_err(Error::DeserializeViewCall)
            })
    }

    /// Creates new access key on the specified account
    ///
    /// Arguments
    /// - signer - Transaction [`Signer`]
    /// - account_id - The user [`AccountId`] in a Near network
    /// - new_account_pk - The new [`Ed25519PublicKey`]
    /// - permission - Granted permissions level for the new access key
    pub fn add_access_key<'a>(
        &'a self,
        signer: &'a Signer,
        account_id: &'a AccountId,
        new_account_pk: Ed25519PublicKey,
        permission: AccessKeyPermission,
    ) -> FunctionCall {
        let info = TransactionInfo::new(self, signer, account_id);
        let actions = vec![AddKeyAction {
            public_key: new_account_pk,
            access_key: AccessKey {
                nonce: rand::random::<u64>(),
                permission,
            },
        }
        .into()];
        FunctionCall::new(info, actions)
    }

    /// Deletes an access key on the specified account
    ///
    /// Arguments
    /// - signer - Transaction [`Signer`]
    /// - account_id - The user [`AccountId`] in a Near network
    /// - public_key - The [`Ed25519PublicKey`] to be deleted from users access keys
    pub fn delete_access_key<'a>(
        &'a self,
        signer: &'a Signer,
        account_id: &'a AccountId,
        public_key: Ed25519PublicKey,
    ) -> FunctionCall {
        let info = TransactionInfo::new(self, signer, account_id);
        let actions = vec![DeleteKeyAction { public_key }.into()];
        FunctionCall::new(info, actions)
    }

    /// Execute a transaction with a function call to the smart contract
    ///
    /// Arguments
    ///
    /// - signer - Transaction [`Signer`]
    /// - contract_id - The [`AccountId`] where smart contract is located
    /// - method - Function that is declared in a smart contract (Arguments fir function call provided later in a [`FunctionCallBuilder`])
    pub fn function_call<'a>(
        &'a self,
        signer: &'a Signer,
        contract_id: &'a AccountId,
        method: &'static str,
    ) -> FunctionCallBuilder {
        let transaction_info = TransactionInfo::new(self, signer, contract_id);
        FunctionCallBuilder::new(transaction_info, method)
    }

    /// Deploys contract code to the chain
    ///
    /// ## Arguments
    ///
    /// - signer - Transaction [`Signer`]
    /// - contract_id - The [`AccountId`] where smart contract is located
    /// - wasm - Actually a compiled code
    pub fn deploy_contract<'a>(
        &'a self,
        signer: &'a Signer,
        contract_id: &'a AccountId,
        wasm: Vec<u8>,
    ) -> FunctionCall {
        FunctionCall::new(
            TransactionInfo::new(self, signer, contract_id),
            vec![Action::from(DeployContractAction { code: wasm })],
        )
    }

    /// Creates account
    ///
    /// ## Arguments
    ///
    /// - signer - Transaction [`Signer`]
    /// - new_account_id - The new [`AccountId`]
    /// - new_account_pk - The new [`Ed25519PublicKey`]
    /// - amount - Initial balance of that account, could be zero
    pub fn create_account<'a>(
        &'a self,
        signer: &'a Signer,
        new_account_id: &'a AccountId,
        new_account_pk: Ed25519PublicKey,
        amount: Balance,
    ) -> FunctionCall {
        let info = TransactionInfo::new(self, signer, new_account_id);
        let actions = vec![
            CreateAccountAction {}.into(),
            AddKeyAction {
                public_key: new_account_pk,
                access_key: AccessKey {
                    nonce: 0,
                    permission: AccessKeyPermission::FullAccess,
                },
            }
            .into(),
            TransferAction { deposit: amount }.into(),
        ];

        FunctionCall::new(info, actions)
    }

    /// Deletes account
    ///
    /// ## Arguments
    ///
    /// - signer - Transaction [`Signer`]
    /// - account_id - The [`AccountId`] that we own and want to delete
    /// - beneficiary_acc_id - Where to return a founds from the deleted account
    pub fn delete_account<'a>(
        &'a self,
        signer: &'a Signer,
        account_id: &'a AccountId,
        beneficiary_acc_id: &'a AccountId,
    ) -> FunctionCall {
        let info = TransactionInfo::new(self, signer, account_id);
        let actions = vec![DeleteAccountAction {
            beneficiary_id: beneficiary_acc_id.clone(),
        }
        .into()];

        FunctionCall::new(info, actions)
    }

    /// Sends Near tokens from one account to another.
    ///
    /// ## Arguments
    ///
    /// - `signer` - The account ID of the sender and transaction [`Signer`]
    /// - `receiver_id` - The account ID of the receiver.
    /// - `deposit` - The amount of Near tokens to send.
    ///
    /// ## Errors
    ///
    /// Possible error conditions include insufficient funds, invalid account IDs, or
    /// other issues preventing the successful execution of the transaction.
    pub fn send<'a>(
        &'a self,
        signer: &'a Signer,
        receiver_id: &'a AccountId,
        deposit: Balance,
    ) -> FunctionCall {
        let info = TransactionInfo::new(self, signer, receiver_id);
        let actions = vec![TransferAction { deposit }.into()];

        FunctionCall::new(info, actions)
    }
}

/// Output of a view contract call
/// Contains the return data and logs
#[derive(Debug)]
pub struct ViewOutput<T: DeserializeOwned> {
    logs: Vec<String>,
    data: T,
}

impl<T: DeserializeOwned> ViewOutput<T> {
    /// Logs from view call
    pub fn logs(&self) -> Vec<String> {
        self.logs.clone()
    }

    /// Return a view call result
    pub fn data(self) -> T {
        self.data
    }
}

impl<T: DeserializeOwned> Deref for ViewOutput<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: DeserializeOwned> DerefMut for ViewOutput<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// Function call output.
#[derive(Debug)]
pub struct Output {
    transaction: ExecutionOutcomeWithIdView,
    logs: Vec<String>,
    data: Vec<u8>,
}

impl Output {
    #[allow(clippy::result_large_err)]
    /// If function don't return anything it will return [`Error::DeserializeTransactionOutput`]
    /// Or if you miss matching a return type
    pub fn output<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice::<T>(&self.data).map_err(Error::DeserializeTransactionOutput)
    }

    #[allow(clippy::misnamed_getters)]
    /// Returns a transaction id
    pub const fn id(&self) -> CryptoHash {
        self.transaction.id
    }

    /// Amount of gas that was burnt during transaction execution
    pub const fn gas_burnt(&self) -> Gas {
        self.transaction.outcome.gas_burnt
    }

    /// Logs that smart contract produced
    pub fn logs(&self) -> Vec<String> {
        self.logs.clone()
    }
}

#[doc(hidden)]
pub struct FunctionCallBuilder<'a> {
    info: TransactionInfo<'a>,
    deposit: Balance,
    gas: Gas,
    args: Option<Value>,
    retry: Retry,
    method_name: &'a str,
}

impl<'a> FunctionCallBuilder<'a> {
    fn new(info: TransactionInfo<'a>, method_name: &'a str) -> Self {
        Self {
            info,
            method_name,
            gas: Default::default(),
            args: Default::default(),
            deposit: Default::default(),
            retry: Default::default(),
        }
    }

    pub const fn deposit(mut self, deposit: Balance) -> Self {
        self.deposit = deposit;
        self
    }

    /// Amount of gas that will be hold for function execution
    pub const fn gas(mut self, gas: Gas) -> Self {
        self.gas = gas;
        self
    }

    pub fn args(mut self, args: Value) -> Self {
        self.args = Some(args);
        self
    }

    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<FunctionCall<'a>> {
        let action = Action::from(FunctionCallAction {
            method_name: self.method_name.to_string(),
            args: serialize_arguments(self.args)?,
            gas: self.gas,
            deposit: self.deposit,
        });

        Ok(FunctionCall {
            info: self.info,
            actions: vec![action],
            retry: self.retry,
        })
    }

    /// Set [`Retry`] strategy
    pub const fn retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }

    /// Sends a transaction and waits until transaction is fully complete. (Has a 10 second timeout)
    /// Also, possible that an output data will be empty if the transaction is still executing
    ///
    /// ## Arguments
    ///
    /// - **finality** - Block [`Finality`]
    pub async fn commit(self, finality: Finality) -> Result<Output> {
        let call = self.build()?;
        call.commit(finality).await
    }

    /// Sends a transaction and immediately returns transaction hash.
    ///
    /// ## Arguments
    ///
    /// - **finality** - Block [`Finality`]
    pub async fn commit_async(self, finality: Finality) -> Result<CryptoHash> {
        let call = self.build()?;
        call.commit_async(finality).await
    }
}

/// Tells the **client** to execute transaction one more time if it's failed.
/// > It's only happens during **InvalidNonce** error.
///
/// - NONE - default value, transaction executes once
/// - ONCE - retry once
/// - TWICE - retry two times
///
#[repr(usize)]
#[derive(Debug, Default, Clone, Copy)]
pub enum Retry {
    /// Executes once, basically no retry
    #[default]
    NONE = 1,
    /// If **InvalidNonce** error received try to execute one more time
    ONCE = 2,
    /// If **InvalidNonce** error received try to execute two times
    TWICE = 3,
}

#[doc(hidden)]
pub struct FunctionCall<'a> {
    info: TransactionInfo<'a>,
    actions: Vec<Action>,
    retry: Retry,
}

impl<'a> FunctionCall<'a> {
    /// Sends a transaction and waits until transaction is fully complete. (Has a 10 second timeout)
    /// Also, possible that an output data will be empty if the transaction is still executing
    ///
    /// ## Arguments
    ///
    /// - **finality** - Block [`Finality`]
    pub async fn commit(self, finality: Finality) -> Result<Output> {
        let execution_outcome =
            commit_with_retry(&self, finality, "broadcast_tx_commit", self.retry)
                .await
                .and_then(|execution_outcome| {
                    serde_json::from_value::<FinalExecutionOutcomeView>(execution_outcome)
                        .map_err(Error::DeserializeExecutionOutcome)
                })?;

        proceed_outcome(self.info.signer(), execution_outcome)
    }

    /// Sends a transaction and immediately returns transaction hash.
    ///
    /// ## Arguments
    ///
    /// - **finality** - Block [`Finality`]
    pub async fn commit_async(self, finality: Finality) -> Result<CryptoHash> {
        commit_with_retry(&self, finality, "broadcast_tx_async", self.retry)
            .await
            .and_then(|id| {
                serde_json::from_value::<CryptoHash>(id).map_err(Error::DeserializeTransactionId)
            })
    }

    /// Set [`Retry`] strategy
    pub const fn retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }

    const fn info(&self) -> &TransactionInfo {
        &self.info
    }

    fn actions(&self) -> &[Action] {
        &self.actions
    }

    const fn new(info: TransactionInfo<'a>, actions: Vec<Action>) -> Self {
        Self {
            info,
            actions,
            retry: Retry::NONE,
        }
    }
}

async fn commit_with_retry<'a>(
    call: &FunctionCall<'a>,
    finality: Finality,
    transaction_type: &'static str,
    retry: Retry,
) -> Result<Value> {
    let mut execution_count = 0;
    let retry_count = retry as usize;

    loop {
        execution_count += 1;

        let transaction = BASE64_STANDARD_NO_PAD.encode(
            serialize_transaction(call.info(), call.actions().to_vec(), finality.clone()).await?,
        );

        let resp = call
            .info()
            .rpc()
            .request(transaction_type, Some(json!(vec![transaction])))
            .await
            .map_err(transaction_error);

        if let Err(Error::TxExecution(
            TxExecutionError::InvalidTxError(InvalidTxError::InvalidNonce { ak_nonce, .. }),
            ..,
        )) = resp
        {
            if retry_count > 1 && execution_count <= retry_count {
                call.info().signer().update_nonce(ak_nonce + 1);
                continue;
            }
        }

        return resp;
    }
}

// Try to parse the error that may be located in the node response
fn transaction_error(err: RpcError) -> Error {
    let RpcError::NearProtocol(near_err) = &err else {
        return Error::RpcError(err);
    };

    let (NearErrorVariant::RequestValidation(CauseKind::ParseError(cause))
    | NearErrorVariant::Handler(CauseKind::InvalidTransaction(cause))) = near_err.error()
    else {
        return Error::RpcError(err);
    };

    serde_json::from_value::<TxExecutionErrorContainer>(cause.to_owned())
        .or_else(|err| {
            near_err.data().ok_or(err).and_then(|cause| {
                serde_json::from_value::<TxExecutionErrorContainer>(cause.to_owned())
            })
        })
        .map(|exec_err| Error::TxExecution(exec_err.tx_execution_error, Default::default()))
        .unwrap_or(Error::RpcError(err))
}

#[allow(clippy::result_large_err)]
pub(crate) fn proceed_outcome(
    signer: &Signer,
    execution_outcome: FinalExecutionOutcomeView,
) -> Result<Output> {
    signer.update_nonce(execution_outcome.transaction.nonce);
    let transaction = execution_outcome.transaction_outcome;
    let logs = extract_logs(execution_outcome.receipts_outcome);

    match execution_outcome.status {
        FinalExecutionStatus::Failure(err) => Err(Error::TxExecution(err, Box::new(logs))),
        FinalExecutionStatus::SuccessValue(data) => Ok(Output {
            transaction,
            logs,
            data,
        }),
        FinalExecutionStatus::NotStarted => Err(Error::TxNotStarted(Box::new(logs))),
        FinalExecutionStatus::Started => Ok(Output {
            transaction,
            logs,
            data: vec![],
        }),
    }
}
