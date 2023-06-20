use super::{errors::TxExecutionError, receipt::*, transaction::*, types::*};
use crate::crypto::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use chrono::DateTime;
use serde_with::{base64::Base64, serde_as};
use std::fmt;
use strum::IntoEnumIterator;

use near_primitives_core::{
    account::Account,
    account::{AccessKey, AccessKeyPermission, FunctionCallPermission},
    config::{ActionCosts, ExtCosts},
    contract::ContractCode,
    hash::hash,
    hash::CryptoHash,
    serialize::dec_format,
    types::{
        AccountId, Balance, BlockHeight, Gas, Nonce, NumBlocks, ProtocolVersion, ShardId,
        StorageUsage,
    },
};

pub type EpochId = CryptoHash;
pub type ChunkHash = CryptoHash;

/// A view of the account
#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct AccountView {
    #[serde(with = "dec_format")]
    pub amount: Balance,
    #[serde(with = "dec_format")]
    pub locked: Balance,
    pub code_hash: CryptoHash,
    pub storage_usage: StorageUsage,
    /// TODO(2271): deprecated.
    #[serde(default)]
    pub storage_paid_at: BlockHeight,
}

/// A view of the contract code.
#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ContractCodeView {
    #[serde(rename = "code_base64")]
    #[serde_as(as = "Base64")]
    pub code: Vec<u8>,
    pub hash: CryptoHash,
}

impl From<&Account> for AccountView {
    fn from(account: &Account) -> Self {
        AccountView {
            amount: account.amount(),
            locked: account.locked(),
            code_hash: account.code_hash(),
            storage_usage: account.storage_usage(),
            storage_paid_at: 0,
        }
    }
}

impl From<Account> for AccountView {
    fn from(account: Account) -> Self {
        (&account).into()
    }
}

impl From<&AccountView> for Account {
    fn from(view: &AccountView) -> Self {
        Account::new(view.amount, view.locked, view.code_hash, view.storage_usage)
    }
}

impl From<AccountView> for Account {
    fn from(view: AccountView) -> Self {
        (&view).into()
    }
}

impl From<ContractCode> for ContractCodeView {
    fn from(contract_code: ContractCode) -> Self {
        let hash = *contract_code.hash();
        let code = contract_code.into_code();
        ContractCodeView { code, hash }
    }
}

impl From<ContractCodeView> for ContractCode {
    fn from(contract_code: ContractCodeView) -> Self {
        ContractCode::new(contract_code.code, Some(contract_code.hash))
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Eq,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum AccessKeyPermissionView {
    FunctionCall {
        #[serde(with = "dec_format")]
        allowance: Option<Balance>,
        receiver_id: String,
        method_names: Vec<String>,
    },
    FullAccess,
}

impl From<AccessKeyPermission> for AccessKeyPermissionView {
    fn from(permission: AccessKeyPermission) -> Self {
        match permission {
            AccessKeyPermission::FunctionCall(func_call) => AccessKeyPermissionView::FunctionCall {
                allowance: func_call.allowance,
                receiver_id: func_call.receiver_id,
                method_names: func_call.method_names,
            },
            AccessKeyPermission::FullAccess => AccessKeyPermissionView::FullAccess,
        }
    }
}

impl From<AccessKeyPermissionView> for AccessKeyPermission {
    fn from(view: AccessKeyPermissionView) -> Self {
        match view {
            AccessKeyPermissionView::FunctionCall {
                allowance,
                receiver_id,
                method_names,
            } => AccessKeyPermission::FunctionCall(FunctionCallPermission {
                allowance,
                receiver_id,
                method_names,
            }),
            AccessKeyPermissionView::FullAccess => AccessKeyPermission::FullAccess,
        }
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Eq,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AccessKeyView {
    pub nonce: Nonce,
    pub permission: AccessKeyPermissionView,
}

impl From<AccessKey> for AccessKeyView {
    fn from(access_key: AccessKey) -> Self {
        Self {
            nonce: access_key.nonce,
            permission: access_key.permission.into(),
        }
    }
}

impl From<AccessKeyView> for AccessKey {
    fn from(view: AccessKeyView) -> Self {
        Self {
            nonce: view.nonce,
            permission: view.permission.into(),
        }
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Eq,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AccessKeyListView {
    pub keys: Vec<KeysView>,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Eq,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct KeysView {
    pub public_key: Ed25519PublicKey,
    pub access_key: AccessKey,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct CallResult {
    pub result: Vec<u8>,
    pub logs: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct QueryError {
    pub error: String,
    pub logs: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AccessKeyInfoView {
    pub public_key: Ed25519PublicKey,
    pub access_key: AccessKeyView,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct AccessKeyList {
    pub keys: Vec<AccessKeyInfoView>,
}

impl FromIterator<AccessKeyInfoView> for AccessKeyList {
    fn from_iter<I: IntoIterator<Item = AccessKeyInfoView>>(iter: I) -> Self {
        Self {
            keys: iter.into_iter().collect(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
pub struct BlockStatusView {
    pub height: BlockHeight,
    pub hash: CryptoHash,
}

impl BlockStatusView {
    pub fn new(height: &BlockHeight, hash: &CryptoHash) -> BlockStatusView {
        Self {
            height: *height,
            hash: *hash,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BlockByChunksView {
    pub height: BlockHeight,
    pub hash: CryptoHash,
    pub block_status: String,
    pub chunk_status: String,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum BlockProcessingStatus {
    Orphan,
    WaitingForChunks,
    InProcessing,
    Accepted,
    Error(String),
    Dropped(DroppedReason),
    Unknown,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum DroppedReason {
    // If the node has already processed a block at this height
    HeightProcessed,
    // If the block processing pool is full
    TooManyProcessingBlocks,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ChunkProcessingInfo {
    pub height_created: BlockHeight,
    pub shard_id: ShardId,
    pub chunk_hash: ChunkHash,
    pub prev_block_hash: CryptoHash,
    /// Account id of the validator who created this chunk
    /// Theoretically this field should never be None unless there is some database corruption.
    pub created_by: Option<AccountId>,
    pub status: ChunkProcessingStatus,
    /// Timestamp of first time when we request for this chunk.
    pub requested_timestamp: Option<DateTime<chrono::Utc>>,
    /// Timestamp of when the chunk is complete
    pub completed_timestamp: Option<DateTime<chrono::Utc>>,
    /// Time (in millis) that it takes between when the chunk is requested and when it is completed.
    pub request_duration: Option<u64>,
    pub chunk_parts_collection: Vec<PartCollectionInfo>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct PartCollectionInfo {
    pub part_owner: AccountId,
    // Time when the part is received through any message
    pub received_time: Option<DateTime<chrono::Utc>>,
    // Time when we receive a PartialEncodedChunkForward containing this part
    pub forwarded_received_time: Option<DateTime<chrono::Utc>>,
    // Time when we receive the PartialEncodedChunk message containing this part
    pub chunk_received_time: Option<DateTime<chrono::Utc>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum ChunkProcessingStatus {
    NeedToRequest,
    Requested,
    Completed,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BlockHeaderView {
    pub height: BlockHeight,
    pub prev_height: Option<BlockHeight>,
    pub epoch_id: CryptoHash,
    pub next_epoch_id: CryptoHash,
    pub hash: CryptoHash,
    pub prev_hash: CryptoHash,
    pub prev_state_root: CryptoHash,
    pub chunk_receipts_root: CryptoHash,
    pub chunk_headers_root: CryptoHash,
    pub chunk_tx_root: CryptoHash,
    pub outcome_root: CryptoHash,
    pub chunks_included: u64,
    pub challenges_root: CryptoHash,
    /// Legacy json number. Should not be used.
    pub timestamp: u64,
    #[serde(with = "dec_format")]
    pub timestamp_nanosec: u64,
    pub random_value: CryptoHash,
    pub chunk_mask: Vec<bool>,
    #[serde(with = "dec_format")]
    pub gas_price: Balance,
    pub block_ordinal: Option<NumBlocks>,
    /// TODO(2271): deprecated.
    #[serde(with = "dec_format")]
    pub rent_paid: Balance,
    /// TODO(2271): deprecated.
    #[serde(with = "dec_format")]
    pub validator_reward: Balance,
    #[serde(with = "dec_format")]
    pub total_supply: Balance,
    pub last_final_block: CryptoHash,
    pub last_ds_final_block: CryptoHash,
    pub next_bp_hash: CryptoHash,
    pub block_merkle_root: CryptoHash,
    pub epoch_sync_data_hash: Option<CryptoHash>,
    pub approvals: Vec<Option<Ed25519Signature>>,
    pub signature: Ed25519Signature,
    pub latest_protocol_version: ProtocolVersion,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ChunkHeaderView {
    pub chunk_hash: CryptoHash,
    pub prev_block_hash: CryptoHash,
    pub outcome_root: CryptoHash,
    pub prev_state_root: StateRoot,
    pub encoded_merkle_root: CryptoHash,
    pub encoded_length: u64,
    pub height_created: BlockHeight,
    pub height_included: BlockHeight,
    pub shard_id: ShardId,
    pub gas_used: Gas,
    pub gas_limit: Gas,
    /// TODO(2271): deprecated.
    #[serde(with = "dec_format")]
    pub rent_paid: Balance,
    /// TODO(2271): deprecated.
    #[serde(with = "dec_format")]
    pub validator_reward: Balance,
    #[serde(with = "dec_format")]
    pub balance_burnt: Balance,
    pub outgoing_receipts_root: CryptoHash,
    pub tx_root: CryptoHash,
    pub signature: Ed25519Signature,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BlockView {
    pub author: AccountId,
    pub header: BlockHeaderView,
    pub chunks: Vec<ChunkHeaderView>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ChunkView {
    pub author: AccountId,
    pub header: ChunkHeaderView,
    pub transactions: Vec<SignedTransactionView>,
    pub receipts: Vec<ReceiptView>,
}

#[serde_as]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum ActionView {
    CreateAccount,
    DeployContract {
        #[serde_as(as = "Base64")]
        code: Vec<u8>,
    },
    FunctionCall {
        method_name: String,
        #[serde_as(as = "Base64")]
        args: Vec<u8>,
        gas: Gas,
        #[serde(with = "dec_format")]
        deposit: Balance,
    },
    Transfer {
        #[serde(with = "dec_format")]
        deposit: Balance,
    },
    Stake {
        #[serde(with = "dec_format")]
        stake: Balance,
        public_key: Ed25519PublicKey,
    },
    AddKey {
        public_key: Ed25519PublicKey,
        access_key: AccessKeyView,
    },
    DeleteKey {
        public_key: Ed25519PublicKey,
    },
    DeleteAccount {
        beneficiary_id: AccountId,
    },
    Delegate {
        delegate_action: DelegateAction,
        signature: Ed25519Signature,
    },
}

impl From<Action> for ActionView {
    fn from(action: Action) -> Self {
        match action {
            Action::CreateAccount(_) => ActionView::CreateAccount,
            Action::DeployContract(action) => {
                let code = hash(&action.code).as_ref().to_vec();
                ActionView::DeployContract { code }
            }
            Action::FunctionCall(action) => ActionView::FunctionCall {
                method_name: action.method_name,
                args: action.args,
                gas: action.gas,
                deposit: action.deposit,
            },
            Action::Transfer(action) => ActionView::Transfer {
                deposit: action.deposit,
            },
            Action::Stake(action) => ActionView::Stake {
                stake: action.stake,
                public_key: action.public_key,
            },
            Action::AddKey(action) => ActionView::AddKey {
                public_key: action.public_key,
                access_key: action.access_key.into(),
            },
            Action::DeleteKey(action) => ActionView::DeleteKey {
                public_key: action.public_key,
            },
            Action::DeleteAccount(action) => ActionView::DeleteAccount {
                beneficiary_id: action.beneficiary_id,
            },
            Action::Delegate(action) => ActionView::Delegate {
                delegate_action: action.delegate_action,
                signature: action.signature,
            },
        }
    }
}

impl TryFrom<ActionView> for Action {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(action_view: ActionView) -> Result<Self, Self::Error> {
        Ok(match action_view {
            ActionView::CreateAccount => Action::CreateAccount(CreateAccountAction {}),
            ActionView::DeployContract { code } => {
                Action::DeployContract(DeployContractAction { code })
            }
            ActionView::FunctionCall {
                method_name,
                args,
                gas,
                deposit,
            } => Action::FunctionCall(FunctionCallAction {
                method_name,
                args,
                gas,
                deposit,
            }),
            ActionView::Transfer { deposit } => Action::Transfer(TransferAction { deposit }),
            ActionView::Stake { stake, public_key } => {
                Action::Stake(StakeAction { stake, public_key })
            }
            ActionView::AddKey {
                public_key,
                access_key,
            } => Action::AddKey(AddKeyAction {
                public_key,
                access_key: access_key.into(),
            }),
            ActionView::DeleteKey { public_key } => {
                Action::DeleteKey(DeleteKeyAction { public_key })
            }
            ActionView::DeleteAccount { beneficiary_id } => {
                Action::DeleteAccount(DeleteAccountAction { beneficiary_id })
            }
            ActionView::Delegate {
                delegate_action,
                signature,
            } => Action::Delegate(SignedDelegateAction {
                delegate_action,
                signature,
            }),
        })
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    PartialEq,
    Eq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct SignedTransactionView {
    pub signer_id: AccountId,
    pub public_key: Ed25519PublicKey,
    pub nonce: Nonce,
    pub receiver_id: AccountId,
    pub actions: Vec<ActionView>,
    pub signature: Ed25519Signature,
    pub hash: CryptoHash,
}

impl From<SignedTransaction> for SignedTransactionView {
    fn from(signed_tx: SignedTransaction) -> Self {
        let hash = signed_tx.get_hash();
        SignedTransactionView {
            signer_id: signed_tx.transaction.signer_id,
            public_key: signed_tx.transaction.public_key,
            nonce: signed_tx.transaction.nonce,
            receiver_id: signed_tx.transaction.receiver_id,
            actions: signed_tx
                .transaction
                .actions
                .into_iter()
                .map(|action| action.into())
                .collect(),
            signature: signed_tx.signature,
            hash,
        }
    }
}

#[serde_as]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    PartialEq,
    Eq,
    Clone,
    Default,
)]
#[allow(clippy::large_enum_variant)]
pub enum FinalExecutionStatus {
    /// The execution has not yet started.
    #[default]
    NotStarted,
    /// The execution has started and still going.
    Started,
    /// The execution has failed with the given error.
    Failure(TxExecutionError),
    /// The execution has succeeded and returned some value or an empty vec encoded in base64.
    SuccessValue(#[serde_as(as = "Base64")] Vec<u8>),
}

impl fmt::Debug for FinalExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FinalExecutionStatus::NotStarted => f.write_str("NotStarted"),
            FinalExecutionStatus::Started => f.write_str("Started"),
            FinalExecutionStatus::Failure(e) => f.write_fmt(format_args!("Failure({:?})", e)),
            FinalExecutionStatus::SuccessValue(v) => {
                f.write_fmt(format_args!("SuccessValue({v:?})"))
            }
        }
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    PartialEq,
    Eq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
#[allow(clippy::large_enum_variant)]
pub enum ServerError {
    TxExecutionError(TxExecutionError),
    Timeout,
    Closed,
}

#[serde_as]
#[derive(
    BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone,
)]
#[allow(clippy::large_enum_variant)]
pub enum ExecutionStatusView {
    /// The execution is pending or unknown.
    Unknown,
    /// The execution has failed.
    Failure(TxExecutionError),
    /// The final action succeeded and returned some value or an empty vec encoded in base64.
    SuccessValue(#[serde_as(as = "Base64")] Vec<u8>),
    /// The final action of the receipt returned a promise or the signed transaction was converted
    /// to a receipt. Contains the receipt_id of the generated receipt.
    SuccessReceiptId(CryptoHash),
}

impl fmt::Debug for ExecutionStatusView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionStatusView::Unknown => f.write_str("Unknown"),
            ExecutionStatusView::Failure(e) => f.write_fmt(format_args!("Failure({:?})", e)),
            ExecutionStatusView::SuccessValue(v) => {
                f.write_fmt(format_args!("SuccessValue({v:?})"))
            }
            ExecutionStatusView::SuccessReceiptId(receipt_id) => {
                f.write_fmt(format_args!("SuccessReceiptId({})", receipt_id))
            }
        }
    }
}

impl From<ExecutionStatus> for ExecutionStatusView {
    fn from(outcome: ExecutionStatus) -> Self {
        match outcome {
            ExecutionStatus::Unknown => ExecutionStatusView::Unknown,
            ExecutionStatus::Failure(e) => ExecutionStatusView::Failure(*e),
            ExecutionStatus::SuccessValue(v) => ExecutionStatusView::SuccessValue(v),
            ExecutionStatus::SuccessReceiptId(receipt_id) => {
                ExecutionStatusView::SuccessReceiptId(receipt_id)
            }
        }
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Clone,
    Eq,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CostGasUsed {
    pub cost_category: String,
    pub cost: String,
    #[serde(with = "dec_format")]
    pub gas_used: Gas,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Clone,
    Eq,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ExecutionMetadataView {
    pub version: u32,
    pub gas_profile: Option<Vec<CostGasUsed>>,
}

impl Default for ExecutionMetadataView {
    fn default() -> Self {
        ExecutionMetadata::V1.into()
    }
}

impl From<ExecutionMetadata> for ExecutionMetadataView {
    fn from(metadata: ExecutionMetadata) -> Self {
        let version = match metadata {
            ExecutionMetadata::V1 => 1,
            ExecutionMetadata::V2(_) => 2,
            ExecutionMetadata::V3(_) => 3,
        };
        let mut gas_profile = match metadata {
            ExecutionMetadata::V1 => None,
            ExecutionMetadata::V2(profile_data) => {
                // Add actions, wasm op, and ext costs in groups.

                // actions should use the old format, since `ActionCosts`
                // includes more detailed entries than were present in the old
                // profile
                let mut costs: Vec<CostGasUsed> = profile_data
                    .legacy_action_costs()
                    .into_iter()
                    .filter(|&(_, gas)| gas > 0)
                    .map(|(name, gas)| CostGasUsed::action(name.to_string(), gas))
                    .collect();

                // wasm op is a single cost, for historical reasons it is inaccurately displayed as "wasm host"
                costs.push(CostGasUsed::wasm_host(
                    "WASM_INSTRUCTION".to_string(),
                    profile_data.get_wasm_cost(),
                ));

                // ext costs are 1-to-1, except for those added later which we will display as 0
                for ext_cost in ExtCosts::iter() {
                    costs.push(CostGasUsed::wasm_host(
                        format!("{:?}", ext_cost).to_ascii_uppercase(),
                        profile_data.get_ext_cost(ext_cost),
                    ));
                }

                Some(costs)
            }
            ExecutionMetadata::V3(profile) => {
                // Add actions, wasm op, and ext costs in groups.
                // actions costs are 1-to-1
                let mut costs: Vec<CostGasUsed> = ActionCosts::iter()
                    .flat_map(|cost| {
                        let gas_used = profile.get_action_cost(cost);
                        (gas_used > 0).then(|| {
                            CostGasUsed::action(
                                format!("{:?}", cost).to_ascii_uppercase(),
                                gas_used,
                            )
                        })
                    })
                    .collect();

                // wasm op is a single cost, for historical reasons it is inaccurately displayed as "wasm host"
                let wasm_gas_used = profile.get_wasm_cost();
                if wasm_gas_used > 0 {
                    costs.push(CostGasUsed::wasm_host(
                        "WASM_INSTRUCTION".to_string(),
                        wasm_gas_used,
                    ));
                }

                // ext costs are 1-to-1
                for ext_cost in ExtCosts::iter() {
                    let gas_used = profile.get_ext_cost(ext_cost);
                    if gas_used > 0 {
                        costs.push(CostGasUsed::wasm_host(
                            format!("{:?}", ext_cost).to_ascii_uppercase(),
                            gas_used,
                        ));
                    }
                }

                Some(costs)
            }
        };
        if let Some(ref mut costs) = gas_profile {
            // The order doesn't really matter, but the default one is just
            // historical, which is especially unintuitive, so let's sort
            // lexicographically.
            //
            // Can't `sort_by_key` here because lifetime inference in
            // closures is limited.
            costs.sort_by(|lhs, rhs| {
                lhs.cost_category
                    .cmp(&rhs.cost_category)
                    .then_with(|| lhs.cost.cmp(&rhs.cost))
            });
        }
        ExecutionMetadataView {
            version,
            gas_profile,
        }
    }
}

impl CostGasUsed {
    pub fn action(cost: String, gas_used: Gas) -> Self {
        Self {
            cost_category: "ACTION_COST".to_string(),
            cost,
            gas_used,
        }
    }

    pub fn wasm_host(cost: String, gas_used: Gas) -> Self {
        Self {
            cost_category: "WASM_HOST_COST".to_string(),
            cost,
            gas_used,
        }
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ExecutionOutcomeView {
    /// Logs from this transaction or receipt.
    pub logs: Vec<String>,
    /// Receipt IDs generated by this transaction or receipt.
    pub receipt_ids: Vec<CryptoHash>,
    /// The amount of the gas burnt by the given transaction or receipt.
    pub gas_burnt: Gas,
    /// The amount of tokens burnt corresponding to the burnt gas amount.
    /// This value doesn't always equal to the `gas_burnt` multiplied by the gas price, because
    /// the prepaid gas price might be lower than the actual gas price and it creates a deficit.
    #[serde(with = "dec_format")]
    pub tokens_burnt: Balance,
    /// The id of the account on which the execution happens. For transaction this is signer_id,
    /// for receipt this is receiver_id.
    pub executor_id: AccountId,
    /// Execution status. Contains the result in case of successful execution.
    pub status: ExecutionStatusView,
    /// Execution metadata, versioned
    #[serde(default)]
    pub metadata: ExecutionMetadataView,
}

impl From<ExecutionOutcome> for ExecutionOutcomeView {
    fn from(outcome: ExecutionOutcome) -> Self {
        Self {
            logs: outcome.logs,
            receipt_ids: outcome.receipt_ids,
            gas_burnt: outcome.gas_burnt,
            tokens_burnt: outcome.tokens_burnt,
            executor_id: outcome.executor_id,
            status: outcome.status.into(),
            metadata: outcome.metadata.into(),
        }
    }
}

impl From<&ExecutionOutcomeView> for PartialExecutionOutcome {
    fn from(outcome: &ExecutionOutcomeView) -> Self {
        Self {
            receipt_ids: outcome.receipt_ids.clone(),
            gas_burnt: outcome.gas_burnt,
            tokens_burnt: outcome.tokens_burnt,
            executor_id: outcome.executor_id.clone(),
            status: outcome.status.clone().into(),
        }
    }
}
impl From<ExecutionStatusView> for PartialExecutionStatus {
    fn from(status: ExecutionStatusView) -> PartialExecutionStatus {
        match status {
            ExecutionStatusView::Unknown => PartialExecutionStatus::Unknown,
            ExecutionStatusView::Failure(_) => PartialExecutionStatus::Failure,
            ExecutionStatusView::SuccessValue(value) => PartialExecutionStatus::SuccessValue(value),
            ExecutionStatusView::SuccessReceiptId(id) => {
                PartialExecutionStatus::SuccessReceiptId(id)
            }
        }
    }
}

impl ExecutionOutcomeView {
    // Same behavior as ExecutionOutcomeWithId's to_hashes.
    pub fn to_hashes(&self, id: CryptoHash) -> Vec<CryptoHash> {
        let mut result = Vec::with_capacity(self.logs.len().saturating_add(2));
        result.push(id);
        result.push(CryptoHash::hash_borsh(&PartialExecutionOutcome::from(self)));
        result.extend(self.logs.iter().map(|log| hash(log.as_bytes())));
        result
    }
}

#[cfg_attr(feature = "deepsize_feature", derive(deepsize::DeepSizeOf))]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    PartialEq,
    Eq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ExecutionOutcomeWithIdView {
    pub block_hash: CryptoHash,
    pub id: CryptoHash,
    pub outcome: ExecutionOutcomeView,
}

impl ExecutionOutcomeWithIdView {
    pub fn to_hashes(&self) -> Vec<CryptoHash> {
        self.outcome.to_hashes(self.id)
    }
}

#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum FinalExecutionOutcomeViewEnum {
    FinalExecutionOutcome(FinalExecutionOutcomeView),
    FinalExecutionOutcomeWithReceipt(FinalExecutionOutcomeWithReceiptView),
}

impl FinalExecutionOutcomeViewEnum {
    pub fn into_outcome(self) -> FinalExecutionOutcomeView {
        match self {
            Self::FinalExecutionOutcome(outcome) => outcome,
            Self::FinalExecutionOutcomeWithReceipt(outcome) => outcome.final_outcome,
        }
    }
}

/// Final execution outcome of the transaction and all of subsequent the receipts.
#[derive(
    BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone,
)]
pub struct FinalExecutionOutcomeView {
    /// Execution status. Contains the result in case of successful execution.
    pub status: FinalExecutionStatus,
    /// Signed Transaction
    pub transaction: SignedTransactionView,
    /// The execution outcome of the signed transaction.
    pub transaction_outcome: ExecutionOutcomeWithIdView,
    /// The execution outcome of receipts.
    pub receipts_outcome: Vec<ExecutionOutcomeWithIdView>,
}

impl fmt::Debug for FinalExecutionOutcomeView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalExecutionOutcome")
            .field("status", &self.status)
            .field("transaction", &self.transaction)
            .field("transaction_outcome", &self.transaction_outcome)
            .field("receipts_outcome", &self.receipts_outcome)
            .finish()
    }
}

/// Final execution outcome of the transaction and all of subsequent the receipts. Also includes
/// the generated receipt.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct FinalExecutionOutcomeWithReceiptView {
    /// Final outcome view without receipts
    #[serde(flatten)]
    pub final_outcome: FinalExecutionOutcomeView,
    /// Receipts generated from the transaction
    pub receipts: Vec<ReceiptView>,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ReceiptView {
    pub predecessor_id: AccountId,
    pub receiver_id: AccountId,
    pub receipt_id: CryptoHash,

    pub receipt: ReceiptEnumView,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct DataReceiverView {
    pub data_id: CryptoHash,
    pub receiver_id: AccountId,
}

#[serde_as]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
#[allow(clippy::large_enum_variant)]
pub enum ReceiptEnumView {
    Action {
        signer_id: AccountId,
        signer_public_key: Ed25519PublicKey,
        #[serde(with = "dec_format")]
        gas_price: Balance,
        output_data_receivers: Vec<DataReceiverView>,
        input_data_ids: Vec<CryptoHash>,
        actions: Vec<ActionView>,
    },
    Data {
        data_id: CryptoHash,
        #[serde_as(as = "Option<Base64>")]
        data: Option<Vec<u8>>,
    },
}

impl From<Receipt> for ReceiptView {
    fn from(receipt: Receipt) -> Self {
        ReceiptView {
            predecessor_id: receipt.predecessor_id,
            receiver_id: receipt.receiver_id,
            receipt_id: receipt.receipt_id,
            receipt: match receipt.receipt {
                ReceiptEnum::Action(action_receipt) => ReceiptEnumView::Action {
                    signer_id: action_receipt.signer_id,
                    signer_public_key: action_receipt.signer_public_key,
                    gas_price: action_receipt.gas_price,
                    output_data_receivers: action_receipt
                        .output_data_receivers
                        .into_iter()
                        .map(|data_receiver| DataReceiverView {
                            data_id: data_receiver.data_id,
                            receiver_id: data_receiver.receiver_id,
                        })
                        .collect(),
                    input_data_ids: action_receipt
                        .input_data_ids
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    actions: action_receipt.actions.into_iter().map(Into::into).collect(),
                },
                ReceiptEnum::Data(data_receipt) => ReceiptEnumView::Data {
                    data_id: data_receipt.data_id,
                    data: data_receipt.data,
                },
            },
        }
    }
}

impl TryFrom<ReceiptView> for Receipt {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(receipt_view: ReceiptView) -> Result<Self, Self::Error> {
        Ok(Receipt {
            predecessor_id: receipt_view.predecessor_id,
            receiver_id: receipt_view.receiver_id,
            receipt_id: receipt_view.receipt_id,
            receipt: match receipt_view.receipt {
                ReceiptEnumView::Action {
                    signer_id,
                    signer_public_key,
                    gas_price,
                    output_data_receivers,
                    input_data_ids,
                    actions,
                } => ReceiptEnum::Action(ActionReceipt {
                    signer_id,
                    signer_public_key,
                    gas_price,
                    output_data_receivers: output_data_receivers
                        .into_iter()
                        .map(|data_receiver_view| DataReceiver {
                            data_id: data_receiver_view.data_id,
                            receiver_id: data_receiver_view.receiver_id,
                        })
                        .collect(),
                    input_data_ids: input_data_ids.into_iter().map(Into::into).collect(),
                    actions: actions
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()?,
                }),
                ReceiptEnumView::Data { data_id, data } => {
                    ReceiptEnum::Data(DataReceipt { data_id, data })
                }
            },
        })
    }
}
