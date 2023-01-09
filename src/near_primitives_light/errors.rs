use crate::crypto::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

use near_primitives_core::{
    hash::CryptoHash,
    serialize::dec_format,
    types::{AccountId, Balance, Gas, Nonce},
};

use borsh::{BorshDeserialize, BorshSerialize};

/// Error returned in the ExecutionOutcome in case of failure
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum TxExecutionError {
    /// An error happened during Action execution
    ActionError(ActionError),
    /// An error happened during Transaction execution
    InvalidTxError(InvalidTxError),
}

impl std::error::Error for TxExecutionError {}

impl Display for TxExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            TxExecutionError::ActionError(e) => write!(f, "{e}"),
            TxExecutionError::InvalidTxError(e) => write!(f, "{e}"),
        }
    }
}

impl From<ActionError> for TxExecutionError {
    fn from(error: ActionError) -> Self {
        TxExecutionError::ActionError(error)
    }
}

impl From<InvalidTxError> for TxExecutionError {
    fn from(error: InvalidTxError) -> Self {
        TxExecutionError::InvalidTxError(error)
    }
}

/// Error returned from `Runtime::apply`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// An unexpected integer overflow occurred. The likely issue is an invalid state or the transition.
    UnexpectedIntegerOverflow,
    /// An error happened during TX verification and account charging. It's likely the chunk is invalid.
    /// and should be challenged.
    InvalidTxError(InvalidTxError),
    /// Unexpected error which is typically related to the node storage corruption.
    /// It's possible the input state is invalid or malicious.
    StorageError(StorageError),
    /// An error happens if `check_balance` fails, which is likely an indication of an invalid state.
    BalanceMismatchError(BalanceMismatchError),
    /// The incoming receipt didn't pass the validation, it's likely a malicious behaviour.
    ReceiptValidationError(ReceiptValidationError),
    /// Error when accessing validator information. Happens inside epoch manager.
    ValidatorError(EpochError),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{self:?}"))
    }
}

impl std::error::Error for RuntimeError {}

/// Internal
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Key-value db internal failure
    StorageInternalError,
    /// Storage is PartialStorage and requested a missing trie node
    TrieNodeMissing,
    /// Either invalid state or key-value db is corrupted.
    /// For PartialStorage it cannot be corrupted.
    /// Error message is unreliable and for debugging purposes only. It's also probably ok to
    /// panic in every place that produces this error.
    /// We can check if db is corrupted by verifying everything in the state trie.
    StorageInconsistentState(String),
    /// Error from flat storage
    FlatStorageError(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{self:?}"))
    }
}

impl std::error::Error for StorageError {}

/// An error happened during TX execution
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum InvalidTxError {
    /// Happens if a wrong AccessKey used or AccessKey has not enough permissions
    InvalidAccessKeyError(InvalidAccessKeyError),
    /// TX signer_id is not a valid [`AccountId`]
    InvalidSignerId { signer_id: String },
    /// TX signer_id is not found in a storage
    SignerDoesNotExist { signer_id: AccountId },
    /// Transaction nonce must be `account[access_key].nonce + 1`.
    InvalidNonce { tx_nonce: Nonce, ak_nonce: Nonce },
    /// Transaction nonce is larger than the upper bound given by the block height
    NonceTooLarge { tx_nonce: Nonce, upper_bound: Nonce },
    /// TX receiver_id is not a valid AccountId
    InvalidReceiverId { receiver_id: String },
    /// TX signature is not valid
    InvalidSignature,
    /// Account does not have enough balance to cover TX cost
    NotEnoughBalance {
        signer_id: AccountId,
        #[serde(with = "dec_format")]
        balance: Balance,
        #[serde(with = "dec_format")]
        cost: Balance,
    },
    /// Signer account doesn't have enough balance after transaction.
    LackBalanceForState {
        /// An account which doesn't have enough balance to cover storage.
        signer_id: AccountId,
        /// Required balance to cover the state.
        #[serde(with = "dec_format")]
        amount: Balance,
    },
    /// An integer overflow occurred during transaction cost estimation.
    CostOverflow,
    /// Transaction parent block hash doesn't belong to the current chain
    InvalidChain,
    /// Transaction has expired
    Expired,
    /// An error occurred while validating actions of a Transaction.
    ActionsValidation(ActionsValidationError),
    /// The size of serialized transaction exceeded the limit.
    TransactionSizeExceeded { size: u64, limit: u64 },
}

impl std::error::Error for InvalidTxError {}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum InvalidAccessKeyError {
    /// The access key identified by the `public_key` doesn't exist for the account
    AccessKeyNotFound {
        account_id: AccountId,
        public_key: Ed25519PublicKey,
    },
    /// Transaction `receiver_id` doesn't match the access key receiver_id
    ReceiverMismatch {
        tx_receiver: AccountId,
        ak_receiver: String,
    },
    /// Transaction method name isn't allowed by the access key
    MethodNameMismatch { method_name: String },
    /// Transaction requires a full permission access key.
    RequiresFullAccess,
    /// Access Key does not have enough allowance to cover transaction cost
    NotEnoughAllowance {
        account_id: AccountId,
        public_key: Ed25519PublicKey,
        #[serde(with = "dec_format")]
        allowance: Balance,
        #[serde(with = "dec_format")]
        cost: Balance,
    },
    /// Having a deposit with a function call action is not allowed with a function call access key.
    DepositWithFunctionCall,
}

/// Describes the error for validating a list of actions.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActionsValidationError {
    /// The delete action must be a final aciton in transaction
    DeleteActionMustBeFinal,
    /// The total prepaid gas (for all given actions) exceeded the limit.
    TotalPrepaidGasExceeded { total_prepaid_gas: Gas, limit: Gas },
    /// The number of actions exceeded the given limit.
    TotalNumberOfActionsExceeded {
        total_number_of_actions: u64,
        limit: u64,
    },
    /// The total number of bytes of the method names exceeded the limit in a Add Key action.
    AddKeyMethodNamesNumberOfBytesExceeded {
        total_number_of_bytes: u64,
        limit: u64,
    },
    /// The length of some method name exceeded the limit in a Add Key action.
    AddKeyMethodNameLengthExceeded { length: u64, limit: u64 },
    /// Integer overflow during a compute.
    IntegerOverflow,
    /// Invalid account ID.
    InvalidAccountId { account_id: String },
    /// The size of the contract code exceeded the limit in a DeployContract action.
    ContractSizeExceeded { size: u64, limit: u64 },
    /// The length of the method name exceeded the limit in a Function Call action.
    FunctionCallMethodNameLengthExceeded { length: u64, limit: u64 },
    /// The length of the arguments exceeded the limit in a Function Call action.
    FunctionCallArgumentsLengthExceeded { length: u64, limit: u64 },
    /// An attempt to stake with a public key that is not convertible to ristretto.
    UnsuitableStakingKey { public_key: Ed25519PublicKey },
    /// The attached amount of gas in a FunctionCall action has to be a positive number.
    FunctionCallZeroAttachedGas,
}

/// Describes the error for validating a receipt.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ReceiptValidationError {
    /// The `predecessor_id` of a Receipt is not valid.
    InvalidPredecessorId { account_id: String },
    /// The `receiver_id` of a Receipt is not valid.
    InvalidReceiverId { account_id: String },
    /// The `signer_id` of an ActionReceipt is not valid.
    InvalidSignerId { account_id: String },
    /// The `receiver_id` of a DataReceiver within an ActionReceipt is not valid.
    InvalidDataReceiverId { account_id: String },
    /// The length of the returned data exceeded the limit in a DataReceipt.
    ReturnedValueLengthExceeded { length: u64, limit: u64 },
    /// The number of input data dependencies exceeds the limit in an ActionReceipt.
    NumberInputDataDependenciesExceeded {
        number_of_input_data_dependencies: u64,
        limit: u64,
    },
    /// An error occurred while validating actions of an ActionReceipt.
    ActionsValidation(ActionsValidationError),
}

impl Display for ReceiptValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ReceiptValidationError::InvalidPredecessorId { account_id } => {
                write!(f, "The predecessor_id `{account_id}` of a Receipt is not valid.")
            }
            ReceiptValidationError::InvalidReceiverId { account_id } => {
                write!(f, "The receiver_id `{account_id}` of a Receipt is not valid.")
            }
            ReceiptValidationError::InvalidSignerId { account_id } => {
                write!(f, "The signer_id `{account_id}` of an ActionReceipt is not valid.")
            }
            ReceiptValidationError::InvalidDataReceiverId { account_id } => write!(
                f,
                "The receiver_id `{account_id}` of a DataReceiver within an ActionReceipt is not valid."
            ),
            ReceiptValidationError::ReturnedValueLengthExceeded { length, limit } => write!(
                f,
                "The length of the returned data {length} exceeded the limit {limit} in a DataReceipt"
            ),
            ReceiptValidationError::NumberInputDataDependenciesExceeded { number_of_input_data_dependencies, limit } => write!(
                f,
                "The number of input data dependencies {number_of_input_data_dependencies} exceeded the limit {limit} in an ActionReceipt"
            ),
            ReceiptValidationError::ActionsValidation(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReceiptValidationError {}

impl Display for ActionsValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ActionsValidationError::DeleteActionMustBeFinal => {
                write!(f, "The delete action must be the last action in transaction")
            }
            ActionsValidationError::TotalPrepaidGasExceeded { total_prepaid_gas, limit } => {
                write!(f, "The total prepaid gas {total_prepaid_gas} exceeds the limit {limit}")
            }
            ActionsValidationError::TotalNumberOfActionsExceeded {total_number_of_actions, limit } => {
                write!(
                    f,
                    "The total number of actions {total_number_of_actions} exceeds the limit {limit}"
                )
            }
            ActionsValidationError::AddKeyMethodNamesNumberOfBytesExceeded { total_number_of_bytes, limit } => write!(
                f,
                "The total number of bytes in allowed method names {total_number_of_bytes} exceeds the maximum allowed number {limit} in a AddKey action"
            ),
            ActionsValidationError::AddKeyMethodNameLengthExceeded { length, limit } => write!(
                f,
                "The length of some method name {length} exceeds the maximum allowed length {limit} in a AddKey action"
            ),
            ActionsValidationError::IntegerOverflow => write!(
                f,
                "Integer overflow during a compute",
            ),
            ActionsValidationError::InvalidAccountId { account_id } => write!(
                f,
                "Invalid account ID `{account_id}`"
            ),
            ActionsValidationError::ContractSizeExceeded { size, limit } => write!(
                f,
                "The length of the contract size {size} exceeds the maximum allowed size {limit} in a DeployContract action"
            ),
            ActionsValidationError::FunctionCallMethodNameLengthExceeded { length, limit } => write!(
                f,
                "The length of the method name {length} exceeds the maximum allowed length {limit} in a FunctionCall action"
            ),
            ActionsValidationError::FunctionCallArgumentsLengthExceeded { length, limit } => write!(
                f,
                "The length of the arguments {length} exceeds the maximum allowed length {limit} in a FunctionCall action"
            ),
            ActionsValidationError::UnsuitableStakingKey { public_key } => write!(
                f,
                "The staking key must be ristretto compatible ED25519 key. {public_key} is provided instead."
            ),
            ActionsValidationError::FunctionCallZeroAttachedGas => write!(
                f,
                "The attached amount of gas in a FunctionCall action has to be a positive number",
            ),
        }
    }
}

impl std::error::Error for ActionsValidationError {}

/// An error happened during Action execution
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ActionError {
    /// Index of the failed action in the transaction.
    /// Action index is not defined if ActionError.kind is `ActionErrorKind::LackBalanceForState`
    pub index: Option<u64>,
    /// The kind of ActionError happened
    pub kind: ActionErrorKind,
}

impl std::error::Error for ActionError {}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum ActionErrorKind {
    /// Happens when CreateAccount action tries to create an account with account_id which is already exists in the storage
    AccountAlreadyExists { account_id: AccountId },
    /// Happens when TX receiver_id doesn't exist (but action is not Action::CreateAccount)
    AccountDoesNotExist { account_id: AccountId },
    /// A top-level account ID can only be created by registrar.
    CreateAccountOnlyByRegistrar {
        account_id: AccountId,
        registrar_account_id: AccountId,
        predecessor_id: AccountId,
    },
    /// A newly created account must be under a namespace of the creator account
    CreateAccountNotAllowed {
        account_id: AccountId,
        predecessor_id: AccountId,
    },
    /// Administrative actions like `DeployContract`, `Stake`, `AddKey`, `DeleteKey`. can be proceed only if sender=receiver
    /// or the first TX action is a `CreateAccount` action
    ActorNoPermission {
        account_id: AccountId,
        actor_id: AccountId,
    },
    /// Account tries to remove an access key that doesn't exist
    DeleteKeyDoesNotExist {
        account_id: AccountId,
        public_key: Ed25519PublicKey,
    },
    /// The public key is already used for an existing access key
    AddKeyAlreadyExists {
        account_id: AccountId,
        public_key: Ed25519PublicKey,
    },
    /// Account is staking and can not be deleted
    DeleteAccountStaking { account_id: AccountId },
    /// ActionReceipt can't be completed, because the remaining balance will not be enough to cover storage.
    LackBalanceForState {
        /// An account which needs balance
        account_id: AccountId,
        /// Balance required to complete an action.
        #[serde(with = "dec_format")]
        amount: Balance,
    },
    /// Account is not yet staked, but tries to unstake
    TriesToUnstake { account_id: AccountId },
    /// The account doesn't have enough balance to increase the stake.
    TriesToStake {
        account_id: AccountId,
        #[serde(with = "dec_format")]
        stake: Balance,
        #[serde(with = "dec_format")]
        locked: Balance,
        #[serde(with = "dec_format")]
        balance: Balance,
    },
    InsufficientStake {
        account_id: AccountId,
        #[serde(with = "dec_format")]
        stake: Balance,
        #[serde(with = "dec_format")]
        minimum_stake: Balance,
    },
    /// An error occurred during a `FunctionCall` Action, parameter is debug message.
    FunctionCallError(near_vm_errors::FunctionCallErrorSer),
    /// Error occurs when a new `ActionReceipt` created by the `FunctionCall` action fails
    /// receipt validation.
    NewReceiptValidationError(ReceiptValidationError),
    /// Error occurs when a `CreateAccount` action is called on hex-characters
    /// account of length 64.  See implicit account creation NEP:
    /// <https://github.com/nearprotocol/NEPs/pull/71>.
    OnlyImplicitAccountCreationAllowed { account_id: AccountId },
    /// Delete account whose state is large is temporarily banned.
    DeleteAccountWithLargeState { account_id: AccountId },
}

impl From<ActionErrorKind> for ActionError {
    fn from(e: ActionErrorKind) -> ActionError {
        ActionError {
            index: None,
            kind: e,
        }
    }
}

impl Display for InvalidTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            InvalidTxError::InvalidSignerId { signer_id } => {
                write!(
                    f,
                    "Invalid signer account ID {signer_id:?} according to requirements"
                )
            }
            InvalidTxError::SignerDoesNotExist { signer_id } => {
                write!(f, "Signer {signer_id:?} does not exist")
            }
            InvalidTxError::InvalidAccessKeyError(access_key_error) => {
                Display::fmt(&access_key_error, f)
            }
            InvalidTxError::InvalidNonce { tx_nonce, ak_nonce } => write!(
                f,
                "Transaction nonce {tx_nonce} must be larger than nonce of the used access key {ak_nonce}"
            ),
            InvalidTxError::InvalidReceiverId { receiver_id } => {
                write!(
                    f,
                    "Invalid receiver account ID {receiver_id:?} according to requirements"
                )
            }
            InvalidTxError::InvalidSignature => {
                write!(f, "Transaction is not signed with the given public key")
            }
            InvalidTxError::NotEnoughBalance {
                signer_id,
                balance,
                cost,
            } => write!(
                f,
                "Sender {signer_id:?} does not have enough balance {balance} for operation costing {cost}"
            ),
            InvalidTxError::LackBalanceForState { signer_id, amount } => {
                write!(f, "Failed to execute, because the account {signer_id:?} wouldn't have enough balance to cover storage, required to have {amount} yoctoNEAR more")
            }
            InvalidTxError::CostOverflow => {
                write!(f, "Transaction gas or balance cost is too high")
            }
            InvalidTxError::InvalidChain => {
                write!(
                    f,
                    "Transaction parent block hash doesn't belong to the current chain"
                )
            }
            InvalidTxError::Expired => {
                write!(f, "Transaction has expired")
            }
            InvalidTxError::ActionsValidation(error) => {
                write!(f, "Transaction actions validation error: {error}")
            }
            InvalidTxError::NonceTooLarge {
                tx_nonce,
                upper_bound,
            } => {
                write!(
                    f,
                    "Transaction nonce {tx_nonce} must be smaller than the access key nonce upper bound {upper_bound}"
                )
            }
            InvalidTxError::TransactionSizeExceeded { size, limit } => {
                write!(
                    f,
                    "Size of serialized transaction {size} exceeded the limit {limit}"
                )
            }
        }
    }
}

impl From<InvalidAccessKeyError> for InvalidTxError {
    fn from(error: InvalidAccessKeyError) -> Self {
        InvalidTxError::InvalidAccessKeyError(error)
    }
}

impl Display for InvalidAccessKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            InvalidAccessKeyError::AccessKeyNotFound {
                account_id,
                public_key,
            } => write!(
                f,
                "Signer {account_id:?} doesn't have access key with the given public_key {public_key}"
            ),
            InvalidAccessKeyError::ReceiverMismatch {
                tx_receiver,
                ak_receiver,
            } => write!(
                f,
                "Transaction receiver_id {tx_receiver:?} doesn't match the access key receiver_id {ak_receiver:?}",
            ),
            InvalidAccessKeyError::MethodNameMismatch { method_name } => write!(
                f,
                "Transaction method name {method_name:?} isn't allowed by the access key"
            ),
            InvalidAccessKeyError::RequiresFullAccess => {
                write!(f, "Invalid access key type. Full-access keys are required for transactions that have multiple or non-function-call actions")
            }
            InvalidAccessKeyError::NotEnoughAllowance {
                account_id,
                public_key,
                allowance,
                cost,
            } => write!(
                f,
                "Access Key {account_id:?}:{public_key} does not have enough balance {allowance} for transaction costing {cost}"
            ),
            InvalidAccessKeyError::DepositWithFunctionCall => {
                write!(f, "Having a deposit with a function call action is not allowed with a function call access key.")
            }
        }
    }
}

impl std::error::Error for InvalidAccessKeyError {}

/// Happens when the input balance doesn't match the output balance in Runtime apply.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BalanceMismatchError {
    // Input balances
    #[serde(with = "dec_format")]
    pub incoming_validator_rewards: Balance,
    #[serde(with = "dec_format")]
    pub initial_accounts_balance: Balance,
    #[serde(with = "dec_format")]
    pub incoming_receipts_balance: Balance,
    #[serde(with = "dec_format")]
    pub processed_delayed_receipts_balance: Balance,
    #[serde(with = "dec_format")]
    pub initial_postponed_receipts_balance: Balance,
    // Output balances
    #[serde(with = "dec_format")]
    pub final_accounts_balance: Balance,
    #[serde(with = "dec_format")]
    pub outgoing_receipts_balance: Balance,
    #[serde(with = "dec_format")]
    pub new_delayed_receipts_balance: Balance,
    #[serde(with = "dec_format")]
    pub final_postponed_receipts_balance: Balance,
    #[serde(with = "dec_format")]
    pub tx_burnt_amount: Balance,
    #[serde(with = "dec_format")]
    pub slashed_burnt_amount: Balance,
    #[serde(with = "dec_format")]
    pub other_burnt_amount: Balance,
}

impl Display for BalanceMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        // Using saturating add to avoid overflow in display
        let initial_balance = self
            .incoming_validator_rewards
            .saturating_add(self.initial_accounts_balance)
            .saturating_add(self.incoming_receipts_balance)
            .saturating_add(self.processed_delayed_receipts_balance)
            .saturating_add(self.initial_postponed_receipts_balance);
        let final_balance = self
            .final_accounts_balance
            .saturating_add(self.outgoing_receipts_balance)
            .saturating_add(self.new_delayed_receipts_balance)
            .saturating_add(self.final_postponed_receipts_balance)
            .saturating_add(self.tx_burnt_amount)
            .saturating_add(self.slashed_burnt_amount)
            .saturating_add(self.other_burnt_amount);
        write!(
            f,
            "Balance Mismatch Error. The input balance {} doesn't match output balance {}\n\
             Inputs:\n\
             \tIncoming validator rewards sum: {}\n\
             \tInitial accounts balance sum: {}\n\
             \tIncoming receipts balance sum: {}\n\
             \tProcessed delayed receipts balance sum: {}\n\
             \tInitial postponed receipts balance sum: {}\n\
             Outputs:\n\
             \tFinal accounts balance sum: {}\n\
             \tOutgoing receipts balance sum: {}\n\
             \tNew delayed receipts balance sum: {}\n\
             \tFinal postponed receipts balance sum: {}\n\
             \tTx fees burnt amount: {}\n\
             \tSlashed amount: {}\n\
             \tOther burnt amount: {}",
            initial_balance,
            final_balance,
            self.incoming_validator_rewards,
            self.initial_accounts_balance,
            self.incoming_receipts_balance,
            self.processed_delayed_receipts_balance,
            self.initial_postponed_receipts_balance,
            self.final_accounts_balance,
            self.outgoing_receipts_balance,
            self.new_delayed_receipts_balance,
            self.final_postponed_receipts_balance,
            self.tx_burnt_amount,
            self.slashed_burnt_amount,
            self.other_burnt_amount,
        )
    }
}

impl std::error::Error for BalanceMismatchError {}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct IntegerOverflowError;

impl std::fmt::Display for IntegerOverflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{self:?}"))
    }
}

impl std::error::Error for IntegerOverflowError {}

impl From<IntegerOverflowError> for InvalidTxError {
    fn from(_: IntegerOverflowError) -> Self {
        InvalidTxError::CostOverflow
    }
}

impl From<IntegerOverflowError> for RuntimeError {
    fn from(_: IntegerOverflowError) -> Self {
        RuntimeError::UnexpectedIntegerOverflow
    }
}

impl From<StorageError> for RuntimeError {
    fn from(e: StorageError) -> Self {
        RuntimeError::StorageError(e)
    }
}

impl From<BalanceMismatchError> for RuntimeError {
    fn from(e: BalanceMismatchError) -> Self {
        RuntimeError::BalanceMismatchError(e)
    }
}

impl From<InvalidTxError> for RuntimeError {
    fn from(e: InvalidTxError) -> Self {
        RuntimeError::InvalidTxError(e)
    }
}

impl From<EpochError> for RuntimeError {
    fn from(e: EpochError) -> Self {
        RuntimeError::ValidatorError(e)
    }
}

impl Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "Action #{}: {}",
            self.index.unwrap_or_default(),
            self.kind
        )
    }
}

impl Display for ActionErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ActionErrorKind::AccountAlreadyExists { account_id } => {
                write!(f, "Can't create a new account {account_id:?}, because it already exists")
            }
            ActionErrorKind::AccountDoesNotExist { account_id } => write!(
                f,
                "Can't complete the action because account {account_id:?} doesn't exist"
            ),
            ActionErrorKind::ActorNoPermission { actor_id, account_id } => write!(
                f,
                "Actor {actor_id:?} doesn't have permission to account {account_id:?} to complete the action"
            ),
            ActionErrorKind::LackBalanceForState { account_id, amount } => write!(
                f,
                "The account {account_id} wouldn't have enough balance to cover storage, required to have {amount} yoctoNEAR more"
            ),
            ActionErrorKind::TriesToUnstake { account_id } => {
                write!(f, "Account {account_id:?} is not yet staked, but tries to unstake")
            }
            ActionErrorKind::TriesToStake { account_id, stake, locked, balance } => write!(
                f,
                "Account {account_id:?} tries to stake {stake}, but has staked {locked} and only has {balance}"
            ),
            ActionErrorKind::CreateAccountOnlyByRegistrar { account_id, registrar_account_id, predecessor_id } => write!(
                f,
                "A top-level account ID {account_id:?} can't be created by {predecessor_id:?}, short top-level account IDs can only be created by {registrar_account_id:?}"
            ),
            ActionErrorKind::CreateAccountNotAllowed { account_id, predecessor_id } => write!(
                f,
                "A sub-account ID {account_id:?} can't be created by account {predecessor_id:?}"
            ),
            ActionErrorKind::DeleteKeyDoesNotExist { account_id, .. } => write!(
                f,
                "Account {account_id:?} tries to remove an access key that doesn't exist"
            ),
            ActionErrorKind::AddKeyAlreadyExists { public_key, .. } => write!(
                f,
                "The public key {public_key:?} is already used for an existing access key"
            ),
            ActionErrorKind::DeleteAccountStaking { account_id } => {
                write!(f, "Account {account_id:?} is staking and can not be deleted")
            }
            ActionErrorKind::FunctionCallError(s) => write!(f, "{s:?}"),
            ActionErrorKind::NewReceiptValidationError(e) => {
                write!(f, "An new action receipt created during a FunctionCall is not valid: {e}")
            }
            ActionErrorKind::InsufficientStake { account_id, stake, minimum_stake } => write!(f, "Account {account_id} tries to stake {stake} but minimum required stake is {minimum_stake}"),
            ActionErrorKind::OnlyImplicitAccountCreationAllowed { account_id } => write!(f, "CreateAccount action is called on hex-characters account of length 64 {account_id}"),
            ActionErrorKind::DeleteAccountWithLargeState { account_id } => write!(f, "The state of account {account_id} is too large and therefore cannot be deleted"),
        }
    }
}

#[derive(Eq, PartialEq, Clone)]
pub enum EpochError {
    /// Error calculating threshold from given stakes for given number of seats.
    /// Only should happened if calling code doesn't check for integer value of stake > number of seats.
    ThresholdError { stake_sum: Balance, num_seats: u64 },
    /// Missing block hash in the storage (means there is some structural issue).
    MissingBlock(CryptoHash),
    /// Error due to IO (DB read/write, serialization, etc.).
    IOErr(String),
    /// Error getting information for a shard
    ShardingError(String),
    NotEnoughValidators {
        num_validators: u64,
        num_shards: u64,
    },
}

impl std::error::Error for EpochError {}

impl Display for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochError::ThresholdError {
                stake_sum,
                num_seats,
            } => write!(
                f,
                "Total stake {stake_sum} must be higher than the number of seats {num_seats}"
            ),
            EpochError::MissingBlock(hash) => write!(f, "Missing block {hash}"),
            EpochError::IOErr(err) => write!(f, "IO: {err}"),
            EpochError::ShardingError(err) => write!(f, "Sharding Error: {err}"),
            EpochError::NotEnoughValidators {
                num_shards,
                num_validators,
            } => {
                write!(f, "There were not enough validator proposals to fill all shards. num_proposals: {num_validators}, num_shards: {num_shards}")
            }
        }
    }
}

impl Debug for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochError::ThresholdError {
                stake_sum,
                num_seats,
            } => {
                write!(f, "ThresholdError({stake_sum}, {num_seats})")
            }
            EpochError::MissingBlock(hash) => write!(f, "MissingBlock({hash})"),
            EpochError::IOErr(err) => write!(f, "IOErr({err})"),
            EpochError::ShardingError(err) => write!(f, "ShardingError({err})"),
            EpochError::NotEnoughValidators {
                num_shards,
                num_validators,
            } => {
                write!(f, "NotEnoughValidators({num_validators}, {num_shards})")
            }
        }
    }
}

impl From<std::io::Error> for EpochError {
    fn from(error: std::io::Error) -> Self {
        EpochError::IOErr(error.to_string())
    }
}
