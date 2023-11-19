#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

/// API for the network requests to the RPC endpoint.
pub mod client;
#[doc(hidden)]
pub mod components;
pub mod crypto;
#[doc(hidden)]
pub mod near_primitives_light;
pub(crate) mod rpc;
#[doc(hidden)]
pub mod utils;

use std::fmt::Display;

pub use near_primitives_core as core;
pub use near_units;

type Result<T> = std::result::Result<T, Error>;

/// Parse's human-readable string into [Gas](core::types::Gas)
///
/// # Panic
/// If can't correctly parse input into [Gas](core::types::Gas)
pub fn gas(input: &str) -> core::types::Gas {
    near_units::gas::parse(input).unwrap() as u64
}

/// Parse's human-readable string into [Balance](core::types::Balance)
///
/// # Panic
/// If can't correctly parse input into [Balance](core::types::Balance)
pub fn near(input: &str) -> core::types::Balance {
    near_units::near::parse(input).unwrap()
}

/// Converts a Near token amount to a human-readable format.
///
/// ## Arguments
///
/// - `amount` - The amount of Near tokens to convert.
///
/// ## Returns
///
/// Returns a formatted string representing the Near token amount in a
/// human-readable format. The format may include commas for thousands separators,
/// a specific number of decimal places, and a symbol such as "N" to indicate the
/// token type.
///
/// ## Example
///
/// ```rust
/// use near_client::prelude::*;
///
/// let amount: u128 = 123456789000000000000000000000;
/// let formatted_amount = near_to_human(amount);
/// assert_eq!(formatted_amount, "123,456.789 N");
/// ```
pub fn near_to_human(amount: core::types::Balance) -> String {
    near_units::near::to_human(amount)
}

/// Converts a gas amount to a human-readable format.
///
/// ## Arguments
///
/// - `gas` - The amount of gas to convert.
///
/// ## Returns
///
/// Returns a formatted string representing the gas amount in a
/// human-readable format. The format may include commas for thousands separators
/// and a unit such as "MGas" to indicate the gas type.
///
/// ## Example
///
/// ```rust
/// use near_client::prelude::*;
///
/// let gas: u64 = 123456789;
/// let formatted_gas = gas_to_human(gas);
/// assert_eq!(formatted_gas, "123.456789 Mgas");
/// ```
pub fn gas_to_human(gas: core::types::Gas) -> String {
    near_units::gas::to_human(gas as u128)
}

/// Client prelude.
/// All the frequently used API
pub mod prelude {
    pub use super::client::*;
    pub use super::components::*;
    pub use super::core::{
        account::{AccessKeyPermission, Account, FunctionCallPermission},
        types::{AccountId, Balance, Gas, Nonce},
    };
    pub use super::crypto::prelude::*;
    pub use super::near_primitives_light::{
        errors::{self as transaction_errors},
        types::Finality,
    };
    pub use super::{gas, gas_to_human, near, near_to_human};
    pub use transaction_errors::*;
}

/// Describes errors that could be thrown during execution.
/// Each error is self-described
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[doc(hidden)]
    #[error("Failed to create a signer, cause [\"{0}\"]")]
    CreateSigner(crypto::Error),
    #[doc(hidden)]
    #[error("Transaction not started, logs: [\"{0:?}\"]")]
    TxNotStarted(Box<Vec<String>>),
    #[doc(hidden)]
    #[error("Transaction failed during execution, cause [\"{0:?}\"], logs: [\"{1:?}\"]")]
    TxExecution(prelude::TxExecutionError, Box<Vec<String>>),
    #[doc(hidden)]
    #[error("Transaction serialization error: [\"{0}\"]")]
    TxSerialization(std::io::Error),
    #[doc(hidden)]
    #[error("Couldn't serialize an argument [\"{0}\"] to view a transaction, cause: [\"{1}\"]")]
    SerializeTxViewArg(&'static str, serde_json::Error),
    #[doc(hidden)]
    #[error("Couldn't serialize arguments for view or function call, cause: [\"{0}\"]")]
    ArgsSerialization(serde_json::Error),
    #[doc(hidden)]
    #[error("Client creation failed, cause: [\"{0}\"]")]
    CreateClient(rpc::Error),
    #[doc(hidden)]
    #[error("Can't view a transaction, cause: [\"{0}\"]")]
    ViewTransaction(rpc::Error),
    #[doc(hidden)]
    #[error("Failed to execute rpc call to Near blockchain, cause: [\"{0}\"]")]
    RpcError(rpc::Error),
    #[doc(hidden)]
    #[error("Block call failed with an error: \"{0}\"")]
    BlockCall(rpc::Error),
    #[doc(hidden)]
    #[error("View access key call failed with an error: \"{0}\"")]
    ViewAccessKeyCall(ViewAccessKeyCall),
    #[doc(hidden)]
    #[error("View access key list call failed with an error: \"{0}\"")]
    ViewAccessKeyListCall(ViewAccessKeyCall),
    #[doc(hidden)]
    #[error("View call failed with an error: \"{0}\"")]
    ViewCall(rpc::Error),
    #[doc(hidden)]
    #[error("Couldn't deserialize a transaction function output, cause: [\"{0}\"]")]
    DeserializeTransactionOutput(serde_json::Error),
    #[doc(hidden)]
    #[error("Couldn't deserialize a transaction outcome, cause: [\"{0}\"]")]
    DeserializeExecutionOutcome(serde_json::Error),
    #[doc(hidden)]
    #[error("Couldn't deserialize a transaction id, cause: [\"{0}\"]")]
    DeserializeTransactionId(serde_json::Error),
    #[doc(hidden)]
    #[error("Couldn't deserialize a view call result, cause [\"{0}\"]")]
    DeserializeViewCall(serde_json::Error),
    #[doc(hidden)]
    #[error("Couldn't deserialize a view response, cause [\"{0}\"]")]
    DeserializeResponseView(serde_json::Error),
    #[doc(hidden)]
    #[error("Couldn't deserialize a block, cause: [\"{0}\"]")]
    DeserializeBlock(serde_json::Error),
    #[doc(hidden)]
    #[error("Can't deserialize an access key response, cause: [\"{0}\"]")]
    DeserializeAccessKeyViewCall(serde_json::Error),
    #[doc(hidden)]
    #[error("Can't deserialize an access key response, cause: [\"{0}\"]")]
    DeserializeAccessKeyListViewCall(serde_json::Error),
}

#[doc(hidden)]
#[derive(Debug)]
pub enum ViewAccessKeyCall {
    Rpc(rpc::Error),
    ParseError { error: String, logs: Vec<String> },
}

#[doc(hidden)]
impl Display for ViewAccessKeyCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(err) => {
                write!(f, "Rpc error: {err}")
            }
            Self::ParseError { error, logs } => write!(f, "Error during parsing: {error},")
                .and(write!(f, "with logs: "))
                .and(writeln!(
                    f,
                    "{}",
                    logs.iter().fold(String::new(), |init, next| {
                        init + format!("{next}\n").as_str()
                    })
                )),
        }
    }
}
