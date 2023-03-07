//! Simple near client for contract function calls.
//! Has a multiplatform support.
//! The main goal of this client is to run on wasm32 architecture.

pub mod client;
pub mod crypto;
pub mod near_primitives_light;
pub(crate) mod rpc;
pub mod utils;

pub use near_primitives_core as core;
pub use near_units;

type Result<T> = std::result::Result<T, Error>;

pub mod prelude {
    pub use super::client::*;
    pub use super::crypto::prelude::*;
    pub use super::near_primitives_light::types::Finality;
    pub use super::utils::*;
    pub use near_primitives_core::types::AccountId;
}

/// Describes errors that could be thrown during execution
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to create a signer, cause [\"{0}\"]")]
    CreateSigner(crypto::Error),
    #[error("Transaction not started")]
    TxNotStarted,
    #[error("Transaction failed during execution, cause [\"{0:?}\"]")]
    TxExecution(near_primitives_light::errors::TxExecutionError),
    #[error("Transaction serialization error: [\"{0}\"]")]
    TxSerialization(std::io::Error),
    #[error("Couldn't serialize an argument [\"{0}\"] to view a transaction, cause: [\"{1}\"]")]
    SerializeTxViewArg(&'static str, serde_json::Error),
    #[error("Couldn't serialize arguments for view or function call, cause: [\"{0}\"]")]
    ArgsSerialization(serde_json::Error),
    #[error("Client creation failed, cause: [\"{0}\"]")]
    CreateClient(rpc::Error),
    #[error("Can't view a transaction, cause: [\"{0}\"]")]
    ViewTransaction(rpc::Error),
    #[error("Transaction commit failed with an error, cause: [\"{0}\"]")]
    CommitTransaction(rpc::Error),
    #[error("Transaction async commit failed with an error, cause: [\"{0}\"]")]
    CommitAsyncTransaction(rpc::Error),
    #[error("Block call failed with an error: \"{0}\"")]
    BlockCall(rpc::Error),
    #[error("Access key call failed with an error: \"{0}\"")]
    ViewAccessKeyCall(rpc::Error),
    #[error("View call failed with an error: \"{0}\"")]
    ViewCall(rpc::Error),
    #[error("Couldn't deserialize a transaction function output, cause: [\"{0}\"]")]
    DeserializeTransactionOutput(serde_json::Error),
    #[error("Couldn't deserialize a transaction outcome, cause: [\"{0}\"]")]
    DeserializeExecutionOutcome(serde_json::Error),
    #[error("Couldn't deserialize a transaction id, cause: [\"{0}\"]")]
    DeserializeTransactionId(serde_json::Error),
    #[error("Couldn't deserialize a view call result, cause [\"{0}\"]")]
    DeserializeViewCall(serde_json::Error),
    #[error("Couldn't deserialize a view response, cause [\"{0}\"]")]
    DeserializeResponseView(serde_json::Error),
    #[error("Couldn't deserialize a block, cause: [\"{0}\"]")]
    DeserializeBlock(serde_json::Error),
    #[error("Can't deserialize an access key response, cause: [\"{0}\"]")]
    DeserializeAccessKeyViewCall(serde_json::Error),
}
