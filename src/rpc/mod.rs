pub(crate) mod client;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Couldn't create a RpcClient: [\"{0}\"]")]
    RpcClientCreate(reqwest::Error),
    #[error("Rpc request failed with: [\"{0}\"]")]
    RpcRequest(reqwest::Error),
    #[error("Failed to serialize an RPC request: [\"{0}\"]")]
    SerializeRpcRequest(serde_json::Error),
    #[error("Failed to deserialize an RPC response: [\"{0}\"]")]
    DeserializeRpcResponse(reqwest::Error),
    #[error("Near protocol error: [\"{0}\"]")]
    NearProtocol(NearError),
}

impl From<NearError> for Error {
    fn from(err: NearError) -> Self {
        Self::NearProtocol(err)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NearError {
    #[serde(flatten)]
    error: NearErrorVariant,
    data: Option<Value>,
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "name", content = "cause")]
pub enum NearErrorVariant {
    #[serde(rename = "REQUEST_VALIDATION_ERROR")]
    RequestValidation(CauseKind),
    #[serde(rename = "HANDLER_ERROR")]
    Handler(CauseKind),
    #[serde(rename = "INTERNAL_ERROR")]
    Internal(CauseKind),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "name", content = "info", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CauseKind {
    InvalidTransaction(Value),
    TimeoutError,
    ParseError(Value),
    InternalError(Value),
}

impl NearError {
    pub fn handler(cause: Value) -> Self {
        Self {
            error: NearErrorVariant::Handler(CauseKind::InvalidTransaction(cause)),
            data: None,
            message: None,
        }
    }

    pub fn data(&self) -> Option<&Value> {
        self.data.as_ref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn error(&self) -> &NearErrorVariant {
        &self.error
    }
}

impl Display for NearError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error: {:?}, Message: {:?}, Data: {:?}",
            self.error, self.message, self.data
        )
    }
}
