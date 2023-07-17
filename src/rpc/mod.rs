pub(crate) mod client;

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NearError {
    name: String,
    cause: Cause,
    code: i32,
    data: Value,
    message: String,
}

impl NearError {
    pub fn new_simple(cause: Value) -> Self {
        Self {
            data: cause,
            ..Default::default()
        }
    }

    pub fn new_with_msg(cause: Value, message: String) -> Self {
        Self {
            data: cause,
            message,
            ..Default::default()
        }
    }

    pub fn data(self) -> Value {
        self.data
    }
}

impl Display for NearError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Name: {}, Message: {}, Cause: {}, Descr: {}",
            self.name, self.message, self.cause, self.data
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Cause {
    info: Option<Value>,
    name: String,
}

impl Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(info) = &self.info {
            return write!(f, "{info}");
        }

        Ok(())
    }
}
