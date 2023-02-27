use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, ClientBuilder, Response as Resp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Error, NearError};
use std::borrow::Cow;
use url::Url;

type Result<T> = std::result::Result<T, Error>;

pub(crate) struct RpcClient {
    client: Client,
    url: Url,
}

impl RpcClient {
    /// Creates a [`reqwest`] client with headers:
    /// [`CONTENT_TYPE`]: "application/json"
    ///
    /// Arguments
    ///
    /// - url - It's an RPC endpoint [`Url`]
    pub(crate) fn new(url: Url) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let client = ClientBuilder::new()
            .default_headers(headers)
            .build()
            .map_err(Error::RpcClientCreate)?;

        Ok(Self { client, url })
    }

    /// RPC call to the NEAR network
    ///
    /// Arguments
    ///
    /// - method - RPC method
    /// - params - method arguments, could be empty
    ///
    /// Response example:
    /// ```json
    /// {
    ///   "id": "dontcare",
    ///   "jsonrpc": "2.0",
    ///   "result": "...",
    /// }
    ///
    /// ```
    pub(crate) async fn request(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let resp = self
            .client
            .post(self.url.clone())
            .json(
                &serde_json::to_value(&Request::new(method, params))
                    .map_err(Error::SerializeRpcRequest)?,
            )
            .send()
            .await
            .and_then(Resp::error_for_status)
            .map_err(Error::RpcRequest)?;

        match resp
            .json::<Response>()
            .await
            .map_err(Error::DeserializeRpcResponse)?
        {
            Response {
                result: RpcResult::Ok(data),
                ..
            } => Ok(data),
            Response {
                result: RpcResult::Err(err),
                ..
            } => Err(err.into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Request<'a> {
    /// JSON-RPC version.
    pub jsonrpc: &'static str,
    /// Request ID
    pub id: &'static str,
    /// Name of the method to be invoked.
    #[serde(borrow)]
    pub method: Cow<'a, str>,
    /// Parameter values of the request.
    pub params: Option<Value>,
}

impl<'a> Request<'a> {
    fn new(method: &'a str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id: "dontcare",
            method: Cow::from(method),
            params,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Result.
    #[serde(flatten)]
    pub result: RpcResult,
    /// Request ID
    pub id: String,
}

/// Near result format
#[derive(Debug, Serialize, Deserialize)]
enum RpcResult {
    #[serde(rename = "result")]
    Ok(Value),
    #[serde(rename = "error")]
    Err(NearError),
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn response_sample() {
        let resp = Response {
            jsonrpc: "2.0".to_owned(),
            result: RpcResult::Ok(Value::String("some value".to_owned())),
            id: "dontcare".to_owned(),
        };

        assert_eq!(
            serde_json::to_value(resp).unwrap(),
            serde_json::to_value(serde_json::json!({
                "id": "dontcare",
                "jsonrpc": "2.0",
                "result": "some value",
            }))
            .unwrap()
        );
    }
}
