use crate::{
    client::{NearClient, Signer},
    near_primitives_light::views::{AccessKeyListView, AccessKeyView},
    rpc::client::RpcClient,
};
use near_primitives_core::{account::id::AccountId, hash::CryptoHash, types::BlockHeight};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{base64::Base64, serde_as};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum CallResult {
    #[serde(rename = "result")]
    Ok(Vec<u8>),
    #[serde(rename = "error")]
    Err(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ViewResult {
    #[serde(flatten)]
    pub result: CallResult,
    pub logs: Vec<String>,
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub enum ViewAccessKeyResult {
    Ok(AccessKeyView),
    Err { error: String, logs: Vec<String> },
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ViewAccessKey {
    pub block_hash: CryptoHash,
    pub block_height: BlockHeight,
    pub result: ViewAccessKeyResult,
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub enum ViewAccessKeyListResult {
    Ok(AccessKeyListView),
    Err { error: String, logs: Vec<String> },
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ViewAccessKeyList {
    pub block_hash: CryptoHash,
    pub block_height: BlockHeight,
    pub result: ViewAccessKeyListResult,
}

/// A single record in a contract
/// that consist of key and value
///
/// # Examples
///
/// ```
/// use near_sdk::collections::LookupMap;
/// let mut map: LookupMap<String, String> = LookupMap::new(b"m");
/// ```
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateItem {
    /// Key in a binary format
    #[serde_as(as = "Base64")]
    pub key: Vec<u8>,
    /// Value in a binary format
    #[serde_as(as = "Base64")]
    pub value: Vec<u8>,
}

/// View contract state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewStateResult {
    /// Records in a contract storage
    pub values: Vec<StateItem>,
}

pub(crate) struct TransactionInfo<'a> {
    client: &'a NearClient,
    signer: &'a Signer,
    contract_id: &'a AccountId,
}

impl<'a> TransactionInfo<'a> {
    pub(crate) const fn new(
        client: &'a NearClient,
        signer: &'a Signer,
        contract_id: &'a AccountId,
    ) -> Self {
        Self {
            client,
            signer,
            contract_id,
        }
    }

    pub(crate) const fn rpc(&self) -> &RpcClient {
        &self.client.rpc_client
    }

    pub(crate) const fn client(&self) -> &NearClient {
        self.client
    }

    pub(crate) const fn signer(&self) -> &Signer {
        self.signer
    }

    pub(crate) const fn contract(&self) -> &AccountId {
        self.contract_id
    }
}
