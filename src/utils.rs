use crate::near_primitives_light::{
    transaction::{Action, SignedTransaction, Transaction},
    types::Finality,
    views::{
        AccessKeyListView, AccessKeyPermissionView, AccessKeyView, ExecutionOutcomeWithIdView,
        KeysView,
    },
};
use crate::{
    client::{NearClient, Signer},
    rpc::client::RpcClient,
    Error, Result,
};
use near_primitives_core::{
    account::id::AccountId,
    hash::CryptoHash,
    types::{BlockHeight, Nonce},
};
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};
use serde_json::Value;
use serde_with::{base64::Base64, serde_as};
use std::fmt;

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
    pub(crate) fn new(
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

    pub(crate) fn rpc(&self) -> &RpcClient {
        &self.client.rpc_client
    }

    pub(crate) fn signer(&self) -> &Signer {
        self.signer
    }
}

pub(crate) fn extract_logs(
    logs: impl IntoIterator<Item = ExecutionOutcomeWithIdView>,
) -> Vec<String> {
    logs.into_iter()
        .find_map(|it| {
            if it.outcome.logs.is_empty() {
                None
            } else {
                Some(it.outcome.logs)
            }
        })
        .unwrap_or_default()
}

/// Serialize and sign a transaction
/// During call it requests the most recent block [`CryptoHash`]
pub(crate) async fn serialize_transaction<'a>(
    info: &'a TransactionInfo<'_>,
    actions: Vec<Action>,
    block_finality: Finality,
) -> Result<Vec<u8>> {
    let block_hash = info.client.block(block_finality).await?;

    let transaction = Transaction {
        signer_id: info.signer.account().clone(),
        public_key: *info.signer.public_key(),
        nonce: info.signer.nonce() + 1,
        receiver_id: info.contract_id.clone(),
        block_hash,
        actions,
    };

    let signed_transaction = sign_transaction(info.signer, transaction);
    borsh::to_vec(&signed_transaction).map_err(Error::TxSerialization)
}

#[allow(clippy::result_large_err)]
pub(crate) fn serialize_arguments(args: Option<Value>) -> Result<Vec<u8>> {
    Ok(args
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(Error::ArgsSerialization)?
        .unwrap_or_default())
}

pub(crate) fn sign_transaction(signer: &Signer, transaction: Transaction) -> SignedTransaction {
    let (hash, ..) = transaction.get_hash_and_size();
    let signature = signer.sign(hash.0.as_ref());
    SignedTransaction::new(signature, transaction)
}

impl AccessKeyVisitor for ViewAccessKey {
    fn visit_map<'de, Map>(
        mut map: Map,
        block_hash: CryptoHash,
        block_height: BlockHeight,
    ) -> std::result::Result<Self, Map::Error>
    where
        Self: std::marker::Sized,
        Map: de::MapAccess<'de>,
    {
        let next_key = map.next_key::<String>()?;

        match next_key.as_deref() {
            Some("nonce") => {
                let nonce = map.next_value::<Nonce>()?;
                let permission = map
                    .next_entry::<String, AccessKeyPermissionView>()?
                    .ok_or_else(|| de::Error::missing_field("permission"))
                    .and_then(|(key, permission)| {
                        if key != "permission" {
                            Err(serde::de::Error::unknown_field(&key, &["permission"]))
                        } else {
                            Ok(permission)
                        }
                    })?;

                Ok(ViewAccessKey {
                    block_hash,
                    block_height,
                    result: ViewAccessKeyResult::Ok(AccessKeyView { nonce, permission }),
                })
            }
            Some("error") => {
                let error = map.next_value::<String>()?;
                let logs = map
                    .next_entry::<String, Vec<String>>()?
                    .ok_or_else(|| serde::de::Error::missing_field("logs"))
                    .and_then(|(key, logs)| {
                        if key != "logs" {
                            Err(serde::de::Error::unknown_field(&key, &["logs"]))
                        } else {
                            Ok(logs)
                        }
                    })?;

                Ok(ViewAccessKey {
                    block_hash,
                    block_height,
                    result: ViewAccessKeyResult::Err { error, logs },
                })
            }
            Some(field) => Err(serde::de::Error::unknown_field(field, &["nonce", "error"])),
            None => Err(serde::de::Error::missing_field("nonce or error")),
        }
    }
}

impl<'de> Deserialize<'de> for ViewAccessKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(Visit::<ViewAccessKey>::new())
    }
}

impl AccessKeyVisitor for ViewAccessKeyList {
    fn visit_map<'de, Map>(
        mut map: Map,
        block_hash: CryptoHash,
        block_height: BlockHeight,
    ) -> std::result::Result<Self, Map::Error>
    where
        Self: std::marker::Sized,
        Map: de::MapAccess<'de>,
    {
        let next_key = map.next_key::<String>()?;

        match next_key.as_deref() {
            Some("keys") => {
                let keys = map.next_value::<Vec<KeysView>>()?;

                Ok(ViewAccessKeyList {
                    block_hash,
                    block_height,
                    result: ViewAccessKeyListResult::Ok(AccessKeyListView { keys }),
                })
            }
            Some("error") => {
                let error = map.next_value::<String>()?;
                let logs = map
                    .next_entry::<String, Vec<String>>()?
                    .ok_or_else(|| serde::de::Error::missing_field("logs"))
                    .and_then(|(key, logs)| {
                        if key != "logs" {
                            Err(serde::de::Error::unknown_field(&key, &["logs"]))
                        } else {
                            Ok(logs)
                        }
                    })?;

                Ok(ViewAccessKeyList {
                    block_hash,
                    block_height,
                    result: ViewAccessKeyListResult::Err { error, logs },
                })
            }
            Some(field) => Err(serde::de::Error::unknown_field(field, &["keys", "error"])),
            None => Err(serde::de::Error::missing_field("keys or error")),
        }
    }
}

impl<'de> Deserialize<'de> for ViewAccessKeyList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(Visit::<ViewAccessKeyList>::new())
    }
}

struct Visit<T>(std::marker::PhantomData<T>)
where
    T: AccessKeyVisitor;

impl<T> Visit<T>
where
    T: AccessKeyVisitor,
{
    fn new() -> Self {
        Self(std::marker::PhantomData::<T>)
    }
}

trait AccessKeyVisitor {
    fn visit_map<'de, Map>(
        map: Map,
        block_hash: CryptoHash,
        block_height: BlockHeight,
    ) -> std::result::Result<Self, Map::Error>
    where
        Self: std::marker::Sized,
        Map: de::MapAccess<'de>;
}

impl<'de, AccessKeyImpl> Visitor<'de> for Visit<AccessKeyImpl>
where
    AccessKeyImpl: AccessKeyVisitor,
{
    type Value = AccessKeyImpl;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Expecting an key-value map")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let block_hash = map
            .next_entry::<String, CryptoHash>()?
            .ok_or_else(|| de::Error::missing_field("block_hash"))
            .and_then(|(key, block_hash)| {
                if key != "block_hash" {
                    Err(de::Error::unknown_field(&key, &["block_hash"]))
                } else {
                    Ok(block_hash)
                }
            })?;

        let block_height = map
            .next_entry::<String, BlockHeight>()?
            .ok_or_else(|| de::Error::missing_field("block_height"))
            .and_then(|(key, block_hash)| {
                if key != "block_height" {
                    Err(de::Error::unknown_field(&key, &["block_height"]))
                } else {
                    Ok(block_hash)
                }
            })?;

        AccessKeyImpl::visit_map(map, block_hash, block_height)
    }
}
