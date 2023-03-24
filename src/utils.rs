use crate::near_primitives_light::{
    transaction::{Action, SignedTransaction, Transaction},
    types::Finality,
    views::{AccessKeyPermissionView, AccessKeyView, ExecutionOutcomeWithIdView},
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

impl<'de> Deserialize<'de> for ViewAccessKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visit;

        impl<'de> Visitor<'de> for Visit {
            type Value = ViewAccessKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "Expecting an key-value map")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let block_hash = map
                    .next_entry::<String, CryptoHash>()?
                    .ok_or_else(|| de::Error::missing_field("block_hash"))
                    .and_then(|(key, block_hash)| {
                        if key != "block_hash" {
                            Err(serde::de::Error::unknown_field(&key, &["block_hash"]))
                        } else {
                            Ok(block_hash)
                        }
                    })?;

                let block_height = map
                    .next_entry::<String, BlockHeight>()?
                    .ok_or_else(|| de::Error::missing_field("block_height"))
                    .and_then(|(key, block_hash)| {
                        if key != "block_height" {
                            Err(serde::de::Error::unknown_field(&key, &["block_height"]))
                        } else {
                            Ok(block_hash)
                        }
                    })?;

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

        deserializer.deserialize_map(Visit)
    }
}
