use near_client::{core::hash::CryptoHash, prelude::*};
use std::rc::Rc;
use url::Url;

pub(crate) async fn signer(
    url: Url,
    account_id: AccountId,
    sk: Ed25519SecretKey,
) -> anyhow::Result<Signer> {
    let client = NearClient::new(url)?;
    let pk = Ed25519PublicKey::from(&sk);
    let nonce = client
        .view_access_key(&account_id, &pk, Finality::Final)
        .await?
        .nonce;

    let signer = Signer::from_secret(sk, account_id, nonce);
    Ok(signer)
}

pub(crate) async fn balance(client: NearClient, account_id: &AccountId) -> anyhow::Result<Balance> {
    let account = client.view_account(account_id).await?;
    Ok(account.amount())
}

pub(crate) async fn transfer(
    client: NearClient,
    signer: Rc<Signer>,
    receiver_id: &AccountId,
    amount: Balance,
) -> anyhow::Result<CryptoHash> {
    let output = client
        .send(&signer, receiver_id, amount)
        .retry(Retry::TWICE)
        .commit(Finality::Final)
        .await?;
    Ok(output.id())
}
