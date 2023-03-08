# Near-client

TL;DR
`near-client` is an implementation of RPC [Near Protocol](https://near.org)

## A little bit detailed explatanion

The main purpose of the library is to be cross-platform. It could be compiled to any target `wasm`, `x64`, `arm`, etc...
That leads to the main purpose of programming **write once, and run everywhere**. The resulting library for contract calls could be used on any platform and with any front end.

Near Protocol provides a [documentation](https://docs.near.org/api/rpc/introduction) with how their RPC can be used. Sometimes it's not very convenient (e.g. you want to call those functions in your Rust code), so `near-client` could help you to avoid writing HTTP-requests on your own. For now, it provides you with common methods such as `view/deploy_contract/function_call/view_access_keys/etc`.

### Example of usage

For just a viewing the ```contract```, let's create an ```RpcClient``` instance and call view.

```rust
let client = RpcClient::new(url).unwrap(); // Please handle an error
let output = client
        .view::<String>(
            contract_id, // `AccountId` of a contract id
            Finality::None, // Take a look in a documentation
            "show_type", // name of the function that we are trying to call
            Some(json!({"is_message": true})),
        )
        .await
        .unwrap(); // Handle an error

output // is an output of a contract execution 
```
If a transaction should be executed, `Signer` object should be created.
```rust
Signer::from_secret_str(secret_key, account_id, nonce)
Signer::from_secret(secret_key, account_id, nonce)
```

Secret key in a `str` representation, should look similar to this
`ed25519:5nEtNZTBUPJUwB7v9tfCgm1xfp1E7wXcZdWDpz1JwKckqG5pqstumaqRHJjtfFZMtik4TpgCVmmpvpxjEcq3CTLx`

It's a combination of a prefix `ed25519`:secret key + public key in a `base58` format.

After this you're free to use it as you wish. For instance, you'd like to call some function on your previously deployed contract. Let's say it could be setting some value in a HashTable. Then you can use something like this:

```rust
let result = client
    .function_call(signer, contract_id, "add_value")
    .args(serde_json::json!({
        "superb_value": "5"
    }))
    .gas(parse_gas!("300 T") as u64)
    .commit(Finality::None) // you can choose your finality for a block
    .await
    .unwrap()
```
