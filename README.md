![crates.io](https://img.shields.io/crates/v/near-client.svg)

# Near-client

TL;DR
`near-client` is an implementation of RPC [Near Protocol](https://near.org)

## Detailed Explanation
The primary objective of this library is to achieve **cross-platform** compatibility. It can be compiled for various targets such as `wasm`, `linux`, `ios`, `android`, and more. The overarching goal is to embrace the philosophy of ***write once, and run everywhere***. The resulting library, designed for contract calls, is versatile and can seamlessly integrate with any platform and frontend.

While Near Protocol offers comprehensive documentation on how to use their RPC (Remote Procedure Call) system, there are instances where it may not be the most convenient, especially when you want to invoke these functions in your Rust code. The near-client library comes to the rescue by simplifying the process, eliminating the need to manually craft HTTP requests. Currently, it offers a set of common methods such as `view`, `deploy_contract`, `function_call`, `view_access_keys`, `view_account`, and more.

### [Live Demo](https://silvestrpredko.github.io/near-client/)

You could find the implementation code in [`examples/wallet`](https://github.com/silvestrpredko/near-client/tree/develop/examples/wallet)

### Example of usage

For just a viewing the ```contract```, let's create an ```NearClient``` instance and call view.

```rust
let client = NearClient::new(url).unwrap(); // Please handle an error
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
    .gas(gas("300 T"))
    .commit(Finality::None) // you can choose your finality for a block
    .retry(Retry::ONCE) // If InvalidNonce error received try to execute one more time
    .await
    .unwrap()
```

## Updating GitHub Pages
To update your GitHub Pages, follow these steps:

1. Build your app using the command: `trunk build --release --public-url near-client`
2. Copy all files from the dist directory and paste them into the gh-pages branch.
3. Commit the changes and push them to your repository.
