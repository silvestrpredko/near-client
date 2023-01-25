# Near-client

TL;DR
`near-client` is an RPC for [Near Protocol](https://near.org), written in Rust.

## A little bit detailed explatanion
Since RPC call are just simple HTTP-requests to the NEAR's RPC server, it's possible for anybody to use it directly without using web3.js/SDK/etc. 
Near Protocol provides a [documentation](https://docs.near.org/api/rpc/introduction) with how their RPC can be used. Sometimes it's not very convinient (e.g. you want to call those functions in your Rust code), so `near-client` could help you to avoid writing HTTP-requests on your own.

Essentially, `near-client` uses [reqwest](https://github.com/seanmonstar/reqwest) library for building an HTTP client that will send requests over the network.
For now, it provides you with common methods such as `view/deploy_contract/function_call/view_access_keys/etc`.

### Example of usage

First of, you probably want to initialize an instance of client. Only thing you should do, provide it with wanted URL in Near Protocol network. E.g.

```rust
RpcClient::new(url).unwrap()
```

After this you're free to use it as you wish. For instance, you'd like to call some function on your previously deployed contract. Let's say it could be setting some value in a HashTable. Then you can use something like this:

```rust
// signer is Signer from near_cli
// contract_id is a String from NEAR Protocol network
// url is a Url struct representing URL an RPC network server

let client = RpcClient::new(url).unwrap();
let some_result = client
    .function_call(signer, contract_id, "add_value")
    .args(serde_json::json!({
        "superb_value": "5"
    }))
    .gas(parse_gas!("300 T") as u64)
    .commit(Finality::None) // you can choose your finality for a block
    .await
    .unwrap()
```
