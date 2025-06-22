//use std::collections::HashMap;
//use std::str::FromStr;

use ethers::prelude::ProviderError;
use ethers::providers::{Http, Provider};
use jsonrpc_core::{ErrorCode, IoHandler, Params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;

//use crate::networks::Networks;

//mod networks;
mod ws;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use once_cell::sync::OnceCell;

//const BACKEND_ADDRESS: &str = "127.0.0.0:8881";
const BACKEND_ADDRESS: &str = "172.16.3.40:8881";

// mainnet
//const CHAIN_ID: &str = "0x01";
// goerli
//const CHAIN_ID: &str = "0x05";

//static mut SELECTED_NETWORK: Network = Network::mainnet();

static NETWORK: OnceCell<Network> = OnceCell::new();

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Network {
    pub name: String,
    pub chain_id: u32,
    pub explorer_url: Option<String>,
    pub http_url: String,
    pub ws_url: Option<String>,
    pub currency: String,
    pub decimals: u32,
    //#[serde(skip)]
    //listener: Option<Arc<Mutex<BlockListener>>>,
}

impl Network {
    pub fn global() -> &'static Network {
        NETWORK.get().expect("network is not initialized")
    }

    fn mainnet() -> Network {
        Self {
            name: String::from("mainnet"),
            chain_id: 1,
            explorer_url: Some(String::from("https://etherscan.io/search?q=")),
            //http_url: String::from("https://rpc.payload.de"),
            //http_url: String::from("https://ethereum.publicnode.com"),
            //http_url: String::from("http://localhost:9999"),
            http_url: String::from("https://x.y.z:8443"),
            ws_url: None,
            currency: String::from("ETH"),
            decimals: 18,
            //listener: None,
        }
    }

    pub fn goerli() -> Self {
        Self {
            name: String::from("goerli"),
            chain_id: 5,
            explorer_url: Some(String::from("https://goerli.etherscan.io/search?q=")),
            //http_url: String::from("https://rpc.ankr.com/eth_goerli"),
            //http_url: String::from("https://ethereum-goerli.publicnode.com"),
            http_url: String::from("https://eth-goerli.public.blastapi.io"),
            ws_url: None,
            currency: String::from("ETH"),
            decimals: 18,
            //listener: None,
        }
    }

    pub fn sepolia() -> Self {
        Self {
            name: String::from("sepolia"),
            chain_id: 11155111,
            explorer_url: Some(String::from("https://sepolia.etherscan.io/search?q=")),
            http_url: String::from("https://rpc.sepolia.org"),
            //http_url: String::from("https://rpc.ankr.com/eth_sepolia"),
            //http_url: String::from("https://ethereum-sepolia-rpc.publicnode.com"),
            ws_url: None,
            currency: String::from("ETH"),
            decimals: 18,
            //listener: None,
        }
    }

    fn get_provider(&self) -> Provider<Http> {
        Provider::<Http>::try_from(self.http_url.clone()).unwrap()
    }

    fn chain_id_hex(&self) -> &str {
        match self.chain_id {
            1 => "0x01",
            5 => "0x05",
            11155111 => "0xaa36a7",
            _ => "0x01",
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {}

pub struct Handler {
    io: IoHandler,
}

impl Default for Handler {
    fn default() -> Self {
        let mut res = Self {
            io: IoHandler::default(),
        };
        res.add_handlers();
        res
    }
}

//#[derive(Debug, thiserror::Error)]
///// An error thrown when making a call to the provider
//pub enum ProviderError {
//    /// An internal error in the JSON RPC Client
//    #[error("{0}")]
//    JsonRpcClientError(Box<dyn crate::RpcError + Send + Sync>),
//
//    /// An error during ENS name resolution
//    #[error("ens name not found: {0}")]
//    EnsError(String),
//
//    /// Invalid reverse ENS name
//    #[error("reverse ens name not pointing to itself: {0}")]
//    EnsNotOwned(String),
//
//    /// Error in underlying lib `serde_json`
//    #[error(transparent)]
//    SerdeJson(#[from] serde_json::Error),
//
//    /// Error in underlying lib `hex`
//    #[error(transparent)]
//    HexError(#[from] hex::FromHexError),
//
//    /// Error in underlying lib `reqwest`
//    #[error(transparent)]
//    HTTPError(#[from] reqwest::Error),
//
//    /// Custom error from unknown source
//    #[error("custom error: {0}")]
//    CustomError(String),
//
//    /// RPC method is not supported by this provider
//    #[error("unsupported RPC")]
//    UnsupportedRPC,
//
//    /// Node is not supported by this provider
//    #[error("unsupported node client")]
//    UnsupportedNodeClient,
//
//    /// Signer is not available to this provider.
//    #[error("Attempted to sign a transaction with no available signer. Hint: did you mean to use a SignerMiddleware?")]
//    SignerUnavailable,
//}

fn ethers_to_jsonrpc_error(e: ProviderError) -> jsonrpc_core::Error {
    // TODO: probable handle more error types here
    match e {
        ProviderError::JsonRpcClientError(e) => {
            if let Some(e) = e.as_error_response() {
                jsonrpc_core::Error {
                    code: ErrorCode::ServerError(e.code),
                    data: e.data.clone(),
                    message: e.message.clone(),
                }
            } else if e.as_serde_error().is_some() {
                jsonrpc_core::Error::invalid_request()
            } else {
                jsonrpc_core::Error::internal_error()
            }
        }
        _ => jsonrpc_core::Error::internal_error(),
    }
}

impl Handler {
    pub async fn handle(&self, request: String) -> Option<String> {
        println!("Handler::handle request = {}", request);
        let res = self.io.handle_request(&request).await;
        println!("Handler::handle response = {:?}", res);
        res
    }

    fn add_handlers(&mut self) {
        macro_rules! self_handler {
            ($name:literal, $fn:path) => {
                self.io
                    .add_method($name, |params: Params| async move { $fn(params).await });
            };
        }

        macro_rules! provider_handler {
            ($name:literal) => {
                self.io.add_method($name, |params: Params| async move {
                    //let provider = Networks::read().await.get_current_provider();
                    //let provider = Network::mainnet().get_provider();
                    let provider = Network::global().get_provider();

                    let res: jsonrpc_core::Result<serde_json::Value> = provider
                        .request::<_, serde_json::Value>($name, params)
                        .await
                        .map_err(ethers_to_jsonrpc_error);
                    res
                });
            };
        }

        // what is `eth_requestAccounts`'s response?

        // delegate directly to provider
        provider_handler!("eth_estimateGas");
        provider_handler!("eth_gasPrice");
        provider_handler!("eth_call");
        provider_handler!("eth_blockNumber"); // one of these block numbers was added by me
        provider_handler!("eth_getBlockByNumber");
        provider_handler!("net_version");
        provider_handler!("eth_getTransactionByHash"); // needed by uniswap post-swap for receipt
        provider_handler!("eth_getTransactionReceipt"); // needed by uniswap post-swap for receipt
        provider_handler!("eth_getCode"); // needed by cowswap mainnet -- but not needed in goerli :/

        provider_handler!("eth_getTransactionCount"); // needed by cowswap while testing sapoli, 2024-12-02

        // handle internally
        self_handler!("eth_accounts", Self::accounts);
        self_handler!("eth_requestAccounts", Self::accounts);
        self_handler!("eth_chainId", Self::chain_id);
        self_handler!("eth_sendTransaction", Self::send_transaction);

        // these two are needed to trade erc-20 on uniswap
        //self_handler!("eth_sign", Self::eth_sign);
        self_handler!("eth_signTypedData_v4", Self::eth_sign_typed_data_v4);

        //self_handler!("personal_sign", Self::eth_sign);
        self_handler!("metamask_getProviderState", Self::provider_state); // added to see if it improves wallet initialization on page re-load, etc

        // disabled in 2024-12-02
        self_handler!("wallet_switchEthereumChain", Self::switch_chain);

        //self_handler!("eth_signTypedData", Self::eth_sign_typed_data_v4);
    }

    async fn accounts(_: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let mut stream = TcpStream::connect(BACKEND_ADDRESS).await.unwrap();

        let request = "eth_accounts";
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.readable().await.unwrap();

        let mut buf = [0; 40960];
        stream.try_read(&mut buf).unwrap();

        let res = std::str::from_utf8(&buf).unwrap();
        let res = res.trim_end_matches(0 as char);

        Ok(json!([res]))
    }

    async fn chain_id(_: Params) -> jsonrpc_core::Result<serde_json::Value> {
        //let chain_id_hex = "0x01";
        //let chain_id_hex = CHAIN_ID;
        let chain_id_hex = Network::global().chain_id_hex();

        Ok(json!(chain_id_hex))
    }

    async fn provider_state(_: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let network = Network::global();

        let address = {
            let mut stream = TcpStream::connect(BACKEND_ADDRESS).await.unwrap();

            let request = "eth_accounts";
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.readable().await.unwrap();

            let mut buf = [0; 40960];
            stream.try_read(&mut buf).unwrap();

            let res = std::str::from_utf8(&buf).unwrap();
            let res = res.trim_end_matches(0 as char);

            res.to_string()
        };

        Ok(json!({
            "isUnlocked": true,
            "chainId": network.chain_id_hex(),
            "networkVersion": network.name,
            "accounts": [address],
        }))
    }

    async fn send_transaction<T: Into<serde_json::Value>>(
        params: T,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let mut stream = TcpStream::connect(BACKEND_ADDRESS).await.unwrap();

        let p: serde_json::Value = params.into();
        let params = &p[0];

        let strip_quotes = |value: String| -> String {
            value
                .strip_prefix('"')
                .unwrap()
                .strip_suffix('"')
                .unwrap()
                .to_string()
        };

        // on https://metamask.github.io/test-dapp/
        println!("sendTransaction::params = {params}");

        //let nonce = &params["nonce"]; // must get from rpc
        let gas = &params["gas"].to_string();
        //let gasTipCap = &params["gasTipCap"]; // must get from rpc
        //let gasFeeCap = &params["gasFeeCap"]; // must get from rpc
        //let chainID = &params["chainID"]; // must get from STATIC var
        let to = &params["to"].to_string();
        let amount = params["value"].to_string(); // NOTICE: `value`
        let amount = if amount == "null" {
            "\"0x0\"".to_string()
        } else {
            amount
        };
        let data = &params["data"].to_string();
        let from = strip_quotes(params["from"].to_string());

        let provider = Network::global().get_provider();
        let nonce = {
            let res: jsonrpc_core::Result<serde_json::Value> = provider
                .request::<_, serde_json::Value>(
                    "eth_getTransactionCount",
                    //json!([WALLET_ADDR, "latest"]),
                    json!([from, "latest"]),
                )
                .await
                .map_err(|err| {
                    println!("nonce err = {}", err);
                    ethers_to_jsonrpc_error(err)
                });

            res.unwrap().to_string()
        };
        let gas_price = strip_quotes({
            let res: jsonrpc_core::Result<serde_json::Value> = provider
                .request::<_, serde_json::Value>("eth_gasPrice", json!([]))
                .await
                .map_err(ethers_to_jsonrpc_error);

            res.unwrap().to_string()
        });
        let gas_tip_cap = strip_quotes({
            let res: jsonrpc_core::Result<serde_json::Value> = provider
                .request::<_, serde_json::Value>("eth_maxPriorityFeePerGas", json!([]))
                .await
                .map_err(|err| {
                    println!("nonce err = {}", err);
                    ethers_to_jsonrpc_error(err)
                });

            res.unwrap().to_string()
        });
        //let gasPrice = "\"0x61A80\"";
        //let gasTipCap = "\"0x61A80\"";
        //let gasTipCap = gasPrice.clone(); // eth_maxPriorityFeePerGas

        println!("received nonce = {nonce}");
        println!("received gasPrice = {gas_price}");
        println!("received gasTipCap = {gas_tip_cap}");

        let chain_id = Network::global().chain_id_hex();

        //let tx = format!("nonce=0 gas=21000 gasTipCap=1000000000 gasFeeCap=15000000000 chainID=1 to={} amount=1000000000", params["to"]);
        //let tx = format!("nonce={nonce} gas={gas} gasTipCap={gasTipCap} gasFeeCap={gasFeeCap} chainID={chainID} to={to} amount={amount}");
        //let tx = format!("nonce={nonce} gas={gas} gasTipCap=1000000000 gasFeeCap={gasPrice} chainID={chainID} to={to} amount={amount}");
        let tx = format!(
            "nonce={} gas={} gasTipCap={} gasFeeCap={} chainID={} to={} amount={} data={}",
            &nonce[1..nonce.len() - 1],
            &gas[1..gas.len() - 1],
            gas_tip_cap,
            gas_price,
            chain_id,
            &to[1..to.len() - 1],
            &amount[1..amount.len() - 1],
            &data[3..data.len() - 1],
        );

        stream.write_all(tx.as_bytes()).await.unwrap();

        // Wait for the socket to be readable
        stream.readable().await.unwrap();

        let mut buf = [0; 40960];
        stream.try_read(&mut buf).unwrap();

        let res = std::str::from_utf8(&buf).unwrap();
        let res = res.trim_end_matches(0 as char);
        println!("\n\nsendTransaction::received = {res}\n\n");

        let tx_hash = {
            let res: jsonrpc_core::Result<serde_json::Value> = provider
                .request::<_, serde_json::Value>("eth_sendRawTransaction", json!([res]))
                .await
                //.map_err(ethers_to_jsonrpc_error);
                .map_err(|err| {
                    println!("broadcast err = {}", err);
                    ethers_to_jsonrpc_error(err)
                });

            let res = res.unwrap().to_string();

            res[1..res.len() - 1].to_string()
        };

        Ok(json!(tx_hash))
    }

    async fn switch_chain(_params: Params) -> jsonrpc_core::Result<serde_json::Value> {
        // TODO(xphoniex)
        Ok(serde_json::Value::Null)
    }

    async fn eth_sign_typed_data_v4(params: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let params = params.parse::<Vec<Option<String>>>().unwrap();
        //let _address = Address::from_str(&params[0].as_ref().cloned().unwrap()).unwrap();
        let data = params[1].as_ref().cloned().unwrap();
        //let typed_data: eip712::TypedData = serde_json::from_str(&data).unwrap();

        let mut stream = TcpStream::connect(BACKEND_ADDRESS).await.unwrap();

        let request = format!("eth_signTypedData_v4 {}", data);

        stream.write_all(request.as_bytes()).await.unwrap();

        // Wait for the socket to be readable
        stream.readable().await.unwrap();

        let mut buf = [0; 40960];
        stream.try_read(&mut buf).unwrap();

        let res = std::str::from_utf8(&buf).unwrap();
        let res = res.trim_end_matches(0 as char);



        Ok(json!(res))
    }

    /*
     * this is paranoid wallet implementation
     *
    async fn eth_sign(params: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let params = params.parse::<Vec<Option<String>>>().unwrap();
        let msg = params[0].as_ref().cloned().unwrap();
        //let address = Address::from_str(&params[1].as_ref().cloned().unwrap()).unwrap();

        let mut stream = TcpStream::connect(BACKEND_ADDRESS).await.unwrap();

        let request = format!("eth_sign {}", msg);
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.readable().await.unwrap();

        let mut buf = [0; 40960];
        stream.try_read(&mut buf).unwrap();

        let res = std::str::from_utf8(&buf).unwrap();
        let res = res.trim_end_matches(0 as char);

        Ok(json!(res))
    }
    */

    /*
    async fn accounts(_: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let wallets = Wallets::read().await;
        let address = wallets.get_current_wallet().get_current_address().await;

        Ok(json!([address]))
    }

    async fn chain_id(_: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let networks = Networks::read().await;
        let network = networks.get_current_network();
        Ok(json!(network.chain_id_hex()))
    }

    async fn provider_state(_: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let networks = Networks::read().await;
        let wallets = Wallets::read().await;

        let network = networks.get_current_network();
        let address = wallets.get_current_wallet().get_current_address().await;

        Ok(json!({
            "isUnlocked": true,
            "chainId": network.chain_id_hex(),
            "networkVersion": network.name,
            "accounts": [address],
        }))
    }

    async fn switch_chain(params: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let params = params.parse::<Vec<HashMap<String, String>>>().unwrap();
        let chain_id_str = params[0].get("chainId").unwrap().clone();
        let chain_id = u32::from_str_radix(&chain_id_str[2..], 16).unwrap();

        let mut networks = Networks::write().await;
        match networks.set_current_network_by_id(chain_id) {
            Ok(_) => Ok(serde_json::Value::Null),
            Err(e) => Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        }
    }

    async fn send_transaction<T: Into<serde_json::Value>>(
        params: T,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        // TODO: should we scope these rwlock reads so they don't stick during sining?
        let networks = Networks::read().await;
        let wallets = Wallets::read().await;

        let network = networks.get_current_network();
        let wallet = wallets.get_current_wallet();

        let signer = wallet
            .build_signer(network.chain_id)
            .await
            .map_err(|e| Error::SignerBuild(e.to_string()))?;

        let mut sender = SendTransaction::default();

        let sender = sender
            .set_params(params.into())
            .set_chain_id(network.chain_id)
            .set_signer(SignerMiddleware::new(network.get_provider(), signer))
            .estimate_gas()
            .await;

        if network.is_dev() && wallet.is_dev() {
            sender.skip_dialog();
        }

        let result = sender.finish().await;

        match result {
            Ok(res) => Ok(res.tx_hash().encode_hex().into()),
            Err(e) => Ok(e.to_string().into()),
        }
    }

    async fn eth_sign(params: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let params = params.parse::<Vec<Option<String>>>().unwrap();
        let msg = params[0].as_ref().cloned().unwrap();
        let address = Address::from_str(&params[1].as_ref().cloned().unwrap()).unwrap();

        // TODO: ensure from == signer

        let networks = Networks::read().await;
        let network = networks.get_current_network();
        let provider = network.get_provider();
        let signer = Wallets::read()
            .await
            .get_current_wallet()
            .build_signer(network.chain_id)
            .await
            .unwrap();
        let signer = SignerMiddleware::new(provider, signer);

        let bytes = Bytes::from_str(&msg).unwrap();
        let res = signer.sign(bytes, &address).await;

        match res {
            Ok(res) => Ok(format!("0x{}", res).into()),
            Err(e) => Ok(e.to_string().into()),
        }
    }

    async fn eth_sign_typed_data_v4(params: Params) -> jsonrpc_core::Result<serde_json::Value> {
        let params = params.parse::<Vec<Option<String>>>().unwrap();
        let _address = Address::from_str(&params[0].as_ref().cloned().unwrap()).unwrap();
        let data = params[1].as_ref().cloned().unwrap();
        let typed_data: eip712::TypedData = serde_json::from_str(&data).unwrap();

        let networks = Networks::read().await;
        let network = networks.get_current_network();
        let signer = Wallets::read()
            .await
            .get_current_wallet()
            .build_signer(network.chain_id)
            .await
            .unwrap();
        // TODO: ensure from == signer

        let res = signer.sign_typed_data(&typed_data).await;

        match res {
            Ok(res) => Ok(format!("0x{}", res).into()),
            Err(e) => Ok(e.to_string().into()),
        }
    }
    */
}

fn main() {
    println!("start");

    let network = Network::sepolia();
    //let network = Network::goerli();
    //let network = Network::mainnet();
    NETWORK.set(network).unwrap();

    let runtime = Runtime::new().unwrap();
    runtime.block_on(async move { ws::ws_server_loop().await });
}
