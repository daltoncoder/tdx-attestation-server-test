mod api;
mod attestation;
mod req_res;
mod server;
pub mod utils;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;

    println!("Starting TDX Quote JSON-RPC Server...");
    server::start_server(addr).await
}
