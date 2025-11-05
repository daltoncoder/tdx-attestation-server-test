mod api;
mod attestation;
mod req_res;
mod server;
pub mod utils;
use std::net::SocketAddr;

use az_tdx_vtpm::{
    hcl::{self},
    imds, tdx, vtpm,
};
use dcap_rs::types::quotes::version_4::QuoteV4;

use crate::attestation::decode_var_data;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // get_and_verify_quote();
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;

    println!("Starting TDX Quote JSON-RPC Server...");
    server::start_server(addr).await
}

fn get_and_verify_quote() {
    // let bytes = vtpm::get_report().unwrap();
    // let hcl_report = hcl::HclReport::new(bytes).unwrap();
    // let var_data: &[u8] = hcl_report.var_data();

    // println!("var_data: {var_data:?}");
    // let td_report: tdx::TdReport = hcl_report.try_into().unwrap();
    // println!("td report: \n {td_report:?}");

    // let td_quote_bytes = imds::get_td_quote(&td_report).unwrap();
    // let quote = QuoteV4::from_bytes(&td_quote_bytes);
    // println!("QuoteV4: {quote:?}");

    // let bytes = vtpm::get_report_with_report_data(&[1u8; 32]).unwrap();
    // // // vtpm::get_report_with_report_data()
    // let hcl_report = hcl::HclReport::new(bytes).unwrap();

    // let var_data = hcl_report.var_data();

    // let decoded_data = decode_var_data(&var_data);

    // println!("var_datav2: {decoded_data:?}");

    // let td_report: tdx::TdReport = hcl_report.try_into().unwrap();
    // let td_quote_bytes = imds::get_td_quote(&td_report).unwrap();
    // let quote = QuoteV4::from_bytes(&td_quote_bytes);
    // println!("QuoteV4v2: {quote:?}");
    // std::fs::write("td_quote.bin", td_quote_bytes).unwrap();

    // let bytes = vtpm::get_report().unwrap();
    // // vtpm::get_report_with_report_data()
    // let hcl_report = hcl::HclReport::new(bytes).unwrap();

    // // println!("hcl_report: \n {:?}", hcl_report.attestation);
    // let var_data_hash = hcl_report.var_data_sha256();
    //  let ak_pub = hcl_report.ak_pub()?;

    // let td_report: tdx::TdReport = hcl_report.try_into()?;
    // println!("tdx td report: \n {td_report:?}");
    // assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
    // let nonce = "a nonce".as_bytes();

    // let tmp_quote = vtpm::get_quote(nonce)?;
    // println!("tpm_quote: \n {tpm_quote:?}");
    // let der = ak_pub.key.try_to_der()?;
    // let pub_key = PKey::public_key_from_der(&der)?;
    // tpm_quote.verify(&pub_key, nonce)?;
}
