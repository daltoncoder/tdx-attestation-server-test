use crate::{
    api::TdxQuoteRpcServer,
    attestation::AttestationAgent,
    req_res::{
        AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse,
        AttestationGetEvidenceRequest, AttestationGetEvidenceResponse, GetPurposeKeysRequest,
        GetPurposeKeysResponse, PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
        RetrieveRootKeyRequest, RetrieveRootKeyResponse, ShareRootKeyRequest, ShareRootKeyResponse,
    },
    utils::anyhow_to_rpc_error,
};
use dcap_rs::types::quotes::version_4::QuoteV4;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    server::ServerBuilder,
};
use std::net::SocketAddr;

pub struct TdxQuoteServer {
    attestation_agent: AttestationAgent,
}

impl TdxQuoteServer {
    pub fn new() -> Self {
        Self {
            attestation_agent: AttestationAgent::new().unwrap(),
        }
    }
}

#[async_trait]
impl TdxQuoteRpcServer for TdxQuoteServer {
    /// Health check endpoint that returns "OK" if service is running
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".to_string())
    }

    /// Get the secp256k1 public key
    async fn get_purpose_keys(
        &self,
        req: GetPurposeKeysRequest,
    ) -> RpcResult<GetPurposeKeysResponse> {
        todo!()
    }

    /// Generates attestation evidence from the attestation authority
    async fn get_attestation_evidence(
        &self,
        _req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        self.attestation_agent
            .get_attestation_evidence()
            .map_err(anyhow_to_rpc_error)
    }

    /// Evaluates provided attestation evidence
    async fn eval_attestation_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        let quote = QuoteV4::from_bytes(&req.quote);
        self.attestation_agent
            .verify_attestation_report(quote)
            .map_err(anyhow_to_rpc_error)
    }

    /// Retrieves the root key from an existing node
    async fn boot_retrieve_root_key(
        &self,
        req: RetrieveRootKeyRequest,
    ) -> RpcResult<RetrieveRootKeyResponse> {
        todo!()
    }

    /// Shares the root key with an existing node
    async fn boot_share_root_key(
        &self,
        req: ShareRootKeyRequest,
    ) -> RpcResult<ShareRootKeyResponse> {
        todo!()
    }

    /// Genesis boot
    async fn boot_genesis(&self) -> RpcResult<()> {
        todo!()
    }

    /// Completes the genesis boot
    async fn complete_boot(&self) -> RpcResult<()> {
        todo!()
    }

    /// Prepares an encrypted snapshot
    async fn prepare_encrypted_snapshot(
        &self,
        req: PrepareEncryptedSnapshotRequest,
    ) -> RpcResult<PrepareEncryptedSnapshotResponse> {
        todo!()
    }

    /// Restores from an encrypted snapshot
    async fn restore_from_encrypted_snapshot(
        &self,
        req: RestoreFromEncryptedSnapshotRequest,
    ) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
        todo!()
    }
}

pub async fn start_server(addr: SocketAddr) -> anyhow::Result<()> {
    let server = ServerBuilder::default().build(addr).await?;

    let handle = server.start(TdxQuoteServer::new().into_rpc());

    println!("TDX Quote JSON-RPC Server started at {}", addr);

    handle.stopped().await;
    Ok(())
}
