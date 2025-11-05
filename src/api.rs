use crate::req_res::{
    AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse, AttestationGetEvidenceRequest,
    AttestationGetEvidenceResponse, GetPurposeKeysRequest, GetPurposeKeysResponse,
    PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
    RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
    RetrieveRootKeyRequest, RetrieveRootKeyResponse, ShareRootKeyRequest, ShareRootKeyResponse,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server)]
pub trait TdxQuoteRpc {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Get the secp256k1 public key
    #[method(name = "getPurposeKeys")]
    async fn get_purpose_keys(
        &self,
        req: GetPurposeKeysRequest,
    ) -> RpcResult<GetPurposeKeysResponse>;

    /// Generates attestation evidence from the attestation authority
    #[method(name = "getAttestationEvidence")]
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse>;

    /// Evaluates provided attestation evidence
    #[method(name = "evalAttestationEvidence")]
    async fn eval_attestation_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse>;

    /// Retrieves the root key from an existing node
    #[method(name = "boot.retrieve_root_key")]
    async fn boot_retrieve_root_key(
        &self,
        req: RetrieveRootKeyRequest,
    ) -> RpcResult<RetrieveRootKeyResponse>;

    /// Shares the root key with an existing node
    #[method(name = "boot.share_root_key")]
    async fn boot_share_root_key(
        &self,
        req: ShareRootKeyRequest,
    ) -> RpcResult<ShareRootKeyResponse>;

    /// Genesis boot
    #[method(name = "boot.genesis_boot")]
    async fn boot_genesis(&self) -> RpcResult<()>;

    /// Completes the genesis boot
    #[method(name = "boot.complete_boot")]
    async fn complete_boot(&self) -> RpcResult<()>;

    /// Prepares an encrypted snapshot
    #[method(name = "snapshot.prepare_encrypted_snapshot")]
    async fn prepare_encrypted_snapshot(
        &self,
        req: PrepareEncryptedSnapshotRequest,
    ) -> RpcResult<PrepareEncryptedSnapshotResponse>;

    /// Restores from an encrypted snapshot
    #[method(name = "snapshot.restore_from_encrypted_snapshot")]
    async fn restore_from_encrypted_snapshot(
        &self,
        req: RestoreFromEncryptedSnapshotRequest,
    ) -> RpcResult<RestoreFromEncryptedSnapshotResponse>;
}
