use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPurposeKeysRequest {
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPurposeKeysResponse {
    pub tx_io_sk: secp256k1::SecretKey,
    pub tx_io_pk: secp256k1::PublicKey,
    pub snapshot_key_bytes: [u8; 32],
    pub rng_keypair: schnorrkel::keys::Keypair,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationGetEvidenceRequest {
    // For AzTdxVtpm, this affects the quotes's aztdxvtpm.quote.body.report_data
    // pub runtime_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationGetEvidenceResponse {
    pub hcl_report: Vec<u8>,
    pub quote: Vec<u8>,
}

/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Data {
    /// This will be used as the expected runtime/init data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime/Init data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

/// Represents the request to evaluate attestation evidence.
///
/// This struct contains the necessary information for evaluating attestation
/// evidence, including the raw evidence bytes, the TEE (Trusted Execution Environment)
/// type, and optional runtime data and its associated hash algorithm.
///
/// # Fields
///
/// - `evidence`: The raw bytes of the attestation evidence to be evaluated.
/// - `tee`: The TEE type of the attestation evidence, indicating which TEE generated the evidence.
/// - `runtime_data`: The expected runtime data that the evidence should match against. This is optional.
/// - `runtime_data_hash_algorithm`: The hash algorithm to use for the runtime data. This is optional.
///
/// # Notes
///
/// - For the `AzTdxVtpm` TEE, `runtime_data` and `runtime_data_hash_algorithm` must not be `None`.
/// - For empty data in `AzTdxVtpm`, set the following:
///   - `runtime_data = Some(Data::Raw("".into()))`
///   - `runtime_data_hash_algorithm = Some(HashAlgorithm::Sha256)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvalEvidenceRequest {
    pub hcl_report: Vec<u8>,
    pub quote: Vec<u8>,
}

/// Represents the response to an attestation evidence evaluation request.
///
/// This struct contains the result of the attestation evaluation, including whether
/// the evidence was deemed valid and any claims extracted from the evidence.
///
/// # Fields
///
/// - `eval`: A boolean indicating whether the attestation service deemed the evidence valid (`true`) or invalid (`false`).
/// - `claims`: A summary of the claims included in the attestation evidence. This may be `None` if there are no claims.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationEvalEvidenceResponse {
    // todo
}

/// RetieveRootKey endpoint triggers the enclave to retrieve the root key
/// via http from an existing node running the enclave server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRootKeyRequest {
    pub addr: SocketAddr,
    pub attestation_policy_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRootKeyResponse {}

/// ShareRootKey endpoint triggers the enclave to share the root key with
/// an new enclave server that is booting
///
/// It is expected that the attestation is created with the following parameters:
/// - runtime_data: Some(Data::Raw(req.retriever_pk.serialize().to_vec())),
/// - runtime_data_hash_algorithm: HashAlgorithm::Sha256,

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareRootKeyResponse {
    pub root_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrepareEncryptedSnapshotRequest {} // require auth token eventually

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrepareEncryptedSnapshotResponse {
    pub success: bool,
    pub error: String,
    // Potentially add fields if useful:
    // file size
    // block number at snapshot point
    // block hash at snapshot point
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RestoreFromEncryptedSnapshotRequest {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RestoreFromEncryptedSnapshotResponse {
    pub success: bool,
    pub error: String,
}
