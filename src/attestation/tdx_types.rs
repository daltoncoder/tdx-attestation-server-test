use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HclVarData {
    pub keys: Vec<JwkKey>,
    #[serde(rename = "vm-configuration")]
    pub vm_configuration: VmConfiguration,
    #[serde(rename = "user-data")]
    pub user_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkKey {
    pub kid: String,
    pub key_ops: Vec<String>,
    pub kty: String,
    pub e: String,
    pub n: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VmConfiguration {
    #[serde(rename = "console-enabled")]
    pub console_enabled: bool,
    #[serde(rename = "root-cert-thumbprint")]
    pub root_cert_thumbprint: String,
    #[serde(rename = "secure-boot")]
    pub secure_boot: bool,
    #[serde(rename = "tpm-enabled")]
    pub tpm_enabled: bool,
    #[serde(rename = "tpm-persisted")]
    pub tpm_persisted: bool,
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: String,
}
