use anyhow::{Context, Result, anyhow};

use crate::attestation::CA;

pub trait PccsProvider {
    fn new() -> Self;
    async fn get_tcb_info(&self, tcb_type: u8, fmspc: &str, version: u32) -> Result<Vec<u8>>;

    async fn get_enclave_identity(&self, version: u32) -> Result<Vec<u8>>;

    async fn get_certificate_by_id(&self, ca_id: CA) -> Result<(Vec<u8>, Vec<u8>)>;
}

pub struct IntelPccs {
    base_url: String,
    client: reqwest::Client,
    subscription_key: Option<String>,
}

impl PccsProvider for IntelPccs {
    fn new() -> Self {
        Self {
            base_url: "https://pccs.scrtlabs.com".to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            subscription_key: None,
        }
    }

    /// Get TCB Info for SGX or TDX
    ///
    /// # Arguments
    /// * `tcb_type` - 0 for SGX, 1 for TDX
    /// * `fmspc` - Hex-encoded FMSPC value (12 hex chars representing 6 bytes)
    /// * `version` - API version (should be 4 for v4 API)
    async fn get_tcb_info(&self, tcb_type: u8, fmspc: &str, version: u32) -> Result<Vec<u8>> {
        let tech = match tcb_type {
            0 => "sgx",
            1 => "tdx",
            _ => return Err(anyhow!("Invalid tcb_type: must be 0 (SGX) or 1 (TDX)")),
        };

        let url = format!(
            "{}/{}/certification/v{}/tcb?fmspc={}",
            self.base_url, tech, version, fmspc
        );

        let mut request = self.client.get(&url);

        if let Some(key) = &self.subscription_key {
            request = request.header("Ocp-Apim-Subscription-Key", key);
        }

        let response = request
            .send()
            .await
            .context("Failed to send TCB Info request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "TCB Info request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        // Get the TCB Info JSON body
        let tcb_info_json = response.bytes().await?.to_vec();

        Ok(tcb_info_json)
    }

    /// Get Enclave Identity (QE Identity for SGX or TDX)
    ///
    /// # Arguments
    /// * `version` - API version (should be 4 for v4 API)
    async fn get_enclave_identity(&self, version: u32) -> Result<Vec<u8>> {
        // For TDX Quote verification, we typically need the TDX QE Identity
        let url = format!(
            "{}/tdx/certification/v{}/qe/identity",
            self.base_url, version
        );

        let mut request = self.client.get(&url);

        if let Some(key) = &self.subscription_key {
            request = request.header("Ocp-Apim-Subscription-Key", key);
        }

        let response = request
            .send()
            .await
            .context("Failed to send QE Identity request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "QE Identity request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        let qe_identity_json = response.bytes().await?.to_vec();

        Ok(qe_identity_json)
    }

    /// Get certificate by CA ID (Processor or Platform CA)
    /// Returns tuple of (certificate_chain, crl)
    ///
    /// # Arguments
    /// * `ca_id` - CA identifier (Processor or Platform)
    /// Get certificate and CRL by CA ID (Root, Processor, or Platform CA)
    /// Returns tuple of (certificate, crl)
    ///
    /// # Arguments
    /// * `ca_id` - CA identifier (Root, Processor or Platform)
    async fn get_certificate_by_id(&self, ca_id: CA) -> Result<(Vec<u8>, Vec<u8>)> {
        match ca_id {
            CA::ROOT => {
                // For Root CA, fetch the certificate directly
                // Root CA doesn't have a CRL endpoint, so we return empty CRL
                let cert_url = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";

                let cert_response = self
                    .client
                    .get(cert_url)
                    .send()
                    .await
                    .context("Failed to fetch Root CA certificate")?;

                if !cert_response.status().is_success() {
                    return Err(anyhow!(
                        "Root CA certificate request failed with status {}: {}",
                        cert_response.status(),
                        cert_response.text().await.unwrap_or_default()
                    ));
                }

                let cert = cert_response.bytes().await?.to_vec();

                // Root CA doesn't have a CRL, return empty vector
                Ok((cert, Vec::new()))
            }
            CA::PROCESSOR | CA::PLATFORM => {
                let ca_str = match ca_id {
                    CA::PROCESSOR => "processor",
                    CA::PLATFORM => "platform",
                    _ => unreachable!(),
                };

                // Get the CRL for this CA
                let crl_url = format!(
                    "{}/sgx/certification/v4/pckcrl?ca={}&encoding=der",
                    self.base_url, ca_str
                );

                let mut crl_request = self.client.get(&crl_url);

                if let Some(key) = &self.subscription_key {
                    crl_request = crl_request.header("Ocp-Apim-Subscription-Key", key);
                }

                let crl_response = crl_request
                    .send()
                    .await
                    .context("Failed to send CRL request")?;

                if !crl_response.status().is_success() {
                    return Err(anyhow!(
                        "CRL request failed with status {}: {}",
                        crl_response.status(),
                        crl_response.text().await.unwrap_or_default()
                    ));
                }

                // Extract the certificate chain from the response header
                let cert_chain = crl_response
                    .headers()
                    .get("SGX-PCK-CRL-Issuer-Chain")
                    .ok_or_else(|| anyhow!("Missing SGX-PCK-CRL-Issuer-Chain header"))?
                    .to_str()
                    .context("Invalid certificate chain header")?;

                // URL decode the certificate chain
                let cert_chain = urlencoding::decode(cert_chain)
                    .context("Failed to URL decode certificate chain")?
                    .into_owned()
                    .into_bytes();

                let crl = crl_response.bytes().await?.to_vec();

                // The cert chain contains both Root CA and the intermediate CA (Processor/Platform)
                // We need to parse and extract just the requested CA certificate
                // The chain format is: <Intermediate CA Cert><Root CA Cert>
                let cert = extract_first_certificate(&cert_chain)
                    .context("Failed to extract CA certificate from chain")?;

                Ok((cert, crl))
            }
            _ => return Err(anyhow!("unssuported CA")),
        }
    }
}

/// Extract the first certificate from a PEM certificate chain
fn extract_first_certificate(pem_chain: &[u8]) -> Result<Vec<u8>> {
    let chain_str =
        std::str::from_utf8(pem_chain).context("Certificate chain is not valid UTF-8")?;

    // Find the first certificate in the chain
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = chain_str
        .find(begin_marker)
        .ok_or_else(|| anyhow!("No certificate found in chain"))?;

    let end = chain_str[start..]
        .find(end_marker)
        .ok_or_else(|| anyhow!("Malformed certificate in chain"))?;

    // Extract the first certificate including the markers
    let cert = &chain_str[start..start + end + end_marker.len()];

    Ok(cert.as_bytes().to_vec())
}

impl IntelPccs {
    /// Create a new IntelPccs instance with a subscription key
    /// Subscription keys are optional for v4 API but recommended for higher rate limits
    pub fn with_subscription_key(subscription_key: String) -> Self {
        Self {
            base_url: "https://api.trustedservices.intel.com".to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            subscription_key: Some(subscription_key),
        }
    }

    /// Set a custom base URL (useful for testing or using PCCS cache servers)
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    /// Get TCB Info with issuer certificate chain
    /// Returns tuple of (tcb_info_json, issuer_chain_pem)
    pub async fn get_tcb_info_with_chain(
        &self,
        tcb_type: u8,
        fmspc: &str,
        version: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let tech = match tcb_type {
            0 => "sgx",
            1 => "tdx",
            _ => return Err(anyhow!("Invalid tcb_type: must be 0 (SGX) or 1 (TDX)")),
        };

        let url = format!(
            "{}/{}/certification/v{}/tcb?fmspc={}",
            self.base_url, tech, version, fmspc
        );

        let mut request = self.client.get(&url);

        if let Some(key) = &self.subscription_key {
            request = request.header("Ocp-Apim-Subscription-Key", key);
        }

        let response = request
            .send()
            .await
            .context("Failed to send TCB Info request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "TCB Info request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        // Extract issuer chain from header
        let issuer_chain = response
            .headers()
            .get("TCB-Info-Issuer-Chain")
            .ok_or_else(|| anyhow!("Missing TCB-Info-Issuer-Chain header"))?
            .to_str()
            .context("Invalid issuer chain header")?
            .as_bytes()
            .to_vec();

        let tcb_info_json = response.bytes().await?.to_vec();

        Ok((tcb_info_json, issuer_chain))
    }

    /// Get Enclave Identity with issuer certificate chain
    /// Returns tuple of (identity_json, issuer_chain_pem)
    pub async fn get_enclave_identity_with_chain(
        &self,
        version: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let url = format!(
            "{}/tdx/certification/v{}/qe/identity",
            self.base_url, version
        );

        let mut request = self.client.get(&url);

        if let Some(key) = &self.subscription_key {
            request = request.header("Ocp-Apim-Subscription-Key", key);
        }

        let response = request
            .send()
            .await
            .context("Failed to send QE Identity request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "QE Identity request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        // Extract issuer chain from header
        let issuer_chain = response
            .headers()
            .get("SGX-Enclave-Identity-Issuer-Chain")
            .ok_or_else(|| anyhow!("Missing SGX-Enclave-Identity-Issuer-Chain header"))?
            .to_str()
            .context("Invalid issuer chain header")?;

        // URL decode the issuer chain
        let issuer_chain = urlencoding::decode(issuer_chain)
            .context("Failed to URL decode issuer chain")?
            .into_owned()
            .into_bytes();

        let identity_json = response.bytes().await?.to_vec();

        Ok((identity_json, issuer_chain))
    }
}
