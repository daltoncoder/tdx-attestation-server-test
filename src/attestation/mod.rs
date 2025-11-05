pub mod pccs;
pub mod tdx_types;

use anyhow::{Result, anyhow, bail};
use az_tdx_vtpm::{hcl::HclReport, imds, tdx, vtpm};
use coco_provider::{coco::CocoDeviceType, get_coco_provider};
use dcap_rs::{
    types::{
        collaterals::IntelCollateral,
        quotes::{QeReportCertData, version_4::QuoteV4},
    },
    utils::{
        cert::{get_x509_issuer_cn, parse_certchain, parse_pem},
        quotes::version_4::verify_quote_dcapv4,
    },
};
use x509_parser::{
    der_parser::{
        Oid,
        asn1_rs::{OctetString, Sequence, oid},
    },
    prelude::{FromDer as _, X509Certificate},
};

use crate::{
    attestation::{
        pccs::{IntelPccs, PccsProvider},
        tdx_types::HclVarData,
    },
    req_res::{AttestationEvalEvidenceResponse, AttestationGetEvidenceResponse},
};

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum CA {
    ROOT,
    PROCESSOR,
    PLATFORM,
    SIGNING,
    __Invalid,
}

pub struct AttestationAgent {
    provider: CocoDeviceType,
    pccs: IntelPccs,
}

impl AttestationAgent {
    pub fn new() -> Result<Self> {
        let provider = get_coco_provider()?;
        Ok(Self {
            provider: provider.device_type,
            pccs: IntelPccs::new(),
        })
    }

    pub fn get_attestation_evidence(&self) -> Result<AttestationGetEvidenceResponse> {
        match self.provider {
            // Azure and other TDX cloud providers use TPM
            CocoDeviceType::Tpm => self.get_attestation_evidence_tpm(),
            _ => bail!("Unsupported TDX platform"),
        }
    }

    fn get_attestation_evidence_tpm(&self) -> Result<AttestationGetEvidenceResponse> {
        // todo this will be included in the quote, placeholding this for now we probably want our public key or a nonce here instead
        let report_data = [1u8; 32];

        // Get Unsigned td report
        let hcl_report_bytes = vtpm::get_report_with_report_data(&report_data)?;
        let hcl_report = HclReport::new(hcl_report_bytes.clone())?;

        // get the unsigned td report
        let unsigned_td_report: tdx::TdReport = hcl_report.try_into()?;

        // send td report to the imds to be signed
        let signed_td_report_bytes = imds::get_td_quote(&unsigned_td_report).unwrap();

        // let quote = QuoteV4::from_bytes(&signed_td_report_bytes);
        Ok(AttestationGetEvidenceResponse {
            hcl_report: hcl_report_bytes,
            quote: signed_td_report_bytes,
        })
    }

    pub async fn verify_attestation_report(
        &self,
        quote: QuoteV4,
    ) -> Result<AttestationEvalEvidenceResponse> {
        // 1. Get Root CA and root ca crl from PCCS
        let RootCA {
            root_ca,
            root_ca_crl,
        } = self.get_root_ca();

        if root_ca.is_empty() || root_ca_crl.is_empty() {
            return Err(anyhow!("Root CA or CRL is empty"));
        }
        // 2. get fmspc and pck_type from the quote cert
        let (fmspc, pck_type) = get_pck_fmspc_and_issuer(&quote);

        // 3. get TCB info from PCCS

        // tcb_type: 0: SGX, 1: TDX
        // version: TDX uses TcbInfoV3
        let tcb_info = self.pccs.get_tcb_info(1, &fmspc, 3).await?;

        // 4. Get Enclave Identity from PCCS
        let quote_version = quote.header.version;
        let qe_identity = self.pccs.get_enclave_identity(quote_version as u32).await?;

        let (signing_ca, _) = self.pccs.get_certificate_by_id(CA::SIGNING).await?;

        if signing_ca.is_empty() {
            return Err(anyhow!("Signing CA is empty".to_string()));
        }

        let (_, pck_crl) = self.pccs.get_certificate_by_id(pck_type).await?;
        if pck_crl.is_empty() {
            return Err(anyhow!("PCK CRL is empty".to_string()));
        }

        // Pass all the collaterals into a struct for verifying the quote.
        let current_time = chrono::Utc::now().timestamp() as u64;
        let mut collaterals = IntelCollateral::new();

        collaterals.set_tcbinfo_bytes(&tcb_info);
        collaterals.set_qeidentity_bytes(&qe_identity);
        collaterals.set_intel_root_ca_der(&root_ca);
        collaterals.set_sgx_tcb_signing_der(&signing_ca);
        collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl);

        match pck_type {
            CA::PLATFORM => {
                collaterals.set_sgx_platform_crl_der(&pck_crl);
            }
            CA::PROCESSOR => {
                collaterals.set_sgx_processor_crl_der(&pck_crl);
            }
            _ => {
                return Err(anyhow!("Unknown PCK Type".to_string()));
            }
        }

        match std::panic::catch_unwind(|| verify_quote_dcapv4(&quote, &collaterals, current_time)) {
            Ok(_) => Ok(AttestationEvalEvidenceResponse {}), // todo actually respond with something
            Err(e) => Err(anyhow!("DCAP Error: {:?}", e)),
        }
    }

    fn get_root_ca(&self) -> RootCA {
        todo!()
    }
}

pub fn get_pck_fmspc_and_issuer(quote: &QuoteV4) -> (String, CA) {
    let raw_cert_data = QeReportCertData::from_bytes(&quote.signature.qe_cert_data.cert_data);

    let pem = parse_pem(&raw_cert_data.qe_cert_data.cert_data).expect("Failed to parse cert data");
    // Cert Chain:
    // [0]: pck ->
    // [1]: pck ca ->
    // [2]: root ca
    let cert_chain = parse_certchain(&pem);
    let pck = &cert_chain[0];

    let pck_issuer = get_x509_issuer_cn(pck);

    let pck_ca = match pck_issuer.as_str() {
        "Intel SGX PCK Platform CA" => CA::PLATFORM,
        "Intel SGX PCK Processor CA" => CA::PROCESSOR,
        _ => panic!("Unknown PCK Issuer"),
    };

    let fmspc_slice = extract_fmspc_from_extension(pck);
    let fmspc = hex::encode(fmspc_slice);
    (fmspc, pck_ca)
}

pub fn extract_fmspc_from_extension<'a>(cert: &'a X509Certificate<'a>) -> [u8; 6] {
    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840.113741.1.13.1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    let mut fmspc = [0; 6];

    let mut i = sgx_extensions.content.as_ref();

    while i.len() > 0 {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
                break;
            }
            _ => continue,
        }
    }

    fmspc
}

pub struct RootCA {
    pub root_ca: Vec<u8>,
    pub root_ca_crl: Vec<u8>,
}

pub fn decode_var_data(var_data: &[u8]) -> HclVarData {
    // Convert bytes to UTF-8 string
    let json_str = std::str::from_utf8(var_data).unwrap();

    // Parse JSON into struct
    let hcl_data: HclVarData = serde_json::from_str(json_str).unwrap();

    hcl_data
}
