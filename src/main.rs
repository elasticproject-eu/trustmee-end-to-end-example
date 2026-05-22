use std::{collections::HashMap, path::PathBuf};

use trustmee_attester::trustmee_coco_client::{CocoClient, CocoBuildWithCollateralOptions};
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

const TRUSTED_COMPONENTS: &[(&str, &str)] = &[
    (
        "5a36532545d5a9166a68facf53bf58a459957e34bbeb3465104df166df5f290c",
        "docker.io/pss1998/tdx-verifier-component:1.0.0",
    ),
    (
        "877bed7fcbfd47a91ecfc0b17a5cb818d40bcdb155be764c63f29bdbb3dc224c",
        "docker.io/pss1998/snp-verifier-component:1.0.0",
    ),
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Obtain attestation evidence from the CoCo Attestation Agent ────

    let built = CocoClient::builder()
        .build()?
        .build_trustmee_json_cmw_coco_with_collateral(
            CocoBuildWithCollateralOptions::builder()
                .component_oci_url("oci://docker.io/pss1998/tdx-verifier-component:1.0.0")
                .tdx_collateral(),
        )
        .await?;

    println!("component id : {}", built.component_id);

    // ── 2. Verify ─────────────────────────────────────────────────────────

    let verifier = WasmVerificationComponent::new()?;

    let options = VerifyOptions::builder()
        .cache_dir(PathBuf::from("/var/cache/trustmee/wasm"))
        .component_repository_hint("docker.io/pss1998")
        .build();

    let claims = verifier.verify_cmw_bytes(
        &built.cmw_json_bytes,
        None, // expected_report_data
        None, // expected_init_data_hash
        &options,
    )?;

    // ── 3. Trust gate — check the component hash, not tee_type ───────────

    let trusted: HashMap<&str, &str> = TRUSTED_COMPONENTS.iter().copied().collect();

    let component_hash = claims["verifier_component_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing verifier_component_sha256"))?;

    let component_label = trusted
        .get(component_hash)
        .ok_or_else(|| anyhow::anyhow!("untrusted verifier component: sha256:{component_hash}"))?;

    println!("verified by  : {component_label}");

    // ── 4. Read claims ────────────────────────────────────────────────────

    println!("\n{}", serde_json::to_string_pretty(&claims["claims"])?);

    Ok(())
}
