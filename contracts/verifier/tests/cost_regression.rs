//! CI regression guard for `verify_proof`'s instruction cost — see
//! zksoroban#74 and `docs/performance.md`'s "CI Cost Regression Check"
//! section for the full write-up of why this measures things the way it
//! does.
//!
//! This registers the *compiled* `contracts/verifier` wasm (not the
//! native Rust contract type `contracts/verifier/src/tests.rs` uses) via
//! `Env::register(wasm_bytes, ..)`, so the reported cost includes real
//! wasm-interpretation overhead, not just the host-function costs a
//! native-Rust test registration would measure. Requires the wasm to
//! already be built:
//!
//! ```sh
//! cargo build --manifest-path contracts/verifier/Cargo.toml --target wasm32v1-none --release
//! cargo test --manifest-path contracts/verifier/Cargo.toml --test cost_regression
//! ```
//!
//! `make verifier-cost-check` runs both steps together;
//! `make update-verifier-cost-baseline` does the same but rewrites
//! `baseline-cost.json` with the freshly-measured count instead of
//! comparing against it.

use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env};
use zksoroban_verifier::{VerifierContractClient, VerifyingKey};

// Same known-good poseidon_preimage fixture as
// contracts/verifier/src/tests.rs's poseidon_vk()/VALID_PROOF_* (and
// sdk/test/fixtures.ts's TypeScript copy) — duplicated here because an
// integration test can't reach into that module's private, cfg(test)-gated
// contents.
const VK_ALPHA_G1: [u8; 64] = [
    37, 174, 162, 190, 147, 137, 161, 46, 208, 40, 205, 226, 35, 65, 40, 44, 27, 28, 154, 20, 14,
    58, 206, 243, 150, 37, 97, 176, 235, 29, 70, 139, 31, 142, 73, 125, 220, 208, 55, 78, 173, 173,
    137, 157, 225, 191, 157, 158, 114, 100, 108, 79, 210, 25, 48, 31, 197, 192, 156, 46, 171, 152,
    229, 95,
];

const VK_BETA_G2: [u8; 128] = [
    16, 192, 41, 89, 225, 138, 98, 99, 126, 10, 17, 115, 189, 205, 208, 100, 144, 178, 104, 213,
    204, 186, 176, 7, 121, 123, 72, 37, 204, 63, 176, 252, 3, 140, 21, 18, 253, 163, 204, 42, 212,
    230, 81, 138, 188, 135, 93, 67, 90, 44, 33, 135, 25, 165, 93, 183, 212, 179, 30, 8, 8, 211,
    163, 195, 41, 211, 246, 214, 39, 241, 146, 1, 159, 19, 227, 209, 71, 86, 208, 245, 123, 226,
    249, 207, 175, 129, 207, 140, 152, 64, 207, 168, 184, 182, 65, 48, 36, 103, 94, 218, 64, 127,
    63, 69, 90, 209, 120, 139, 128, 240, 117, 187, 108, 187, 250, 62, 162, 205, 134, 52, 210, 194,
    91, 79, 139, 106, 240, 246,
];

const VK_GAMMA_G2: [u8; 128] = [
    25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73, 51, 53,
    169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194, 24, 0, 222, 239, 18, 31, 30, 118, 66, 106,
    0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92, 217, 146, 246,
    237, 9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149, 188, 75, 49, 51,
    112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91, 18, 200, 94, 165, 219, 140, 109, 235,
    74, 171, 113, 128, 141, 203, 64, 143, 227, 209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1,
    102, 250, 125, 170,
];

const VK_DELTA_G2: [u8; 128] = [
    30, 191, 14, 99, 80, 96, 169, 248, 115, 42, 4, 232, 241, 172, 231, 11, 209, 255, 181, 66, 226,
    81, 114, 203, 9, 17, 245, 14, 21, 47, 108, 131, 15, 248, 194, 120, 215, 200, 221, 17, 228, 29,
    179, 208, 106, 116, 75, 141, 105, 71, 58, 219, 87, 21, 148, 114, 143, 19, 198, 219, 143, 144,
    108, 56, 15, 37, 69, 95, 78, 156, 17, 210, 113, 53, 223, 118, 131, 56, 26, 36, 122, 22, 151,
    118, 241, 78, 236, 218, 93, 11, 9, 244, 103, 165, 60, 68, 32, 134, 231, 54, 45, 60, 153, 212,
    159, 226, 92, 108, 13, 26, 210, 168, 196, 162, 240, 251, 27, 28, 214, 57, 40, 193, 243, 211,
    56, 95, 104, 255,
];

const VK_IC0_G1: [u8; 64] = [
    26, 87, 61, 103, 214, 216, 157, 137, 212, 69, 128, 237, 186, 96, 209, 103, 5, 192, 250, 53,
    143, 250, 58, 172, 43, 103, 8, 35, 102, 252, 118, 220, 34, 5, 29, 156, 107, 195, 217, 202, 19,
    76, 0, 7, 57, 7, 69, 159, 147, 101, 66, 84, 42, 223, 15, 201, 229, 15, 76, 155, 15, 63, 153,
    23,
];

const VK_IC1_G1: [u8; 64] = [
    14, 175, 26, 53, 220, 82, 18, 65, 43, 24, 73, 28, 169, 83, 160, 86, 59, 171, 175, 121, 78, 151,
    209, 220, 243, 234, 179, 65, 226, 63, 53, 247, 14, 78, 72, 228, 67, 167, 115, 92, 178, 191, 32,
    181, 102, 213, 116, 121, 173, 179, 91, 210, 78, 87, 214, 86, 119, 251, 37, 166, 188, 55, 49,
    89,
];

const VALID_PROOF_A: [u8; 64] = [
    28, 159, 72, 150, 222, 218, 126, 226, 53, 93, 4, 80, 73, 92, 40, 120, 36, 194, 215, 167, 39,
    53, 38, 203, 78, 55, 154, 43, 183, 51, 27, 239, 39, 116, 225, 204, 223, 113, 45, 75, 145, 63,
    162, 251, 115, 169, 233, 211, 196, 17, 50, 95, 10, 96, 100, 87, 103, 45, 222, 46, 22, 79, 236,
    207,
];

const VALID_PROOF_B: [u8; 128] = [
    1, 42, 5, 66, 163, 235, 37, 249, 221, 59, 28, 26, 28, 141, 222, 136, 44, 125, 57, 205, 174,
    171, 120, 158, 215, 5, 37, 152, 128, 47, 109, 179, 10, 195, 151, 7, 203, 209, 91, 29, 216, 105,
    99, 216, 134, 57, 249, 38, 63, 28, 61, 16, 237, 176, 106, 59, 106, 127, 132, 150, 173, 249, 24,
    39, 37, 42, 7, 245, 29, 242, 177, 182, 170, 101, 22, 47, 23, 147, 59, 250, 162, 36, 95, 66,
    122, 2, 75, 26, 188, 118, 101, 74, 47, 193, 255, 168, 11, 116, 62, 79, 44, 18, 181, 195, 110,
    255, 73, 31, 99, 67, 197, 43, 29, 151, 157, 210, 34, 247, 134, 38, 31, 23, 4, 3, 49, 77, 27,
    13,
];

const VALID_PROOF_C: [u8; 64] = [
    17, 201, 219, 26, 68, 41, 61, 217, 55, 131, 157, 11, 39, 31, 149, 251, 231, 172, 120, 223, 35,
    49, 86, 11, 238, 214, 162, 152, 3, 170, 201, 25, 12, 55, 128, 235, 89, 16, 108, 55, 145, 211,
    153, 105, 252, 163, 82, 244, 31, 20, 102, 144, 205, 165, 13, 28, 60, 128, 197, 222, 246, 69, 1,
    222,
];

const VALID_PUBLIC_INPUT: [u8; 32] = [
    41, 23, 97, 0, 234, 169, 98, 189, 193, 254, 108, 101, 77, 106, 60, 19, 14, 150, 164, 209, 22,
    139, 51, 132, 139, 137, 125, 197, 2, 130, 1, 51,
];

const WASM_PATH_HINT: &str =
    "contracts/verifier/target/wasm32v1-none/release/zksoroban_verifier.wasm";

/// The 32-byte, all-`0xff`-suffixed public input `read_expiry_ledger`
/// decodes as `expiry_ledger = u32::MAX` — i.e. "never expires" for any
/// ledger sequence this test could plausibly set. See
/// `contracts/verifier/src/lib.rs`'s `read_expiry_ledger`.
fn never_expires(env: &Env) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[28..].copy_from_slice(&u32::MAX.to_be_bytes());
    BytesN::from_array(env, &arr)
}

fn poseidon_vk(env: &Env) -> VerifyingKey {
    VerifyingKey {
        alpha: BytesN::from_array(env, &VK_ALPHA_G1),
        beta: BytesN::from_array(env, &VK_BETA_G2),
        gamma: BytesN::from_array(env, &VK_GAMMA_G2),
        delta: BytesN::from_array(env, &VK_DELTA_G2),
        ic: vec![
            env,
            BytesN::from_array(env, &VK_IC0_G1),
            BytesN::from_array(env, &VK_IC1_G1),
        ],
    }
}

fn built_wasm() -> std::vec::Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("contracts/verifier is two directories below the repo root");
    let wasm_path = repo_root.join(WASM_PATH_HINT);

    std::fs::read(&wasm_path).unwrap_or_else(|err| {
        panic!(
            "could not read {} ({err}) -- build it first:\n  \
             cargo build --manifest-path contracts/verifier/Cargo.toml --target wasm32v1-none --release",
            wasm_path.display()
        )
    })
}

struct Baseline {
    instructions: u64,
}

fn baseline_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("baseline-cost.json")
}

fn read_baseline() -> Baseline {
    let path = baseline_path();
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {} ({err})", path.display()));
    let json: serde_json::Value = serde_json::from_str(&contents)
        .unwrap_or_else(|err| panic!("{} is not valid JSON ({err})", path.display()));
    let instructions = json
        .get("instructions")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "{} is missing an integer \"instructions\" field",
                path.display()
            )
        });
    Baseline { instructions }
}

fn write_baseline(instructions: u64) {
    let path = baseline_path();
    let json = serde_json::json!({
        "instructions": instructions,
        "description": "CPU instructions verify_proof costs against the poseidon_preimage fixture in contracts/verifier/tests/cost_regression.rs, run through the real compiled wasm. Update via `make update-verifier-cost-baseline` -- see docs/performance.md.",
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap() + "\n")
        .unwrap_or_else(|err| panic!("could not write {} ({err})", path.display()));
}

/// Ten percent over baseline is a regression per zksoroban#74's
/// acceptance criteria. Anything at or under that is fine, including a
/// genuine improvement -- this test only ever fails upward.
const MAX_REGRESSION_FRACTION: f64 = 0.10;

#[test]
fn verify_proof_instruction_cost_within_baseline() {
    let wasm = built_wasm();

    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|li| li.sequence_number = 100);

    let admin = Address::generate(&env);
    let vk = poseidon_vk(&env);
    let contract_id = env.register(wasm.as_slice(), (admin, 1_000_000u32, 100u32, vk));
    let client = VerifierContractClient::new(&env, &contract_id);
    let caller = Address::generate(&env);

    let public_inputs = vec![
        &env,
        BytesN::from_array(&env, &VALID_PUBLIC_INPUT),
        never_expires(&env),
    ];

    env.cost_estimate().budget().reset_unlimited();
    let verified = client.verify_proof(
        &caller,
        &Bytes::from_array(&env, &VALID_PROOF_A),
        &Bytes::from_array(&env, &VALID_PROOF_B),
        &Bytes::from_array(&env, &VALID_PROOF_C),
        &public_inputs,
    );
    assert!(
        verified,
        "the fixture proof must actually verify, or this measures a rejection path instead of the real one"
    );

    let actual = env.cost_estimate().budget().cpu_instruction_cost();

    if std::env::var_os("UPDATE_COST_BASELINE").is_some() {
        write_baseline(actual);
        std::println!(
            "wrote {} instructions to {}",
            actual,
            baseline_path().display()
        );
        return;
    }

    let baseline = read_baseline();
    let max_allowed = (baseline.instructions as f64 * (1.0 + MAX_REGRESSION_FRACTION)) as u64;
    let delta = actual as i64 - baseline.instructions as i64;
    let delta_pct = delta as f64 / baseline.instructions as f64 * 100.0;

    assert!(
        actual <= max_allowed,
        "verify_proof instruction cost regressed by more than {:.0}%:\n  \
         baseline:    {} instructions\n  \
         actual:      {} instructions\n  \
         delta:       {:+} instructions ({:+.1}%)\n  \
         max allowed: {} instructions (baseline + {:.0}%)\n\n\
         If this regression is expected (e.g. a deliberate tradeoff), update the \
         baseline with `make update-verifier-cost-baseline` and explain why in the PR.",
        MAX_REGRESSION_FRACTION * 100.0,
        baseline.instructions,
        actual,
        delta,
        delta_pct,
        max_allowed,
        MAX_REGRESSION_FRACTION * 100.0,
    );
}
