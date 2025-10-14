//! Soldering API surface
//!
//! This module exposes a thin, feature-gated wrapper over the SP1-based
//! soldering core by delegating to the external `gsv-soldering-cli` binary.
//! The goals for this layer are:
//! - present stable function signatures that use our core types (`S`, `GarbledWire`)
//! - avoid linking the SP1 SDK directly into the verifier crate; the CLI is
//!   resolved from `GSV_SOLDERING_CLI`, `CARGO_BIN_EXE_gsv-soldering-cli`, a
//!   build-script-provisioned `GSV_SOLDERING_CLI_BUILT`, or the PATH at runtime
//! - provide ergonomic conversions and clear public outputs for downstream use
//!
//! The two entry points are:
//! - `prove_soldering`: produce a proof that a set of additional instances are
//!   correctly soldered to a base instance, and return the public parameters
//!   (deltas and commitments) alongside a proof handle.
//! - `verify_soldering`: verify the proof and return the public parameters
//!   bound by the proof for consumer use.

use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    process::{Command, Stdio},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{GarbledWire, S, circuit::CircuitInput};

/// SHA-256 commitment used for wire-label commitments.
pub type Sha256Commit = [u8; 32];

#[derive(Serialize)]
struct CliWiresInput {
    instances_wires: Vec<Vec<(u128, u128)>>,
    nonce: u128,
}

#[derive(Serialize, Deserialize)]
struct CliSolderedLabelsData {
    deltas: Vec<Vec<(u128, u128)>>,
    base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
    nonce: u128,
}

/// Public values emitted by the soldering proof.
///
/// These bind all additional instances to the base instance via per-wire
/// commitments and per-instance per-wire deltas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolderedLabels {
    /// For each additional instance, for each input wire, provide the pair of
    /// deltas that transform the base labels into the instance labels.
    /// Layout: `deltas[instance_idx][wire_idx] = (delta0, delta1)`.
    pub deltas: Vec<Vec<(S, S)>>,
    /// For each input wire of the base instance, commitment to both labels.
    /// The entry is ordered as `[commit(label0), commit(label1)]`.
    pub base_commitment: Vec<[Sha256Commit; 2]>,
    /// For each input wire of the base instance, commitment to both labels XORed with nonce.
    /// The entry is ordered as `[commit(label0 XOR nonce), commit(label1 XOR nonce)]`.
    pub base_nonce_commitment: Vec<[Sha256Commit; 2]>,
    /// Commitment per additional instance, binding all its input wires.
    pub commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
    /// Used for `base_nonce_commitment`
    pub nonce: S,
}

/// Error surface for soldering operations.
#[derive(thiserror::Error, Debug)]
pub enum SolderingError {
    #[error("input instances list must not be empty")]
    EmptyInstances,
    #[error("wire count mismatch: base has {base}, instance {instance_idx} has {got}")]
    WireCountMismatch {
        base: usize,
        instance_idx: usize,
        got: usize,
    },
    #[error("failed to encode soldering payload: {0}")]
    Encode(#[source] bincode::Error),
    #[error("failed to decode soldering payload: {0}")]
    Decode(#[source] bincode::Error),
    #[error("soldering CLI binary not found ({bin:?})")]
    CliNotFound { bin: OsString },
    #[error("failed to spawn soldering CLI ({bin:?}): {source}")]
    CliSpawn {
        bin: OsString,
        #[source]
        source: io::Error,
    },
    #[error("soldering CLI missing stdin handle")]
    CliNoStdin,
    #[error("failed to write to soldering CLI stdin: {0}")]
    CliWrite(#[source] io::Error),
    #[error("failed to wait for soldering CLI: {0}")]
    CliWait(#[source] io::Error),
    #[error("soldering CLI exited with status {status:?}: {stderr}")]
    CliExit { status: Option<i32>, stderr: String },
    #[error("soldering CLI output is not UTF-8: {0}")]
    CliUtf8(#[source] std::string::FromUtf8Error),
    #[error("soldering CLI output is not valid hex: {0}")]
    CliHex(#[source] hex::FromHexError),
    #[error("soldering CLI returned empty output")]
    CliEmpty,
}

/// Opaque proof handle returned by the external soldering CLI.
pub struct SolderingProof {
    payload: Vec<u8>,
}

impl core::fmt::Debug for SolderingProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SolderingProof")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Produce a soldering proof and its bound public parameters.
///
/// Input shape:
/// - `base`: the base/core instance input wires (each is a `GarbledWire` with two labels `S`)
/// - `additional`: the list of additional instances to be soldered; each must
///   contain exactly the same number of wires as `base`.
/// - `nonce`: public nonce from evaluator for second-preimage protection
///
/// Returns an opaque `SolderingProof` handle which must be passed to
/// `verify_soldering`. Use the return value of `verify_soldering` as the source
/// of truth for deltas and commitments.
pub fn prove_soldering(
    base: &[GarbledWire],
    additional: &[Vec<GarbledWire>],
    nonce: S,
) -> Result<SolderingProof, SolderingError> {
    let base_len = base.len();
    if additional.is_empty() {
        return Err(SolderingError::EmptyInstances);
    }
    for (idx, inst) in additional.iter().enumerate() {
        if inst.len() != base_len {
            return Err(SolderingError::WireCountMismatch {
                base: base_len,
                instance_idx: idx,
                got: inst.len(),
            });
        }
    }

    // Build soldering-core input: Vec<InstancesWires>, where a wire is (u128,u128)
    let to_wire = |w: &GarbledWire| (w.label0.to_u128(), w.label1.to_u128());

    let mut instances = Vec::with_capacity(1 + additional.len());

    instances.push(base.iter().map(to_wire).collect());

    for inst in additional {
        instances.push(inst.iter().map(to_wire).collect());
    }

    let input = CliWiresInput {
        instances_wires: instances,
        nonce: nonce.to_u128(),
    };

    let request = bincode::serialize(&input).map_err(SolderingError::Encode)?;
    let response = run_cli("prove", &request)?;

    Ok(SolderingProof { payload: response })
}

/// Verify a soldering proof and extract its bound public parameters.
///
/// On success, the returned `SolderedLabels` contains:
/// - per-instance, per-wire deltas in `S` form
/// - base instance per-wire commitments to both labels
/// - base instance per-wire commitments with nonce
/// - per-instance commitments
pub fn verify_soldering(proof: SolderingProof) -> Result<SolderedLabels, SolderingError> {
    let SolderingProof { payload } = proof;
    let response = run_cli("verify", &payload)?;
    let data: CliSolderedLabelsData =
        bincode::deserialize(&response).map_err(SolderingError::Decode)?;
    Ok(convert_public_values(data))
}

fn convert_public_values(data: CliSolderedLabelsData) -> SolderedLabels {
    let deltas = data
        .deltas
        .into_iter()
        .map(|per_wire| {
            per_wire
                .into_iter()
                .map(|(d0, d1)| (S::from_u128(d0), S::from_u128(d1)))
                .collect()
        })
        .collect();

    let base_commitment = data
        .base_commitment
        .into_iter()
        .map(|(c0, c1)| [c0, c1])
        .collect();

    let base_nonce_commitment = data
        .base_nonce_commitment
        .into_iter()
        .map(|(c0, c1)| [c0, c1])
        .collect();

    SolderedLabels {
        deltas,
        base_commitment,
        base_nonce_commitment,
        commitments: data.commitments,
        nonce: S::from_u128(data.nonce),
    }
}

fn cli_binary() -> OsString {
    if let Some(explicit) = env::var_os("GSV_SOLDERING_CLI") {
        return explicit;
    }
    if let Some(cargo) = env::var_os("CARGO_BIN_EXE_gsv-soldering-cli") {
        return cargo;
    }
    if let Some(built) = env::var_os("GSV_SOLDERING_CLI_BUILT") {
        return built;
    }
    OsString::from("gsv-soldering-cli")
}

fn run_cli(subcommand: &str, payload: &[u8]) -> Result<Vec<u8>, SolderingError> {
    let bin = cli_binary();
    let mut command = Command::new(&bin);
    command
        .arg(subcommand)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    let started = Instant::now();
    let mut child = command.spawn().map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => SolderingError::CliNotFound { bin: bin.clone() },
        _ => SolderingError::CliSpawn {
            bin: bin.clone(),
            source,
        },
    })?;

    {
        let stdin = child.stdin.as_mut().ok_or(SolderingError::CliNoStdin)?;
        let hex_payload = hex::encode(payload);
        stdin
            .write_all(hex_payload.as_bytes())
            .map_err(SolderingError::CliWrite)?;
    }

    let output = child.wait_with_output().map_err(SolderingError::CliWait)?;
    let elapsed = started.elapsed();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(SolderingError::CliExit {
            status: output.status.code(),
            stderr,
        });
    }

    let stdout = String::from_utf8(output.stdout).map_err(SolderingError::CliUtf8)?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !stderr.trim().is_empty() {
        info!(?bin, subcommand, stderr = %stderr.trim(), "soldering CLI stderr");
    }

    let payload_hex = stdout.split_whitespace().collect::<String>();
    if payload_hex.is_empty() {
        return Err(SolderingError::CliEmpty);
    }
    let preview = if payload_hex.len() > 64 {
        format!("{}…", &payload_hex[..64])
    } else {
        payload_hex.clone()
    };
    info!(?bin, subcommand, duration = ?elapsed, payload_len = payload_hex.len(), payload_preview = %preview, "soldering CLI completed");
    let bytes = hex::decode(payload_hex).map_err(SolderingError::CliHex)?;
    Ok(bytes)
}

pub trait SolderInput: CircuitInput {
    fn solder(&self, deltas: &[(S, S)]) -> Self;
}

//impl SolderInput for EvaluatedWire {
//    fn solder(&self, deltas: &[(S, S)]) -> Self {
//        let delta = if self.value { deltas[0] } else { deltas[1] };
//
//        EvaluatedWire {
//            active_label: self.active_label.bitxor(delta),
//            value: self.value,
//        }
//    }
//}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use test_log::test;

    use super::*;
    use crate::Delta;

    // This is a slow end-to-end check that exercises the SP1 flow.
    // It is ignored by default and only runs when the `sp1-soldering` feature
    // is enabled and the environment has the required artifacts.
    #[test]
    #[ignore = "slow zkSNARK generation"]
    fn round_trip_prove_verify_with_nonce() {
        use sha2::Digest;

        let mut rng = rand::thread_rng();
        let delta = Delta::generate(&mut rng);
        let nonce = S::from_u128(rng.r#gen());

        let input_wires_count = 64usize;
        let soldered_instances = 3usize;

        let base: Vec<GarbledWire> = (0..input_wires_count)
            .map(|_| GarbledWire::random(&mut rng, &delta))
            .collect();

        let additional: Vec<Vec<GarbledWire>> = (0..soldered_instances)
            .map(|_| {
                (0..input_wires_count)
                    .map(|_| GarbledWire::random(&mut rng, &delta))
                    .collect()
            })
            .collect();

        let proof = prove_soldering(&base, &additional, nonce).expect("prove");
        let out = verify_soldering(proof).expect("verify");

        // Verify nonce commitments are present
        assert_eq!(out.base_nonce_commitment.len(), input_wires_count);

        // Verify nonce commitments are correct
        for (wire_idx, (base_wire, nonce_commit)) in base
            .iter()
            .zip(out.base_nonce_commitment.iter())
            .enumerate()
        {
            // Compute expected commitments
            let expected_commit0 =
                sha2::Sha256::digest((base_wire.label0 ^ &nonce).to_u128().to_be_bytes());
            let expected_commit1 =
                sha2::Sha256::digest((base_wire.label1 ^ &nonce).to_u128().to_be_bytes());

            assert_eq!(
                nonce_commit[0].as_slice(),
                expected_commit0.as_slice(),
                "wire {wire_idx}: label0 nonce commitment mismatch",
            );
            assert_eq!(
                nonce_commit[1].as_slice(),
                expected_commit1.as_slice(),
                "wire {wire_idx}: label1 nonce commitment mismatch",
            );
        }
    }

    #[test]
    #[ignore = "slow zkSNARK generation"]
    fn round_trip_prove_verify() {
        use sha2::Digest;

        let mut rng = rand::thread_rng();
        let delta = Delta::generate(&mut rng);

        let input_wires_count = 64usize;
        let soldered_instances = 3usize;

        let base: Vec<GarbledWire> = (0..input_wires_count)
            .map(|_| GarbledWire::random(&mut rng, &delta))
            .collect();

        let additional: Vec<Vec<GarbledWire>> = (0..soldered_instances)
            .map(|_| {
                (0..input_wires_count)
                    .map(|_| GarbledWire::random(&mut rng, &delta))
                    .collect()
            })
            .collect();

        // Use a dummy nonce (could be zero or random)
        let nonce = S::from_u128(rng.r#gen());

        let proof = prove_soldering(&base, &additional, nonce).expect("prove");
        let out = verify_soldering(proof).expect("verify");

        assert_eq!(out.deltas.len(), soldered_instances);
        assert_eq!(out.base_commitment.len(), input_wires_count);
        assert_eq!(out.commitments.len(), soldered_instances);

        // Helper to select bit from a GarbledWire
        let pick = |gw: &GarbledWire, bit: bool| -> S { if bit { gw.label1 } else { gw.label0 } };

        // For every wire, for both bits, verify reconstruction from any known instance
        #[allow(clippy::needless_range_loop)]
        for wire_id in 0..input_wires_count {
            // Helper to get delta for bit b at wire w for instance idx
            let delta_for = |inst_idx: usize, bit: bool| -> S {
                let (d0, d1) = out.deltas[inst_idx][wire_id];
                if bit { d1 } else { d0 }
            };

            for bit in [false, true] {
                // 1) From base to all instances
                let base_label = pick(&base[wire_id], bit);

                for j in 0..soldered_instances {
                    let expected = pick(&additional[j][wire_id], bit);
                    let got = base_label ^ &delta_for(j, bit);
                    assert_eq!(
                        got, expected,
                        "wire {wire_id}, bit {bit}: reconstruct inst {j} from base"
                    );
                }

                // Verify base commitment for this bit
                let digest = sha2::Sha256::digest(base_label.to_u128().to_be_bytes());
                let commit: [u8; 32] = digest.into();
                let idx = if bit { 1 } else { 0 };
                assert_eq!(
                    out.base_commitment[wire_id][idx], commit,
                    "wire {wire_id}, bit {bit}: base commitment"
                );

                // 2) From each instance (one by one) to base and then to all
                for k in 0..soldered_instances {
                    let known = pick(&additional[k][wire_id], bit);
                    let base_rec = known ^ &delta_for(k, bit);
                    let base_expected = base_label;
                    assert_eq!(
                        base_rec, base_expected,
                        "wire {wire_id}, bit {bit}: recover base from inst {k}"
                    );

                    for j in 0..soldered_instances {
                        let got = base_rec ^ &delta_for(j, bit);
                        let expected = pick(&additional[j][wire_id], bit);
                        assert_eq!(
                            got, expected,
                            "wire {wire_id}, bit {bit}: reconstruct inst {j} from inst {k}"
                        );
                    }
                }
            }
        }
    }
}
