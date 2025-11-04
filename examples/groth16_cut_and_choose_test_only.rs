//! Test-only cut-and-choose flow that mirrors the structure of
//! `examples/groth16_cut_and_choose.rs`, but replaces heavy operations
//! with lightweight `*_test_only` methods or placeholders.
use std::{path::PathBuf, thread};

use crossbeam::channel;
use garbled_snark_verifier::{
    CommitPhaseOne, CommitPhaseTwo, S,
    groth16_cut_and_choose::{self as ccn, EvaluatorCaseInput},
    hashers::Sha256LabelCommitHasher as ExampleHasher,
};
use tracing::info;

// Configuration constants for logging/demo only
const OUT_DIR: &str = "target/cut_and_choose_test_only";

/// Messages emitted by the Garbler during Setup (test-only).
enum SetupBroadcast {
    Commit1(Vec<CommitPhaseOne<ExampleHasher>>),
    Commit2(Vec<CommitPhaseTwo<ExampleHasher>>),
    OpenSeeds(Vec<(usize, ccn::Seed)>),
    SolderingProof(Box<garbled_snark_verifier::sp1_soldering::SolderingProof>),
    #[allow(dead_code)]
    BaseInput(Box<EvaluatorCaseInput>),
}

/// Messages emitted by the Evaluator during Setup (test-only).
enum SetupResponse {
    Commit2Nonce(S),
    FinalizeChallenge(Vec<usize>),
}

fn main() {
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }

    garbled_snark_verifier::init_tracing();

    // Use a mocked config (dummy VK) with moderate sizes to avoid heavy work
    let cfg = ccn::mock_config();
    let out_dir: PathBuf = OUT_DIR.into();

    info!(
        total = cfg.total(),
        finalize = cfg.to_finalize(),
        "Starting test-only cut-and-choose",
    );

    let (g2e_tx, g2e_rx) = channel::unbounded::<SetupBroadcast>();
    let (e2g_tx, e2g_rx) = channel::unbounded::<SetupResponse>();

    let g_cfg = cfg.clone();
    let e_cfg = cfg;
    let garbler = thread::spawn(move || run_garbler_test_only(g_cfg, g2e_tx, e2g_rx));
    let evaluator = thread::spawn(move || run_evaluator_test_only(e_cfg, out_dir, g2e_rx, e2g_tx));

    garbler.join().unwrap();
    evaluator.join().unwrap();
}

fn run_garbler_test_only(
    cfg: ccn::Config,
    g2e_tx: channel::Sender<SetupBroadcast>,
    e2g_rx: channel::Receiver<SetupResponse>,
) {
    let mut g = ccn::Garbler::create_test_only(cfg.clone());

    // Step 1.2 — Garbler publishes Commit₁ for every instance (mocked).
    g2e_tx
        .send(SetupBroadcast::Commit1(
            g.commit_phase_one::<ExampleHasher>(),
        ))
        .expect("send commits");

    // Step 1.3 — Evaluator samples a nonce that will harden input label commits.
    let SetupResponse::Commit2Nonce(_nonce) = e2g_rx.recv().expect("recv nonce") else {
        panic!("unexpected message; expected nonce")
    };

    // Use a fixed nonce to keep test-only flows deterministic (no heavy checks depend on it)
    let fixed_nonce = S::from_u128(0);

    // Step 1.4 — Garbler republishes input commitments blended with the nonce (mocked).
    g2e_tx
        .send(SetupBroadcast::Commit2(
            g.commit_phase_two::<ExampleHasher>(fixed_nonce),
        ))
        .expect("send commit2");

    // Step 2 — Evaluator challenges the Garbler with the finalize set (indexes only).
    let SetupResponse::FinalizeChallenge(finalize_indexes) =
        e2g_rx.recv().expect("recv finalize indexes")
    else {
        panic!("unexpected message; expected challenge")
    };

    // Mock open/close split without ciphertexts or threads
    let open_commit = g.open_commit_without_ciphertexts(finalize_indexes);

    // Step 3 — seeds for all challenge instances (open set).
    g2e_tx
        .send(SetupBroadcast::OpenSeeds(open_commit.open))
        .expect("send open seeds");

    // Step 4 — send a dummy soldering proof (no heavy proving)
    let proof = g.do_soldering_test_only();
    //let rproof = g.do_soldering();
    //assert_eq!(proof, rproof);

    g2e_tx
        .send(SetupBroadcast::SolderingProof(Box::new(proof)))
        .expect("send soldering proof");
}

fn run_evaluator_test_only(
    cfg: ccn::Config,
    out_dir: PathBuf,
    g2e_rx: channel::Receiver<SetupBroadcast>,
    e2g_tx: channel::Sender<SetupResponse>,
) {
    // Step 1.2 — receive Commit₁ batch (mocked)
    let SetupBroadcast::Commit1(commits) = g2e_rx.recv().expect("recv commits") else {
        panic!("unexpected message; expected commits")
    };

    let mut eval = ccn::Evaluator::<ExampleHasher>::create_test_only(cfg.clone(), commits);

    // Step 1.3 — provide the nonce to Garbler
    e2g_tx
        .send(SetupResponse::Commit2Nonce(eval.get_nonce()))
        .expect("send nonce");

    // Step 1.4 — receive Commit₂ batch (mocked)
    let SetupBroadcast::Commit2(commits2) = g2e_rx.recv().expect("recv commit2") else {
        panic!("unexpected message; expected commit2")
    };
    eval.fill_second_commit(commits2);

    // Step 2 — send finalize challenge back to Garbler (indexes only)
    let finalize_indexes = eval.finalized_indexes().to_vec();
    e2g_tx
        .send(SetupResponse::FinalizeChallenge(finalize_indexes))
        .expect("send finalize challenge");

    // Step 3 — receive seeds for open instances and run mocked regarbling
    let SetupBroadcast::OpenSeeds(open) = g2e_rx.recv().expect("recv open seeds") else {
        panic!("unexpected message; expected open seeds")
    };

    let _ = out_dir; // repo path kept for structural similarity/logging

    eval.run_regarbling_test_only(open)
        .expect("regarbling test-only");

    // Step 4 — verify soldering proof against commits (mocked/no-op)
    let SetupBroadcast::SolderingProof(proof) = g2e_rx.recv().expect("recv soldering proof") else {
        panic!("unexpected message; expected soldering proof")
    };

    eval.verify_soldering_against_commits(*proof)
        .expect("soldering verify test-only");
}
