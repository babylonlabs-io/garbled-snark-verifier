#![cfg(feature = "test-utils")]

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use garbled_snark_verifier::{
    cut_and_choose::{
        DefaultLabelCommitHasher,
        groth16::{Config, Evaluator, Garbler, GarblerInput},
    },
    test_utils::dummy_vk,
};
use test_log::test;
use tracing::info;

#[test]
fn easy_test_cache_reuses_garbler_and_evaluator() {
    let base_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));

    let cache_dir = base_dir
        .join("target")
        .join("tests")
        .join("test_utils_tests");

    let _ = fs::create_dir_all(&cache_dir);

    let config = Config::new(
        3,
        2,
        GarblerInput {
            public_params_len: 0,
            vk: dummy_vk(),
        }
        .compress(),
    );

    let before = (0..config.total()).all(|seed| {
        let path = cache_dir.join(format!("{seed}.json"));
        path.exists()
    });

    let first = Instant::now();
    run_flow(&cache_dir, &config);
    let first = first.elapsed();

    if before {
        info!("Run with cache is {}", first.as_secs());
        return;
    }

    for seed in 0..config.total() {
        let path = cache_dir.join(format!("{seed}.json"));
        assert!(
            path.exists(),
            "expected cache file {path:?} to exist after warmup"
        );
    }

    let second = Instant::now();
    run_flow(&cache_dir, &config);
    let second = second.elapsed();

    assert!(second < first);
}

fn run_flow(cache_dir: &Path, config: &Config) {
    let mut garbler = Garbler::create_test_only(cache_dir, config.clone())
        .expect("first pass should garble and populate cache");

    let first_commits = garbler.commit_phase_one::<DefaultLabelCommitHasher>();
    let mut evaluator = Evaluator::create_test_only(config.clone(), first_commits);
    let nonce = evaluator.get_nonce();
    let second_commits = garbler.commit_phase_two::<DefaultLabelCommitHasher>(nonce);
    evaluator.fill_second_commit(second_commits);

    evaluator
        .run_regarbling_test_only_default(cache_dir)
        .expect("warmup regarbling should garble and cache");

    garbler.do_soldering_test_only(Some(cache_dir)).unwrap();
}

// Commit / ciphertext helpers are provided by the crate's test-utils.
