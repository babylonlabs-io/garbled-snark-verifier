#![cfg(feature = "test-utils")]

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use garbled_snark_verifier::{
    S,
    circuit::{CiphertextHandler, ciphertext_source::CiphertextSource},
    cut_and_choose::{
        CiphertextHandlerProvider, CiphertextSourceProvider, DefaultLabelCommitHasher, Seed,
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
    let seeds = vec![11_u64, 22_u64, 33_u64];

    let before = seeds.iter().all(|seed| {
        let path = cache_dir.join(format!("{seed}.json"));
        path.exists()
    });

    let first = Instant::now();
    run_flow(&cache_dir, &config, &seeds);
    let first = first.elapsed();

    if before {
        info!("Run with cache is {}", first.as_secs());
        return;
    }

    for seed in &seeds {
        let path = cache_dir.join(format!("{seed}.json"));
        assert!(
            path.exists(),
            "expected cache file {path:?} to exist after warmup"
        );
    }

    let second = Instant::now();
    run_flow(&cache_dir, &config, &seeds);
    let second = second.elapsed();

    assert!(second < first);
}

fn run_flow(cache_dir: &Path, config: &Config, seeds: &[Seed]) {
    let mut garbler = Garbler::create_test_only(cache_dir, config.clone())
        .expect("first pass should garble and populate cache");

    let first_commits = garbler.commit_phase_one::<DefaultLabelCommitHasher>();
    let mut evaluator = Evaluator::create_test_only(config.clone(), first_commits);
    let nonce = evaluator.get_nonce();
    let second_commits = garbler.commit_phase_two::<DefaultLabelCommitHasher>(nonce);
    evaluator.fill_second_commit(second_commits);

    let mut seeds_for_regarbling = vec![];
    for index in evaluator.finalized_indexes() {
        seeds_for_regarbling.push((*index, seeds[*index]));
    }

    evaluator
        .run_regarbling_test_only(
            seeds_for_regarbling,
            &NoopCiphertextSources,
            &NoopCiphertextHandlers,
            Some(cache_dir),
        )
        .expect("warmup regarbling should garble and cache");

    garbler.do_soldering();
}

#[derive(Clone, Copy)]
struct NoopCiphertextSources;

#[derive(Clone, Copy, Default)]
struct NoCiphertextSource;

impl CiphertextSource for NoCiphertextSource {
    type Result = ();

    fn recv(&mut self) -> Option<S> {
        None
    }

    fn finalize(&self) -> Self::Result {}
}

impl CiphertextSourceProvider for NoopCiphertextSources {
    type Source = NoCiphertextSource;
    type Error = ();

    fn source_for(&self, _: usize) -> Result<Self::Source, Self::Error> {
        Ok(NoCiphertextSource)
    }
}

#[derive(Clone, Copy)]
struct NoopCiphertextHandlers;

#[derive(Clone, Copy, Default)]
struct NoopCiphertextHandler;

impl CiphertextHandler for NoopCiphertextHandler {
    type Result = [u8; 16];

    fn handle(&mut self, _: S) {}

    fn finalize(self) -> Self::Result {
        [0u8; 16]
    }
}

impl CiphertextHandlerProvider for NoopCiphertextHandlers {
    type Handler = NoopCiphertextHandler;
    type Error = ();

    fn handler_for(&self, _: usize) -> Result<Self::Handler, Self::Error> {
        Ok(NoopCiphertextHandler)
    }
}
