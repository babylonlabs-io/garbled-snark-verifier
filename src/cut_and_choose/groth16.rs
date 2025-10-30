//! Groth16-specific wrappers around the generic cut-and-choose API so callers
//! can mirror the protocol described in `docs/gsv_spec.md` with minimal glue.
#[cfg(feature = "sp1-soldering")]
use garbled_groth16::{EvaluatedCompressedG1Wires, EvaluatedCompressedG2Wires, EvaluatedFrWires};
pub use garbled_groth16::{GarblerCompressedInput, GarblerInput};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub use super::Commitment;
pub use crate::cut_and_choose::{
    CommitPhaseOne, CommitPhaseTwo, LabelCommitHasher, OpenForInstance, Seed,
};
use crate::{
    EvaluatedWire, GarbledWire, S,
    circuit::{CiphertextHandler, CiphertextSource},
    cut_and_choose::{
        self as generic, CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider,
        ConsistencyError, DefaultLabelCommitHasher, GarblerStage, garbler::OpenCommit,
    },
    garbled_groth16::{self, PublicParams},
};

pub type Config = generic::Config<GarblerCompressedInput>;

pub const DEFAULT_CAPACITY: usize = 150_000;

/// Groth16-specific wrapper preserving the existing API while delegating
/// to the generic cut-and-choose implementation.
#[derive(Debug, Serialize, Deserialize)]
pub struct Garbler {
    inner: generic::Garbler<garbled_groth16::GarblerCompressedInput>,
}

impl Garbler {
    pub fn create(rng: impl Rng, config: Config) -> Self {
        let inner = generic::Garbler::create(
            rng,
            config,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        );
        Self { inner }
    }

    #[cfg(feature = "test-utils")]
    pub fn create_test_only(
        dir: impl AsRef<std::path::Path>,
        config: Config,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: generic::Garbler::create_test_only(
                dir,
                config,
                DEFAULT_CAPACITY,
                garbled_groth16::verify_compressed,
            )?,
        })
    }

    pub fn commit_phase_one<HHasher>(&self) -> Vec<CommitPhaseOne<HHasher>>
    where
        HHasher: LabelCommitHasher,
    {
        self.inner.commit_phase_one::<HHasher>()
    }

    pub fn commit_phase_two<HHasher>(&mut self, nonce: S) -> Vec<CommitPhaseTwo<HHasher>>
    where
        HHasher: LabelCommitHasher,
    {
        self.inner.commit_phase_two::<HHasher>(nonce)
    }

    pub fn open_commit<CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        indexes_to_finalize: Vec<(usize, CTH)>,
    ) -> Vec<OpenForInstance> {
        self.inner
            .open_commit(indexes_to_finalize, garbled_groth16::verify_compressed)
    }

    pub fn open_commit_without_ciphertexts(
        &mut self,
        indexes_to_finalize: Vec<usize>,
    ) -> OpenCommit {
        self.inner
            .open_commit_without_ciphertexts(indexes_to_finalize)
    }

    #[cfg(feature = "test-utils")]
    pub fn open_commit_test_only(&mut self) -> Vec<(usize, Seed)> {
        self.inner.open_commit_test_only()
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn true_wire_constant_for(&self, index: usize) -> u128 {
        self.inner.true_wire_constant_for(index)
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn false_wire_constant_for(&self, index: usize) -> u128 {
        self.inner.false_wire_constant_for(index)
    }

    /// Return a clone of the input garbled labels for a given instance.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.inner.input_labels_for(index)
    }

    pub fn prepare_input_labels(
        &self,
        public_params: PublicParams,
        challenge_proof: garbled_groth16::SnarkProof,
    ) -> Vec<EvaluatorCaseInput> {
        let finalized_indices = match self.inner.stage() {
            GarblerStage::Generating { .. } => {
                panic!("You can't prepare `input labels` for not finalized garbler")
            }
            GarblerStage::PreparedForEval { indexes_to_eval } => indexes_to_eval,
        };

        finalized_indices
            .iter()
            .map(|idx| {
                let input = garbled_groth16::EvaluatorCompressedInput::new(
                    public_params.clone(),
                    challenge_proof.clone(),
                    self.inner.config().input().vk.clone(),
                    self.input_labels_for(*idx),
                );

                EvaluatorCaseInput { index: *idx, input }
            })
            .collect()
    }

    pub fn output_wire(&self, index: usize) -> Option<&GarbledWire> {
        self.inner.output_wire(index)
    }

    #[cfg(feature = "sp1-soldering")]
    pub fn do_soldering(&self) -> crate::sp1_soldering::SolderingProof {
        self.inner.do_soldering()
    }

    /// Test-only soldering that reuses cached proofs when available. The cache key is
    /// the sorted list of finalized indexes together with the fixed nonce (0 when used
    /// with `Evaluator::create_test`).
    #[cfg(all(feature = "sp1-soldering", feature = "test-utils"))]
    pub fn do_soldering_test_only(
        &self,
        cache_dir: Option<&std::path::Path>,
    ) -> std::io::Result<crate::sp1_soldering::SolderingProof> {
        self.inner.do_soldering_test_only(cache_dir)
    }

    pub fn finalized_indexes(&self) -> Option<&[usize]> {
        self.inner.finalized_indexes()
    }

    /// Get commitments (both phase one and phase two) when they are ready.
    /// Returns None if either the nonce hasn't been set (no commit_phase_two call)
    /// or if the garbler is not in the correct stage.
    ///
    /// This method combines the results of commit_phase_one and commit_phase_two
    /// into a single Option that returns both when ready.
    pub fn get_commitment<HHasher: LabelCommitHasher>(&self) -> Option<Commitment<HHasher>> {
        self.inner.get_commitment::<HHasher>()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "HHasher: LabelCommitHasher")]
pub struct Evaluator<HHasher: LabelCommitHasher = DefaultLabelCommitHasher> {
    inner: generic::Evaluator<garbled_groth16::GarblerCompressedInput, HHasher>,
}

impl<H: LabelCommitHasher> Evaluator<H> {
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(rng: impl Rng, config: Config, commits: Vec<CommitPhaseOne<H>>) -> Self {
        let inner = generic::Evaluator::<garbled_groth16::GarblerCompressedInput, H>::create(
            rng, config, commits,
        );
        Self { inner }
    }

    /// Test-only constructor mirroring `create` but forcing a fixed nonce (0)
    /// to enable deterministic Commit₂ during regarbling without persisting
    /// the nonce to disk.
    #[cfg(feature = "test-utils")]
    pub fn create_test_only(config: Config, commits: Vec<CommitPhaseOne<H>>) -> Self {
        let inner = generic::Evaluator::<garbled_groth16::GarblerCompressedInput, H>::create_test(
            config, commits,
        );
        Self { inner }
    }

    pub fn fill_second_commit(&mut self, commits: Vec<CommitPhaseTwo<H>>) {
        self.inner.fill_second_commit(commits);
    }

    /// Get commitments (both phase one and phase two) when they are ready.
    /// Returns None if either the nonce hasn't been set (no commit_phase_two call)
    /// or if the garbler is not in the correct stage.
    ///
    /// This method combines the results of commit_phase_one and commit_phase_two
    /// into a single Option that returns both when ready.
    pub fn get_commitment(&self) -> Option<Commitment<H>> {
        self.inner.get_commitment()
    }

    pub fn get_nonce(&self) -> S {
        self.inner.get_nonce()
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        self.inner.finalized_indexes()
    }

    pub fn get_commit_phase_one(&self, index: usize) -> Option<&CommitPhaseOne<H>> {
        self.inner.get_commit_phase_one(index)
    }

    pub fn get_commit_phase_two(&self, index: usize) -> Option<&CommitPhaseTwo<H>> {
        self.inner.get_commit_phase_two(index)
    }

    /// Simplified regarbling method that only verifies open instances without ciphertext verification.
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling(&mut self, seeds: Vec<(usize, Seed)>) -> Result<(), ()> {
        self.inner
            .run_regarbling(seeds, DEFAULT_CAPACITY, garbled_groth16::verify_compressed)
    }

    /// Full verification method that checks both ciphertext commitments and performs regarbling.
    #[allow(clippy::result_unit_err)]
    pub fn full_check_commit<CSourceProvider, CHandlerProvider>(
        &mut self,
        seeds: Vec<(usize, Seed)>,
        ciphertext_sources_provider: &CSourceProvider,
        ciphertext_sink_provider: &CHandlerProvider,
    ) -> Result<(), ()>
    where
        CSourceProvider: CiphertextSourceProvider + Send + Sync,
        CHandlerProvider: CiphertextHandlerProvider + Send + Sync,
        CHandlerProvider::Handler: 'static,
        <CHandlerProvider::Handler as CiphertextHandler>::Result: 'static + Into<CiphertextCommit>,
    {
        self.inner.full_check_commit(
            seeds,
            ciphertext_sources_provider,
            ciphertext_sink_provider,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }
}

pub type EvaluatorCaseInput =
    generic::EvaluatorCaseInput<garbled_groth16::EvaluatorCompressedInput>;

impl<H: LabelCommitHasher> Evaluator<H> {
    /// Evaluate all finalized instances from saved ciphertext files with consistency checking.
    ///
    /// This method performs three consistency checks:
    /// 1. Verifies input labels match the commit
    /// 2. Verifies ciphertext stream matches the commit
    /// 3. Verifies output label matches the appropriate commit (label0/label1)
    ///
    /// Returns `Ok(Vec<(index, EvaluatedWire)>)` if all checks pass, or an error describing the failure.
    pub fn evaluate_from<CR: 'static + CiphertextSourceProvider + Send + Sync>(
        &self,
        ciphertext_repo: &CR,
        input_cases: Vec<EvaluatorCaseInput>,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<H>>
    where
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
    {
        self.inner.evaluate_from(
            ciphertext_repo,
            input_cases,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }

    /// Test-only variant of `full_check_commit` that reuses cached garbled
    /// instances when available and persists any misses to `cache_dir`.
    #[cfg(feature = "test-utils")]
    #[allow(clippy::too_many_arguments, clippy::result_unit_err)]
    pub fn full_check_commit_test_only<CSourceProvider, CHandlerProvider>(
        &mut self,
        ciphertext_sources_provider: &CSourceProvider,
        ciphertext_sink_provider: &CHandlerProvider,
        cache_dir: Option<&std::path::Path>,
    ) -> Result<(), ()>
    where
        CSourceProvider: CiphertextSourceProvider + Send + Sync,
        CHandlerProvider: CiphertextHandlerProvider + Send + Sync,
        CHandlerProvider::Handler: 'static,
        <CHandlerProvider::Handler as CiphertextHandler>::Result: 'static + Into<CiphertextCommit>,
    {
        self.inner.full_check_commit_cached(
            ciphertext_sources_provider,
            ciphertext_sink_provider,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
            cache_dir,
        )
    }

    /// Test-only convenience: full check with on-demand cache warmup; no stream required.
    ///
    /// Uses `test_utils::PrecomputedCommits` to provide expected ciphertext commits,
    /// warming the cache at `cache_dir` as needed. For the ciphertext source, a noop
    /// provider is used so finalized indexes do not require an actual stream.
    #[cfg(feature = "test-utils")]
    #[allow(clippy::result_unit_err)]
    pub fn full_check_commit_test_only_default(
        &mut self,
        cache_dir: impl AsRef<std::path::Path>,
    ) -> Result<(), ()> {
        let commits =
            test_utils::PrecomputedCommits::new(cache_dir.as_ref(), self.inner.config().clone());
        let noop = test_utils::NoopCiphertext;
        self.inner.full_check_commit_cached(
            &noop,
            &commits,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
            Some(cache_dir.as_ref()),
        )
    }

    /// Test-only convenience: full check with optional external ciphertext stream and
    /// on-demand cache warmup for commits.
    #[cfg(feature = "test-utils")]
    #[allow(clippy::result_unit_err)]
    pub fn full_check_commit_test_only_with_stream<CSourceProvider>(
        &mut self,
        ciphertext_sources_provider: &CSourceProvider,
        cache_dir: impl AsRef<std::path::Path>,
    ) -> Result<(), ()>
    where
        CSourceProvider: CiphertextSourceProvider + Send + Sync,
    {
        let commits =
            test_utils::PrecomputedCommits::new(cache_dir.as_ref(), self.inner.config().clone());
        self.inner.full_check_commit_cached(
            ciphertext_sources_provider,
            &commits,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
            Some(cache_dir.as_ref()),
        )
    }
}

// Implement SolderInput to allow creating derived instances from base instance with deltas
#[cfg(feature = "sp1-soldering")]
use crate::sp1_soldering::SolderInput;

#[cfg(feature = "sp1-soldering")]
impl SolderInput for garbled_groth16::EvaluatorCompressedInput {
    fn solder(
        &self,
        per_wire: &[(crate::S, crate::S)],
    ) -> garbled_groth16::EvaluatorCompressedInput {
        let mut it = per_wire.iter();

        let mut map_wire = |ew: &EvaluatedWire| -> EvaluatedWire {
            let (d0, d1) = *it.next().expect("delta length matches input wires");
            let delta = if ew.value { d1 } else { d0 };
            EvaluatedWire::new(ew.active_label ^ &delta, ew.value)
        };

        let map_fr =
            |fr: &garbled_groth16::EvaluatedFrWires,
             map_wire: &mut dyn FnMut(&EvaluatedWire) -> EvaluatedWire| {
                EvaluatedFrWires(fr.0.iter().map(map_wire).collect())
            };

        let public = self
            .public
            .iter()
            .map(|fr| map_fr(fr, &mut map_wire))
            .collect();

        let a_x = map_fr(&self.a.x, &mut map_wire);
        let a_y_flag = map_wire(&self.a.y_flag);

        let b_x0 = map_fr(&self.b.x[0], &mut map_wire);
        let b_x1 = map_fr(&self.b.x[1], &mut map_wire);
        let b_y_flag = map_wire(&self.b.y_flag);

        let c_x = map_fr(&self.c.x, &mut map_wire);
        let c_y_flag = map_wire(&self.c.y_flag);

        garbled_groth16::EvaluatorCompressedInput {
            public,
            a: EvaluatedCompressedG1Wires {
                x: a_x,
                y_flag: a_y_flag,
            },
            b: EvaluatedCompressedG2Wires {
                x: [b_x0, b_x1],
                y_flag: b_y_flag,
            },
            c: EvaluatedCompressedG1Wires {
                x: c_x,
                y_flag: c_y_flag,
            },
            vk: self.vk.clone(),
        }
    }
}

#[cfg(feature = "sp1-soldering")]
impl Evaluator<generic::Sha256LabelCommitHasher> {
    pub fn verify_soldering_against_commits(
        &mut self,
        proof: crate::sp1_soldering::SolderingProof,
    ) -> Result<crate::sp1_soldering::SolderedLabels, generic::SolderingCheckError> {
        self.inner.verify_soldering_against_commits(proof)
    }

    pub fn verified_soldered_base_commitment(
        &self,
    ) -> Option<&[generic::LabelCommit<crate::sp1_soldering::Sha256Commit>]> {
        self.inner.verified_soldered_base_commitment()
    }

    /// Evaluate all finalized instances using a single base set of input labels,
    /// reconstructing the rest from previously verified soldering deltas.
    ///
    /// Requirements:
    /// - Call `verify_soldering_against_commits` first; this stores the deltas.
    /// - `base_case.index` must equal the first finalized index (the base).
    /// - No additional constants are required; constants are derived from commits.
    #[allow(clippy::result_large_err)]
    pub fn run_evaluate_with_soldered_instances<
        CR: 'static + CiphertextSourceProvider + Send + Sync,
    >(
        &self,
        ciphertext_repo: &CR,
        base_case: EvaluatorCaseInput,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<generic::Sha256LabelCommitHasher>>
    where
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
    {
        self.inner.evaluate_with_soldered_instances_from(
            ciphertext_repo,
            base_case,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use std::{
        fs, io,
        path::{Path, PathBuf},
    };

    use serde_json;
    use tracing::info;

    use super::{Config, DEFAULT_CAPACITY, garbled_groth16};
    use crate::{
        AESAccumulatingHash, AesNiHasher, GarbleMode, GarbledWire, S,
        circuit::{
            CiphertextHandler, CircuitBuilder, StreamingResult, ciphertext_source::CiphertextSource,
        },
        cut_and_choose::{self as generic},
    };

    /// No-op ciphertext stream provider for tests that don't supply a real stream.
    #[derive(Clone, Copy, Default)]
    pub struct NoCiphertextSource;

    impl CiphertextSource for NoCiphertextSource {
        type Result = ();

        fn recv(&mut self) -> Option<S> {
            None
        }

        fn finalize(&self) -> Self::Result {}
    }

    #[derive(Clone, Copy, Default)]
    pub struct NoopCiphertext;

    impl generic::CiphertextSourceProvider for NoopCiphertext {
        type Source = NoCiphertextSource;
        type Error = ();

        fn source_for(&self, _index: usize) -> Result<Self::Source, Self::Error> {
            Ok(NoCiphertextSource)
        }
    }

    /// Precomputed commit handler that simply returns a fixed commit.
    #[derive(Clone, Copy)]
    pub struct PrecomputedCommit([u8; 16]);

    impl CiphertextHandler for PrecomputedCommit {
        type Result = [u8; 16];

        fn handle(&mut self, _ct: S) {}

        fn finalize(self) -> Self::Result {
            self.0
        }
    }

    /// Test-only provider of ciphertext commits, backed by on-disk cache
    /// with on-demand garbling on cache miss.
    pub struct PrecomputedCommits {
        dir: PathBuf,
        config: Config,
        capacity: usize,
    }

    impl PrecomputedCommits {
        pub fn new(dir: impl AsRef<Path>, config: Config) -> Self {
            Self {
                dir: dir.as_ref().to_path_buf(),
                config,
                capacity: DEFAULT_CAPACITY,
            }
        }

        #[allow(dead_code)]
        pub fn with_capacity(dir: impl AsRef<Path>, config: Config, capacity: usize) -> Self {
            Self {
                dir: dir.as_ref().to_path_buf(),
                config,
                capacity,
            }
        }

        fn load_or_garble_one(&self, index: usize) -> io::Result<generic::GarbledInstance> {
            let seed = index as u64;
            let path = self.dir.join(format!("{seed}.json"));

            if let Ok(bytes) = fs::read(&path)
                && let Ok(instance) = serde_json::from_slice::<generic::GarbledInstance>(&bytes)
            {
                info!(instance = index, seed, "Loaded cached garbled instance");
                return Ok(instance);
            }

            fs::create_dir_all(&self.dir)?;

            let inputs = self.config.input().clone();
            let hasher = AESAccumulatingHash::default();
            let _span = tracing::info_span!("garble", instance = index, seed).entered();
            info!("Garbling (cache miss or parse error)");

            let res: StreamingResult<
                GarbleMode<AesNiHasher, AESAccumulatingHash>,
                garbled_groth16::GarblerCompressedInput,
                GarbledWire,
            > = CircuitBuilder::streaming_garbling(
                inputs,
                self.capacity,
                seed,
                hasher,
                garbled_groth16::verify_compressed,
            );

            let instance: generic::GarbledInstance = res.into();

            let tmp = path.with_extension("tmp");
            let buf = serde_json::to_vec(&instance)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            fs::write(&tmp, &buf)?;
            fs::rename(&tmp, &path)?;

            Ok(instance)
        }
    }

    impl generic::CiphertextHandlerProvider for PrecomputedCommits {
        type Handler = PrecomputedCommit;
        type Error = io::Error;

        fn handler_for(&self, index: usize) -> Result<Self::Handler, Self::Error> {
            // Use the optimized pool to keep behavior consistent with other test-only garbling
            let instance =
                super::super::get_optimized_pool().install(|| self.load_or_garble_one(index))?;
            Ok(PrecomputedCommit(instance.ciphertext_handler_result))
        }
    }
}
