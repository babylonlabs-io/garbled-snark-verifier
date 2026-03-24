//! VSSS Garbler implementation for the cut-and-choose protocol.
//!
//! This module contains the VsssGarbler which uses Verifiable Secret Sharing Scheme
//! for the cut-and-choose protocol.

use std::thread;

use ark_secp256k1::{Fr, Projective};
use itertools::Itertools;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::{
    Canonical, FinalizeChallenge, FinalizedVsssInstance, OpenVsssInstance, Polynomial,
    PolynomialCommits, Secp256k1, ShareCommits, VsssCommit, transpose,
    wide_garbling::GarbledWideLabelTable,
};
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, GarbleMode, GarbledWire, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, EncodeInput, StreamingMode,
        StreamingResult,
    },
    cut_and_choose::{
        Config, LabelCommitHasher, Seed,
        vanilla::{CommitPhaseOne, GarbledInstance, GarblerStage},
    },
    hashers::GateHasher,
};

pub type InstanceWideLabelLookup = Vec<GarbledWideLabelTable>;

/// Helper that owns all VSSS-specific state (polynomials, shares, wide tables).
/// Keeps garbling artifacts (seeds, instances) in the outer garbler.
#[derive(Debug, Serialize, Deserialize)]
pub struct VSSSContext<const W: usize = 8> {
    pub polynomials: Vec<Polynomial<Canonical<Fr>>>,
    /// Transposed shares: per-instance, all shares for that instance.
    pub wide_label_shares: Vec<Vec<Canonical<Fr>>>,
    /// Wide label lookup tables per instance, built from input labels + shares.
    pub wide_tables: Vec<InstanceWideLabelLookup>,
    /// Blake3 hash for each instance's wide table set.
    pub wide_table_commits: Vec<[u8; 32]>,
}

impl<const W: usize> VSSSContext<W> {
    pub fn new<I: CircuitInput + Clone>(mut rng: impl Rng, config: &Config<I>) -> Self {
        let mut x = 0;
        let allocated = config.input().allocate(|| {
            x += 1;
            WireId(x)
        });
        let num_inputs = <I as CircuitInput>::collect_wire_ids(&allocated).len();

        // Generate polynomials for chunks of up to 8 input bits.
        let polynomials = (0..num_inputs)
            .chunks(W)
            .into_iter()
            .flat_map(|chunk| {
                let num_bits = chunk.count();
                let num_labels = 2u32.pow(num_bits as u32);
                (0..num_labels)
                    .map(|_| Polynomial::rand(&mut rng, config.total - config.finalized_count()))
                    .collect_vec()
            })
            .collect_vec();

        // Shares for every polynomial, transposed to per-instance layout.
        let coeffs = polynomials
            .iter()
            .map(|polynomial| {
                polynomial
                    .shares(config.total)
                    .into_iter()
                    .map(|(_, share)| share)
                    .collect_vec()
            })
            .collect_vec();

        let wide_label_shares = transpose(&coeffs)
            .into_iter()
            .map(|shares| shares.into_iter().map(Canonical).collect())
            .collect();

        Self {
            polynomials: polynomials
                .into_iter()
                .map(Polynomial::to_canonical)
                .collect(),
            wide_label_shares,
            wide_tables: Vec::new(),
            wide_table_commits: Vec::new(),
        }
    }

    pub fn share_commits<LH: LabelCommitHasher>(&self) -> Vec<ShareCommits<Canonical<Projective>>> {
        let secp = Secp256k1::shared();

        // Convert canonical polynomials back and compute share commitments in parallel.
        crate::cut_and_choose::get_optimized_pool().install(|| {
            self.polynomials
                .par_iter()
                .map(|polynomial| {
                    polynomial
                        .from_canonical()
                        .share_commits(secp, self.wide_label_shares.len())
                        .to_canonical()
                })
                .collect()
        })
    }

    pub fn polynomial_commits(&self) -> Vec<PolynomialCommits<Canonical<Projective>>> {
        let secp = Secp256k1::shared();

        crate::cut_and_choose::get_optimized_pool().install(|| {
            self.polynomials
                .par_iter()
                .map(|polynomial| {
                    polynomial
                        .from_canonical()
                        .coefficient_commits(secp)
                        .to_canonical()
                })
                .collect()
        })
    }

    pub fn shares_for_instance(&self, idx: usize) -> &[Canonical<Fr>] {
        &self.wide_label_shares[idx]
    }

    pub fn shares_for_instance_fr(&self, idx: usize) -> Vec<Fr> {
        self.wide_label_shares[idx]
            .iter()
            .map(|c| c.0)
            .collect_vec()
    }

    pub fn attach_input_labels(&mut self, all_input_labels: &[Vec<GarbledWire>]) {
        assert_eq!(
            all_input_labels.len(),
            self.wide_label_shares.len(),
            "input labels must match number of instances"
        );

        self.wide_tables = crate::cut_and_choose::get_optimized_pool().install(|| {
            all_input_labels
                .par_iter()
                .zip(self.wide_label_shares.par_iter())
                .map(|(input_labels, wide_labels)| {
                    let wide_labels = wide_labels.iter().map(|c| c.0).collect_vec();
                    GarbledWideLabelTable::build_all::<W>(&wide_labels, input_labels)
                })
                .collect()
        });

        self.wide_table_commits = crate::cut_and_choose::get_optimized_pool().install(|| {
            self.wide_tables
                .par_iter()
                .map(|tables| GarbledWideLabelTable::aggregate_hash(tables))
                .collect()
        });
    }

    pub fn wide_table_commits(&self) -> &[[u8; 32]] {
        &self.wide_table_commits
    }

    pub fn wide_table_for(&self, idx: usize) -> &InstanceWideLabelLookup {
        &self.wide_tables[idx]
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "I: Serialize + serde::de::DeserializeOwned, GH: GateHasher")]
pub struct Garbler<I: CircuitInput + Clone, GH: GateHasher = AesCcrGateHasher, const W: usize = 8> {
    stage: GarblerStage,
    instances: Vec<GarbledInstance<GH>>,
    pub config: Config<I>,
    live_capacity: usize,
    vsss: VSSSContext<W>,
}

impl<I, GH, const W: usize> Garbler<I, GH, W>
where
    I: CircuitInput + Clone + Send + Sync + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>,
    GH: GateHasher + 'static,
    <I as CircuitInput>::WireRepr: Send,
    I: 'static,
{
    /// Create garbled instances in parallel using the provided circuit builder function.
    pub fn create<F>(mut rng: impl Rng, config: Config<I>, live_capacity: usize, builder: F) -> Self
    where
        F: Fn(&mut StreamingMode<GarbleMode<GH, Blake3AccumulatingHash>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let mut vsss = VSSSContext::new(&mut rng, &config);

        let seeds = (0..config.total)
            .map(|_| rng.r#gen())
            .collect::<Box<[Seed]>>();

        // Use optimized thread pool internally
        let instances: Vec<_> = crate::cut_and_choose::get_optimized_pool().install(|| {
            seeds
                .par_iter()
                .enumerate()
                .map(|(index, garbling_seed)| {
                    let inputs = config.input.clone();
                    let hasher = Blake3AccumulatingHash::default();

                    let span = tracing::info_span!("garble", instance = index);
                    let _enter = span.enter();

                    info!("Starting garbling of circuit (cut-and-choose)");

                    let res: StreamingResult<
                        GarbleMode<GH, Blake3AccumulatingHash>,
                        I,
                        GarbledWire,
                    > = CircuitBuilder::streaming_garbling(
                        inputs,
                        live_capacity,
                        *garbling_seed,
                        hasher,
                        builder,
                    );

                    // Derive gate hasher seed from garbling seed (same derivation as GarbleMode::new)
                    let gate_hasher_seed = {
                        use rand::SeedableRng;
                        use rand_chacha::ChaChaRng;
                        let mut rng = ChaChaRng::seed_from_u64(*garbling_seed);
                        GH::from_rng(&mut rng).seed().clone()
                    };
                    GarbledInstance::<GH>::from_streaming_result(res, gate_hasher_seed)
                })
                .collect()
        });

        let all_input_labels = instances
            .iter()
            .map(|instance| instance.input_wire_values.clone())
            .collect_vec();
        vsss.attach_input_labels(&all_input_labels);

        Self {
            stage: GarblerStage::Generating { seeds },
            instances,
            live_capacity,
            config,
            vsss,
        }
    }

    /// Produce the `Commit₁` transcript for every garbled instance (spec Step 1.2).
    pub fn commit<LH>(&self) -> VsssCommit<GH, LH>
    where
        LH: LabelCommitHasher,
    {
        let circuit_commits = self
            .instances
            .iter()
            .map(|x| CommitPhaseOne::<GH, LH>::from_instance(x))
            .collect_vec();
        let share_commits = self.vsss.share_commits::<LH>();
        let polynomial_commits = self.vsss.polynomial_commits();
        let garbling_table_commits = self.vsss.wide_table_commits().to_vec();
        VsssCommit {
            circuit_commits,
            share_commits,
            polynomial_commits,
            garbling_table_commits,
        }
    }

    pub fn open_commit<F, CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        mut indexes_to_finalize: Vec<FinalizeChallenge<CTH>>,
        builder: F,
    ) -> (Vec<OpenVsssInstance>, Vec<FinalizedVsssInstance>)
    where
        F: 'static
            + Fn(&mut StreamingMode<GarbleMode<GH, CTH>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
        I: EncodeInput<GarbleMode<GH, CTH>>,
    {
        let seeds = self
            .stage
            .next_stage(indexes_to_finalize.iter().map(|x| x.index).collect());

        let mut finalized_instance_data = Vec::new();
        let mut opened_instance_data = Vec::new();

        // TODO #37 Since at this point the number but finalization is no more than 7, we just run
        // threads here, without rayon
        seeds
            .iter()
            .enumerate()
            .map(|(index, garbling_seed)| {
                let pos = indexes_to_finalize.iter().position(|x| x.index == index);

                if let Some(pos) = pos {
                    let finalization_info = indexes_to_finalize.remove(pos);
                    // not revealed.
                    let ciphertext_handler = finalization_info.ciphertext_handler;

                    let inputs = self.config.input.clone();
                    let garbling_seed = *garbling_seed;

                    let live_capacity = self.live_capacity;

                    let garbling_thread = thread::spawn(move || {
                        let _span =
                            tracing::info_span!("regarble2send", instance = index).entered();

                        info!("Starting");

                        let _: StreamingResult<_, I, GarbledWire> =
                            CircuitBuilder::<GarbleMode<GH, _>>::streaming_garbling(
                                inputs,
                                live_capacity,
                                garbling_seed,
                                ciphertext_handler,
                                builder,
                            );
                    });

                    finalized_instance_data.push(FinalizedVsssInstance {
                        index,
                        wide_label_lookup: self.vsss.wide_table_for(index).clone(),
                        garbling_thread,
                    });
                } else {
                    // reveal share
                    let shares = self.vsss.shares_for_instance(index).to_vec();
                    opened_instance_data.push(OpenVsssInstance {
                        index,
                        seed: *garbling_seed,
                        shares,
                    });
                }
            })
            .collect_vec();
        (opened_instance_data, finalized_instance_data)
    }

    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    /// Return a clone of the input garbled labels for a given instance.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.instances[index].input_wire_values.clone()
    }

    pub fn wide_labels_for(&self, index: usize) -> Vec<Fr> {
        self.vsss.shares_for_instance_fr(index)
    }
}
