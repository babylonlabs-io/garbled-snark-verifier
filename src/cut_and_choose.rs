#![allow(dead_code)]

use std::{collections::HashMap, fmt, num::NonZero, thread};

use crossbeam::channel::{self};
use log::info;
use rayon::prelude::*;

use crate::{
    AesNiHasher, CiphertextHashAcc, GarbleMode, GarbledWire, S,
    circuit::{
        CircuitBuilder, CircuitInput,
        streaming::{CircuitOutput, EncodeInput, StreamingMode, StreamingResult},
    },
};

/// Commitment to a single garbled circuit instance produced with a seed.
#[derive(Debug, Clone)]
pub struct GarbledCircuitCommit<O> {
    pub seed: u64,
    pub ciphertext_commit: u128,
    pub input_labels: Vec<GarbledWire>,
    pub output: O,
}

/// Build multiple garbling instances in parallel given seeds and a circuit builder closure.
pub fn build_garbling_instances<I, F, O>(
    seeds: &[u64],
    inputs: I,
    live_wires_capacity: usize,
    f: F,
) -> Vec<GarbledCircuitCommit<O>>
where
    I: CircuitInput + EncodeInput<GarbleMode<AesNiHasher>> + Clone + Send + Sync,
    O: CircuitOutput<GarbleMode<AesNiHasher>> + Clone + Send,
    O::WireRepr: fmt::Debug + Send + Sync,
    F: Fn(&mut StreamingMode<GarbleMode<AesNiHasher>>, &I::WireRepr) -> O::WireRepr
        + Sync
        + Send
        + Copy,
{
    // A single collector thread that receives registrations from each garbling task
    // and drains their ciphertext streams with a timeout, computing commits.
    struct Registration {
        rx: channel::Receiver<(usize, S)>,
        commit_tx: channel::Sender<u128>,
    }

    struct InstanceState {
        rx: channel::Receiver<(usize, S)>,
        hasher: CiphertextHashAcc,
        commit_tx: channel::Sender<u128>,
    }

    let expected_instances = seeds.len();
    let (register_tx, register_rx) = channel::unbounded::<Registration>();

    // Simplicity-first collector: block on any ready receiver and hash immediately.

    let collector = thread::spawn(move || {
        info!(
            "Starting single ciphertext collector thread (expecting {expected_instances} instances)..."
        );

        let mut instances: Vec<InstanceState> = Vec::new();
        let mut finished = 0usize;

        while finished < expected_instances {
            let mut did_work = false;

            // Accept any new registrations (tick) without blocking
            while let Ok(reg) = register_rx.try_recv() {
                instances.push(InstanceState {
                    rx: reg.rx,
                    commit_tx: reg.commit_tx,
                    hasher: CiphertextHashAcc::default(),
                });
                did_work = true;
            }

            // Drain each instance non-blockingly, updating hash immediately per ciphertext
            let mut i = 0usize;
            while i < instances.len() {
                let mut closed = false;
                loop {
                    match instances[i].rx.try_recv() {
                        Ok((_gate_id, ct)) => {
                            instances[i].hasher.update(ct);
                            did_work = true;
                        }
                        Err(channel::TryRecvError::Empty) => break,
                        Err(channel::TryRecvError::Disconnected) => {
                            closed = true;
                            break;
                        }
                    }
                }

                if closed {
                    // Finalize this instance commit and remove it
                    let state = instances.swap_remove(i);
                    let commit = state.hasher.finalize();
                    let _ = state.commit_tx.send(commit);
                    finished += 1;
                    continue; // do not increment i; we swapped in a new item
                }

                i += 1;
            }

            if !did_work {
                // Avoid hot spinning when idle
                std::thread::yield_now();
            }
        }

        info!("Collector thread finished: {finished}/{expected_instances} instances processed.");
    });

    let results: Vec<GarbledCircuitCommit<O>> = seeds
        .par_iter()
        .map(|garbling_seed| {
            // Per-instance ciphertext channel. Unbounded so garbling never blocks on collector.
            // NOTE: Memory usage may grow if collector lags behind producers.
            let (ciphertext_tx, ciphertext_rx) = channel::unbounded::<(usize, S)>();
            // Unbounded commit channel to ensure collector never blocks on send
            let (commit_tx, commit_rx) = channel::unbounded::<u128>();

            // Tick: register with the collector before heavy work begins
            register_tx
                .send(Registration {
                    rx: ciphertext_rx,
                    commit_tx,
                })
                .expect("collector must be alive");

            info!("Starting garbling for cut-and-choose instance...");

            let garbling_result: StreamingResult<GarbleMode<AesNiHasher>, I, O> =
                CircuitBuilder::streaming_garbling(
                    inputs.clone(),
                    live_wires_capacity,
                    *garbling_seed,
                    ciphertext_tx,
                    f,
                );

            let input_values = garbling_result.input_wire_values;
            let output_value = garbling_result.output_value.clone();

            // Wait for the collector to finalize the commit for this instance
            let ciphertext_commit: u128 = commit_rx
                .recv()
                .expect("collector should send commit on completion");

            GarbledCircuitCommit {
                seed: *garbling_seed,
                ciphertext_commit,
                input_labels: input_values,
                output: output_value,
            }
        })
        .collect();

    // Ensure collector has exited cleanly before returning
    let _ = collector.join();

    results
}

/// Handle for a re-garbling streaming process used during opening.
pub struct RegarblerProcess {
    pub garbling_thread: thread::JoinHandle<()>,
    pub receiver: channel::Receiver<(usize, S)>,
}

/// Result of opening a subset of instances: seeds for check set and live ciphertext streams for eval set.
pub struct GarbleOpen {
    pub seeds: HashMap<usize, u64>,
    pub evaluation_ciphertexts: HashMap<usize, RegarblerProcess>,
}

/// Configuration for cut-and-choose garbling.
pub struct Config<I: EncodeInput<GarbleMode<AesNiHasher>>> {
    pub total: NonZero<usize>,
    pub for_evaluation: NonZero<usize>,
    pub inputs: I,
    pub live_wires_capacity: usize,
}

/// Generic cut-and-choose garbler over input `I` and output `O`.
pub struct Garbler<I, O> {
    #[allow(dead_code)]
    instances: Vec<GarbledCircuitCommit<O>>, // kept for potential future use
    inputs: I,
    live_wires_capacity: usize,
}

impl<I, O> Garbler<I, O> {
    pub fn create<F>(mut rng: impl rand::Rng, config: Config<I>, f: F) -> Self
    where
        I: CircuitInput + EncodeInput<GarbleMode<AesNiHasher>> + Clone + Send + Sync,
        O: CircuitOutput<GarbleMode<AesNiHasher>> + Clone + Send,
        O::WireRepr: fmt::Debug + Send + Sync,
        F: Fn(&mut StreamingMode<GarbleMode<AesNiHasher>>, &I::WireRepr) -> O::WireRepr
            + Sync
            + Send
            + Copy,
    {
        let seeds = (0..config.total.get())
            .map(|_| rng.r#gen())
            .collect::<Vec<u64>>();

        let instances = build_garbling_instances::<I, _, O>(
            &seeds,
            config.inputs.clone(),
            config.live_wires_capacity,
            f,
        );

        Garbler {
            instances,
            inputs: config.inputs,
            live_wires_capacity: config.live_wires_capacity,
        }
    }

    /// Open by Garbler: stream ciphertexts for selected instances, reveal seeds for others.
    pub fn open<F>(&self, indexes_to_evaluate: &[usize], f: F) -> GarbleOpen
    where
        I: Clone + EncodeInput<GarbleMode<AesNiHasher>> + Send + 'static,
        O: CircuitOutput<GarbleMode<AesNiHasher>> + Send,
        O::WireRepr: fmt::Debug + Send,
        F: Fn(&mut StreamingMode<GarbleMode<AesNiHasher>>, &I::WireRepr) -> O::WireRepr
            + Send
            + Sync
            + Copy
            + 'static,
    {
        let mut seeds = HashMap::new();
        let mut evaluation_ciphertexts = HashMap::new();

        for (idx, inst) in self.instances.iter().enumerate() {
            let selected = indexes_to_evaluate.contains(&idx);

            if selected {
                let (cipher_send, receiver) = channel::unbounded::<(usize, S)>();

                let inputs = self.inputs.clone();
                let live_wires_capacity = self.live_wires_capacity;
                let seed = inst.seed;

                let garbling_thread = thread::spawn(move || {
                    // Run streaming garbling to reproduce ciphertexts
                    let _result: StreamingResult<GarbleMode<AesNiHasher>, I, O> =
                        CircuitBuilder::streaming_garbling(
                            inputs,
                            live_wires_capacity,
                            seed,
                            cipher_send,
                            f,
                        );
                });

                evaluation_ciphertexts.insert(
                    idx,
                    RegarblerProcess {
                        garbling_thread,
                        receiver,
                    },
                );
            } else {
                // For the remaining indices, disclose the seeds.
                seeds.insert(idx, inst.seed);
            }
        }

        GarbleOpen {
            seeds,
            evaluation_ciphertexts,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::{
        CircuitContext, Delta, Gate, WireId,
        circuit::streaming::{CircuitInput, CircuitMode, EncodeInput},
    };

    /// Minimal garbled inputs for tests: feed fixed garbled labels to allocated wires
    #[derive(Clone)]
    struct SimpleGarbledInputs {
        wires: Vec<GarbledWire>,
    }

    impl CircuitInput for SimpleGarbledInputs {
        type WireRepr = Vec<WireId>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            (0..self.wires.len()).map(|_| issue()).collect()
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.clone()
        }
    }

    /// Simple allocator that issues fresh garbled labels via the mode (no manual labels)
    #[derive(Clone)]
    struct SimpleAlloc {
        n: usize,
    }

    impl CircuitInput for SimpleAlloc {
        type WireRepr = Vec<WireId>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            (0..self.n).map(|_| issue()).collect()
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.clone()
        }
    }

    impl<H: crate::hashers::GateHasher> EncodeInput<crate::circuit::streaming::modes::GarbleMode<H>>
        for SimpleAlloc
    {
        fn encode(
            &self,
            repr: &Vec<WireId>,
            cache: &mut crate::circuit::streaming::modes::GarbleMode<H>,
        ) {
            for &wire_id in repr.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(wire_id, gw);
            }
        }
    }

    impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for SimpleGarbledInputs {
        fn encode(&self, repr: &Vec<WireId>, cache: &mut M) {
            for (wire, wire_id) in self.wires.iter().zip(repr.iter()) {
                cache.feed_wire(*wire_id, wire.clone());
            }
        }
    }

    #[test]
    fn generic_cut_and_choose_small_circuit() {
        // Prepare two input garbled wires deterministically
        let mut rng = ChaChaRng::seed_from_u64(7);
        let delta = Delta::generate(&mut rng);
        let a = GarbledWire::random(&mut rng, &delta);
        let b = GarbledWire::random(&mut rng, &delta);

        let inputs = SimpleGarbledInputs {
            wires: vec![a.clone(), b.clone()],
        };

        // Two seeds -> two instances
        let seeds = vec![42u64, 1337u64];

        // Bring CircuitContext methods (add_gate/issue_wire) into scope for the closure

        let instances =
            build_garbling_instances::<_, _, GarbledWire>(&seeds, inputs, 1_000, |ctx, ins| {
                // Small circuit: out = ins[0] AND ins[1]
                let out = ctx.issue_wire();
                ctx.add_gate(Gate::and(ins[0], ins[1], out));
                out
            });

        // Expect one instance per seed
        assert_eq!(instances.len(), seeds.len());

        // Input labels should match provided a,b by base label (label0)
        for inst in &instances {
            assert_eq!(inst.input_labels.len(), 2);
            assert_eq!(inst.input_labels[0].label0, a.label0);
            assert_eq!(inst.input_labels[1].label0, b.label0);
            // Commit should be some non-zero hash
            assert_ne!(inst.ciphertext_commit, 0);
        }
    }

    #[test]
    fn garbler_open_regarble_stream() {
        // Use the simple test circuit and let garbling mode issue labels
        let inputs = SimpleAlloc { n: 2 };

        // Two seeds -> two instances (index 0 will be regarbled/streamed)
        let seeds = [42u64, 1337u64];

        // Emulate cut-and-choose open: stream ciphertexts for selected index, reveal others' seeds
        let mut seeds_map = std::collections::HashMap::new();
        let mut evaluation_ciphertexts = std::collections::HashMap::new();

        for (idx, seed) in seeds.iter().copied().enumerate() {
            if idx == 0 {
                let (cipher_send, cipher_recv) = crossbeam::channel::unbounded::<(usize, S)>();
                let inputs_cloned = inputs.clone();
                let handle = std::thread::spawn(move || {
                    let _result: crate::circuit::streaming::StreamingResult<
                        crate::circuit::streaming::modes::GarbleMode<crate::AesNiHasher>,
                        _,
                        GarbledWire,
                    > = CircuitBuilder::streaming_garbling(
                        inputs_cloned,
                        1_000,
                        seed,
                        cipher_send,
                        |ctx, ins| {
                            // Small circuit: out = ins[0] AND ins[1]
                            let out = ctx.issue_wire();
                            ctx.add_gate(Gate::and(ins[0], ins[1], out));
                            out
                        },
                    );
                });
                evaluation_ciphertexts.insert(idx, (handle, cipher_recv));
            } else {
                seeds_map.insert(idx, seed);
            }
        }

        assert!(evaluation_ciphertexts.contains_key(&0));
        assert!(seeds_map.contains_key(&1));

        // Drain streamed ciphertexts
        let rx = evaluation_ciphertexts.get(&0).unwrap();
        let mut all = Vec::new();
        while let Ok(msg) = rx.1.recv() {
            all.push(msg);
        }
        assert!(!all.is_empty());
    }
}
