//! Performance test for prove operation with specific parameters
//! Run with: cargo test --package gsv-soldering-core --release -- --ignored --nocapture prove_1019x7

use gsv_soldering_core::host;
use gsv_soldering_core::types::{InstancesWires, WiresInput};
use std::time::Instant;
use test_log::test;

/// Generate test input with exact parameters
fn generate_input(wires: usize, instances: usize) -> WiresInput {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Generate a consistent Free-XOR delta (must be odd)
    let delta: u128 = rng.r#gen::<u128>() | 1;
    let nonce: u128 = rng.r#gen();

    let mut instances_wires = Vec::with_capacity(1 + instances);

    // Generate all instances (base + additional)
    for i in 0..=instances {
        let instance: InstancesWires = (0..wires)
            .map(|_| {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;
                (label0, label1)
            })
            .collect();

        instances_wires.push(instance);

        if i == 0 {
            println!("Generated base instance: {wires} wires");
        }
    }

    println!("Generated {} additional instances", instances);

    WiresInput {
        instances_wires,
        nonce,
    }
}

fn prove(wires: usize, instances: usize) {
    let input = generate_input(wires, instances);

    // Confirm sizes
    assert_eq!(input.instances_wires.len(), instances + 1); // 1 base + 2 additional
    assert_eq!(input.instances_wires[0].len(), wires);

    let prove_start = Instant::now();

    let _proven_data = host::prove(&input);

    let prove_duration = prove_start.elapsed();

    println!("Time (seconds): {:.3}", prove_duration.as_secs_f64());
}

#[test]
#[ignore = "slow zkSNARK generation - run with --ignored"]
fn prove_1019x2() {
    prove(1019, 2);
}

#[test]
#[ignore = "slow zkSNARK generation - run with --ignored"]
fn prove_1019x6() {
    prove(1019, 6);
}

#[test]
#[ignore = "slow zkSNARK generation"]
fn prove_minimal() {
    prove(2, 1);
}
