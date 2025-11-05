#![no_main]
sp1_zkvm::entrypoint!(main);

use core::ops::BitXor;
use sha2::{Digest, Sha256};

pub mod types;
pub use types::*;

fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard().with_fixed_int_encoding()
}

#[inline(always)]
fn hash_label_into(hasher: &mut Sha256, label: u128, out: &mut [u8; 32]) {
    let bytes = label.to_be_bytes();
    hasher.update(bytes);
    hasher.finalize_into_reset(out.into());
}

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();

    let (input, _) = bincode::decode_from_slice::<WiresInput, _>(
        &input_bytes,
        bincode_config(),
    )
    .expect("failed to decode input");

    let (base_instance, remaining) = input.instances_wires.split_first().unwrap();
    let soldered_instances_count = remaining.len();
    let nonce = input.nonce;

    let wires_count = base_instance.len();

    let mut base_commitment = vec![([0u8; 32], [0u8; 32]); wires_count];
    let mut base_nonce_commitment = vec![([0u8; 32], [0u8; 32]); wires_count];

    // Initialize commitments for each instance with proper capacity
    let mut commitments: Vec<Vec<([u8; 32], [u8; 32])>> =
        vec![vec![([0u8; 32], [0u8; 32]); wires_count]; soldered_instances_count];

    let mut deltas = vec![Vec::with_capacity(wires_count); soldered_instances_count];

    // Reuse single hasher for all operations
    let mut hasher = Sha256::new();

    for wire_id in 0..wires_count {
        let base_wire = &base_instance[wire_id];

        // Compute base commitments
        hash_label_into(&mut hasher, base_wire.label0, &mut base_commitment[wire_id].0);
        hash_label_into(&mut hasher, base_wire.label1, &mut base_commitment[wire_id].1);

        // Compute base nonce commitments in the same loop
        let label0_with_nonce = base_wire.label0.bitxor(nonce);
        hash_label_into(
            &mut hasher,
            label0_with_nonce,
            &mut base_nonce_commitment[wire_id].0,
        );

        let label1_with_nonce = base_wire.label1.bitxor(nonce);
        hash_label_into(
            &mut hasher,
            label1_with_nonce,
            &mut base_nonce_commitment[wire_id].1,
        );

        // Get corresponding wire from each remaining instance
        for idx in 0..soldered_instances_count {
            let instance_wire = &remaining[idx][wire_id];

            // Hash each label individually like base instance, reusing the hasher
            hash_label_into(
                &mut hasher,
                instance_wire.label0,
                &mut commitments[idx][wire_id].0,
            );
            hash_label_into(
                &mut hasher,
                instance_wire.label1,
                &mut commitments[idx][wire_id].1,
            );

            let delta0 = base_wire.label0.bitxor(instance_wire.label0);
            let delta1 = base_wire.label1.bitxor(instance_wire.label1);
            deltas[idx].push(WireDelta { delta0, delta1 });
        }
    }

    let data = SolderedLabelsData {
        deltas,
        base_commitment,
        base_nonce_commitment,
        commitments,
        nonce,
    };

    let output = bincode::encode_to_vec(data, bincode_config())
        .expect("failed to encode output");
    sp1_zkvm::io::commit_slice(&output);
}
