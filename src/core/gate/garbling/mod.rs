use super::{GateId, GateType};
use crate::{Delta, EvaluatedWire, GarbledWire};

pub mod aes_ni;
pub mod hashers;
#[cfg(feature = "poseidon2")]
pub use hashers::Poseidon2Hasher;
pub use hashers::{AesNiHasher, Blake3Hasher, GateHasher};

pub fn garble<H: GateHasher>(
    gate_id: GateId,
    gate_type: GateType,
    a: &GarbledWire,
    b: &GarbledWire,
    delta: &Delta,
) -> (crate::S, crate::S) {
    let (alpha_a, alpha_b, alpha_c) = gate_type.alphas();

    // Branchless selection of A's active label; compute the other via free-XOR.
    let selected_label = select_branchless(a, alpha_a);
    let other_label = selected_label ^ delta;
    let (h_a0, h_a1) = H::hash_for_garbling(&selected_label, &other_label, gate_id);

    // Branchless selection of B's active label for ciphertext blending.
    let b_sel = select_branchless(b, alpha_b);
    let ct = h_a0 ^ &h_a1 ^ &b_sel;

    let w = if alpha_c { h_a0 ^ delta } else { h_a0 };

    (ct, w)
}

#[inline(always)]
fn select_branchless(w: &GarbledWire, bit: bool) -> crate::S {
    // mask = 0 or !0 as u128
    let mask = 0u128.wrapping_sub(bit as u128);
    let l0 = w.label0.to_u128();
    let l1 = w.label1.to_u128();
    crate::S::from_u128(l0 ^ ((l0 ^ l1) & mask))
}

pub fn degarble<H: GateHasher>(
    gate_id: GateId,
    gate_type: GateType,
    ciphertext: &crate::S,
    a: &EvaluatedWire,
    b: &EvaluatedWire,
) -> crate::S {
    let h_a = H::hash_for_degarbling(&a.active_label, gate_id);

    let (alpha_a, _alpha_b, _alpha_c) = gate_type.alphas();
    let cond_mask = 0u128.wrapping_sub((a.value() != alpha_a) as u128);

    // Branchless: result = h_a ^ (cond ? (ciphertext ^ b.active_label) : 0)
    let h = h_a.to_u128();
    let mix = (ciphertext.to_u128() ^ b.active_label.to_u128()) & cond_mask;
    crate::S::from_u128(h ^ mix)
}

#[cfg(test)]
mod aes_ni_test;
#[cfg(test)]
mod tests;
