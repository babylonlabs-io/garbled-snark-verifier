#[cfg(all(feature = "poseidon2", target_arch = "x86_64", target_feature = "avx2"))]
use p3_goldilocks::PackedGoldilocksAVX2;
#[cfg(feature = "poseidon2")]
use {
    p3_field::{PackedValue, PrimeCharacteristicRing, PrimeField64, integers::QuotientMap},
    p3_goldilocks::{
        Goldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
        HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS, Poseidon2ExternalLayerGoldilocks,
        Poseidon2Goldilocks, Poseidon2InternalLayerGoldilocks,
    },
    p3_poseidon2::{ExternalLayerConstants, Poseidon2},
    p3_symmetric::Permutation,
};

use super::{
    super::GateId,
    aes_ni::{aes128_encrypt_block_static_xor, aes128_encrypt2_blocks_static_xor},
};
use crate::{S, core::s::S_SIZE};

pub trait GateHasher: Clone + Send + Sync {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S);
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S;
}

#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

impl GateHasher for Blake3Hasher {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        let h_selected = Self::hash_for_degarbling(selected_label, gate_id);
        let h_other = Self::hash_for_degarbling(other_label, gate_id);
        (h_selected, h_other)
    }

    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        let mut result = [0u8; S_SIZE];
        let mut hasher = blake3::Hasher::new();
        let b = label.to_bytes();
        hasher.update(&b);
        hasher.update(&gate_id.to_le_bytes());
        let hash = hasher.finalize();
        result.copy_from_slice(&hash.as_bytes()[0..S_SIZE]);
        S::from_bytes(result)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AesNiHasher;

impl GateHasher for AesNiHasher {
    #[inline(always)]
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        // GateId as tweak: XOR pre-whitening with a 128-bit mix of gate_id
        let gate_id_u64 = gate_id as u64;
        let t0 = gate_id_u64 ^ 0x1234_5678_9ABC_DEF0u64;
        let t1 = gate_id_u64.wrapping_mul(0xDEAD_BEEF_CAFE_BABEu64);

        let (c0, c1) = aes128_encrypt2_blocks_static_xor(
            selected_label.to_bytes(),
            other_label.to_bytes(),
            u64_to_mask(t0, t1),
        )
        .expect("AES backend should be available (HW or software)");
        (S::from_bytes(c0), S::from_bytes(c1))
    }

    #[inline(always)]
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        // Same tweak computation as in garbling
        let gate_id_u64 = gate_id as u64;
        let t0 = gate_id_u64 ^ 0x1234_5678_9ABC_DEF0u64;
        let t1 = gate_id_u64.wrapping_mul(0xDEAD_BEEF_CAFE_BABEu64);
        let c = aes128_encrypt_block_static_xor(label.to_bytes(), u64_to_mask(t0, t1))
            .expect("AES backend should be available (HW or software)");
        S::from_bytes(c)
    }
}

#[inline(always)]
fn u64_to_mask(t0: u64, t1: u64) -> [u8; S_SIZE] {
    // Build mask in the same lane order as _mm_set_epi64x(t1, t0)
    let mut m = [0u8; S_SIZE];
    m[..8].copy_from_slice(&t0.to_le_bytes());
    m[8..].copy_from_slice(&t1.to_le_bytes());
    m
}

#[cfg(feature = "poseidon2")]
use once_cell::sync::Lazy;

#[cfg(feature = "poseidon2")]
fn map_u64s_to_goldilocks<const N: usize>(input: [u64; N]) -> [Goldilocks; N] {
    input.map(Goldilocks::from_int)
}

#[cfg(feature = "poseidon2")]
static POSEIDON2_PERM: Lazy<Poseidon2Goldilocks<8>> = Lazy::new(|| {
    // Construct Poseidon2 (Goldilocks, width 8) using saved constants with optimized external layer
    let external = ExternalLayerConstants::<Goldilocks, 8>::new_from_saved_array(
        HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
        map_u64s_to_goldilocks,
    );
    let internal = map_u64s_to_goldilocks(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec();

    Poseidon2::<
        Goldilocks,
        Poseidon2ExternalLayerGoldilocks<8>,
        Poseidon2InternalLayerGoldilocks,
        8,
        7,
    >::new(external, internal)
});

#[cfg(feature = "poseidon2")]
#[derive(Clone, Debug, Default)]
pub struct Poseidon2Hasher;

#[cfg(feature = "poseidon2")]
impl GateHasher for Poseidon2Hasher {
    #[inline(always)]
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        // Fast path: AVX2 dual-lane permutation to compute both hashes at once.
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            // Map labels to two u64 limbs
            let (s_lo, s_hi) = label_to_u64s(selected_label);
            let (o_lo, o_hi) = label_to_u64s(other_label);

            // Build packed state with lanes: [selected, other, 0, 0]
            let g_lo = Goldilocks::from_int(gate_id as u64);
            let mut state: [PackedGoldilocksAVX2; 8] = core::array::from_fn(|i| match i {
                0 => PackedGoldilocksAVX2::from_fn(|lane| match lane {
                    0 => Goldilocks::from_int(s_lo),
                    1 => Goldilocks::from_int(o_lo),
                    _ => Goldilocks::ZERO,
                }),
                1 => PackedGoldilocksAVX2::from_fn(|lane| match lane {
                    0 => Goldilocks::from_int(s_hi),
                    1 => Goldilocks::from_int(o_hi),
                    _ => Goldilocks::ZERO,
                }),
                2 => PackedGoldilocksAVX2::from_fn(|lane| match lane {
                    0 | 1 => g_lo,
                    _ => Goldilocks::ZERO,
                }),
                _ => PackedGoldilocksAVX2::ZERO,
            });

            POSEIDON2_PERM.permute_mut(&mut state);

            let out0 = state[0].as_slice();
            let out1 = state[1].as_slice();

            let s_out = S::from_u128(
                ((out1[0].as_canonical_u64() as u128) << 64) | (out0[0].as_canonical_u64() as u128),
            );
            let o_out = S::from_u128(
                ((out1[1].as_canonical_u64() as u128) << 64) | (out0[1].as_canonical_u64() as u128),
            );

            return (s_out, o_out);
        }

        // Fallback scalar: compute separately.
        #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
        {
            let h_selected = Self::hash_for_degarbling(selected_label, gate_id);
            let h_other = Self::hash_for_degarbling(other_label, gate_id);
            (h_selected, h_other)
        }
    }

    #[inline(always)]
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        let (low, high) = label_to_u64s(label);
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            // Use AVX2 packed path even for single hash to leverage vector ops
            let g_lo = Goldilocks::from_int(gate_id as u64);
            let mut state: [PackedGoldilocksAVX2; 8] = core::array::from_fn(|i| match i {
                0 => PackedGoldilocksAVX2::from_fn(|lane| {
                    if lane == 0 {
                        Goldilocks::from_int(low)
                    } else {
                        Goldilocks::ZERO
                    }
                }),
                1 => PackedGoldilocksAVX2::from_fn(|lane| {
                    if lane == 0 {
                        Goldilocks::from_int(high)
                    } else {
                        Goldilocks::ZERO
                    }
                }),
                2 => PackedGoldilocksAVX2::from_fn(
                    |lane| if lane == 0 { g_lo } else { Goldilocks::ZERO },
                ),
                _ => PackedGoldilocksAVX2::ZERO,
            });
            POSEIDON2_PERM.permute_mut(&mut state);
            let out0 = state[0].as_slice()[0].as_canonical_u64();
            let out1 = state[1].as_slice()[0].as_canonical_u64();
            return S::from_u128(((out1 as u128) << 64) | (out0 as u128));
        }
        #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
        {
            let mut state = [Goldilocks::ZERO; 8];
            state[0] = Goldilocks::from_int(low);
            state[1] = Goldilocks::from_int(high);
            state[2] = Goldilocks::from_int(gate_id as u64);
            POSEIDON2_PERM.permute_mut(&mut state);
            let out0 = state[0].as_canonical_u64();
            let out1 = state[1].as_canonical_u64();
            S::from_u128(((out1 as u128) << 64) | (out0 as u128))
        }
    }
}

#[cfg(feature = "poseidon2")]
#[inline(always)]
fn label_to_u64s(label: &S) -> (u64, u64) {
    let u = label.to_u128();
    ((u & 0xFFFF_FFFF_FFFF_FFFF) as u64, (u >> 64) as u64)
}
