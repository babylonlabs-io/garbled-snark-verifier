use digest::Digest;

use super::{GateId, GateType};
use crate::{Delta, EvaluatedWire, GarbledWire, S};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Generic hash function with unique tweak per gate using any digest implementation
fn hash_gate_with_tweak<D: Digest + Default>(x: &S, tweak: GateId) -> S {
    assert!(<D as Digest>::output_size() >= 16);
    let mut result = [0u8; 16];

    result.copy_from_slice(
        &D::default()
            .chain_update(x.0)
            .chain_update(tweak.to_le_bytes())
            .finalize()[0..16],
    );

    S(result)
}

/// Optimized AES dual-hash for half-garbling: compute both h_a0 and h_a1 simultaneously
/// This is specifically optimized for AES when we need:
/// h_a0 = hash(a.select(alpha_a), gate_id) 
/// h_a1 = hash(a.select(!alpha_a), gate_id)
#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
#[target_feature(enable = "aes,sse2")]
unsafe fn aes_dual_hash_gate_with_tweak(
    a: &GarbledWire,
    gate_id: GateId,
    alpha_a: bool
) -> (S, S) {  // Returns (h_a0, h_a1)
    unsafe {
        // Prepare AES key from gate_id
        let mut key_bytes = [0u8; 16];
        *(key_bytes.as_mut_ptr() as *mut u64) = gate_id as u64;
        let key_vec = _mm_loadu_si128(key_bytes.as_ptr() as *const __m128i);
        
        // Load both wire labels as SIMD vectors 
        let label0_vec = _mm_loadu_si128(a.label0.0.as_ptr() as *const __m128i);
        let label1_vec = _mm_loadu_si128(a.label1.0.as_ptr() as *const __m128i);
        
        // Select based on alpha_a for both h_a0 and h_a1
        let (data_vec0, data_vec1) = if alpha_a {
            (label0_vec, label1_vec)  // h_a0 = hash(label0), h_a1 = hash(label1)
        } else {
            (label1_vec, label0_vec)  // h_a0 = hash(label1), h_a1 = hash(label0)
        };
        
        // Compute both AES encryptions in parallel
        let mut result0_vec = _mm_xor_si128(data_vec0, key_vec);
        result0_vec = _mm_aesenc_si128(result0_vec, key_vec);
        result0_vec = _mm_aesenclast_si128(result0_vec, key_vec);
        
        let mut result1_vec = _mm_xor_si128(data_vec1, key_vec);
        result1_vec = _mm_aesenc_si128(result1_vec, key_vec);
        result1_vec = _mm_aesenclast_si128(result1_vec, key_vec);
        
        // Store results
        let mut h_a0 = [0u8; 16];
        let mut h_a1 = [0u8; 16];
        _mm_storeu_si128(h_a0.as_mut_ptr() as *mut __m128i, result0_vec);
        _mm_storeu_si128(h_a1.as_mut_ptr() as *mut __m128i, result1_vec);
        
        (S(h_a0), S(h_a1))
    }
}

/// Optimized AES garble function using dual-hash SIMD optimization
#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
pub(super) fn garble_aes_optimized(
    gate_id: GateId,
    gate_type: GateType,
    a: &GarbledWire,
    b: &GarbledWire,
    delta: &Delta,
) -> (S, S) {
    let (alpha_a, alpha_b, alpha_c) = gate_type.alphas();

    // Use optimized dual-hash for AES
    let (h_a0, h_a1) = unsafe {
        aes_dual_hash_gate_with_tweak(a, gate_id, alpha_a)
    };

    let ct = h_a0 ^ &h_a1 ^ &b.select(alpha_b);

    let w = if alpha_c { h_a0 ^ delta } else { h_a0 };

    (ct, w)
}

pub(super) fn garble<H: digest::Digest + Default + Clone>(
    gate_id: GateId,
    gate_type: GateType,
    a: &GarbledWire,
    b: &GarbledWire,
    delta: &Delta,
) -> (S, S) {
    // Try to use AES optimization if available and if we're using an AES-based hasher
    #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
    {
        // Check if H is an AES-based hasher by checking the type name
        let type_name = std::any::type_name::<H>();
        if type_name.contains("AesHasher") || type_name.contains("aes") {
            // Use the optimized AES path
            return garble_aes_optimized(gate_id, gate_type, a, b, delta);
        }
    }
    
    // Fallback to generic implementation
    let (alpha_a, alpha_b, alpha_c) = gate_type.alphas();

    let h_a0 = hash_gate_with_tweak::<H>(&a.select(alpha_a), gate_id);
    let h_a1 = hash_gate_with_tweak::<H>(&a.select(!alpha_a), gate_id);

    let ct = h_a0 ^ &h_a1 ^ &b.select(alpha_b);

    let w = if alpha_c { h_a0 ^ delta } else { h_a0 };

    (ct, w)
}

pub(super) fn degarble<H: digest::Digest + Default + Clone>(
    gate_id: GateId,
    gate_type: GateType,
    ciphertext: &S,
    a: &EvaluatedWire,
    b: &EvaluatedWire,
) -> S {
    let h_a = hash_gate_with_tweak::<H>(&a.active_label, gate_id);

    let (alpha_a, _alpha_b, _alpha_c) = gate_type.alphas();

    if a.value() != alpha_a {
        ciphertext ^ &h_a ^ &b.active_label
    } else {
        h_a // h_a0
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{Delta, GarbledWire, GateType, S, core::gate::GateId, test_utils::trng};

    const GATE_ID: GateId = 0;

    const TEST_CASES: [(bool, bool); 4] =
        [(false, false), (false, true), (true, false), (true, true)];

    fn garble_consistency(gt: GateType) {
        let mut rng = trng();

        let delta = Delta::generate(&mut rng);

        #[derive(Debug, PartialEq, Eq)]
        struct FailedCase {
            a_value: bool,
            b_value: bool,
            c_value: bool,
            c: GarbledWire,
            evaluated: S,
            expected: S,
        }
        let mut failed_cases = Vec::new();

        // Create wires with specific LSB patterns
        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);
        let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
        let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

        // Test all combinations of LSB patterns for label0

        // Create bitmask visualization (16 cases total: 2×2×4)
        let mut bitmask = String::with_capacity(16);

        let (ct, c) = garble::<blake3::Hasher>(GATE_ID, gt, &a, &b, &delta);
        let c = GarbledWire::new(c, c ^ &delta);

        for (a_vl, b_vl) in TEST_CASES {
            let evaluated = degarble::<blake3::Hasher>(
                GATE_ID,
                gt,
                &ct,
                &EvaluatedWire::new_from_garbled(&a, a_vl),
                &EvaluatedWire::new_from_garbled(&b, b_vl),
            );

            let expected = EvaluatedWire::new_from_garbled(&c, (gt.f())(a_vl, b_vl)).active_label;

            if evaluated != expected {
                bitmask.push('0');
                failed_cases.push(FailedCase {
                    c: c.clone(),
                    a_value: a_vl,
                    b_value: b_vl,
                    c_value: (gt.f())(a_vl, b_vl),
                    evaluated,
                    expected,
                });
            } else {
                bitmask.push('1');
            }
        }

        let mut error = String::new();
        error.push_str(&format!("{:?}\n", gt.alphas()));
        error.push_str(&format!(
            "Bitmask: {} ({}/4 failed)\n",
            bitmask,
            failed_cases.len()
        ));
        error.push_str("Order: wire_a_lsb0,wire_b_lsb0,a_value,b_value\n");
        for case in failed_cases.iter() {
            error.push_str(&format!("{case:#?}\n"));
        }

        assert_eq!(&failed_cases, &[], "{error}");
    }

    macro_rules! garble_consistency_tests {
    ($($gate_type:ident => $test_name:ident),*) => {
        $(
            #[test]
            fn $test_name() {
                garble_consistency(GateType::$gate_type);
            }
        )*
    };
}

    garble_consistency_tests!(
        And => garble_consistency_and,
        Nand => garble_consistency_nand,
        Nimp => garble_consistency_nimp,
        Imp => garble_consistency_imp,
        Ncimp => garble_consistency_ncimp,
        Cimp => garble_consistency_cimp,
        Nor => garble_consistency_nor,
        Or => garble_consistency_or
    );

    #[test]
    fn test_different_hash_functions() {
        use sha2::Sha256;

        let mut rng = trng();
        let delta = Delta::generate(&mut rng);

        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);
        let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
        let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

        // Test with Blake3
        let (ct_blake3, _) = garble::<blake3::Hasher>(GATE_ID, GateType::And, &a, &b, &delta);

        // Test with SHA256
        let (ct_sha256, _) = garble::<Sha256>(GATE_ID, GateType::And, &a, &b, &delta);

        // Different hash functions should produce different ciphertexts
        assert_ne!(ct_blake3, ct_sha256);
    }
}
