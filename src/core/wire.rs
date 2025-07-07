use std::sync::OnceLock;

use bitvm::{bigint::U256, hash::blake3::blake3_compute_script_with_limb, treepp::*};

use crate::core::{
    s::S,
    utils::{convert_between_blake3_and_normal_form, LIMB_LEN, N_LIMBS},
};

static DELTA: OnceLock<S> = OnceLock::new();

/// Returns the global Free-XOR delta constant used to derive `label1` from `label0` on each wire.
///
/// In Free-XOR garbling schemes, every wire label pair is generated as:
/// `label1 = label0 ⊕ Δ`, where Δ is a fixed global secret known only to the garbler.
/// This function exposes that Δ, which must:
/// - be sampled once per garbled circuit,
/// - have its least significant bit (LSB) set to 1 to preserve point-and-permute semantics,
/// - remain hidden from the evaluator.
///
/// # Returns
/// A reference to the global `S` value representing Δ.
///
/// # Panics
/// Never panics. Initialized lazily on first access.
pub fn get_delta() -> &'static S {
    DELTA.get_or_init(|| {
        let mut d = S::random();
        d.0[0] |= 1;
        d
    })
}

#[derive(Clone, Debug)]
pub struct Wire {
    pub label0: S,
    pub label1: S,
    pub hash0: S,
    pub hash1: S,
    pub value: Option<bool>,
    pub label: Option<S>,
}

impl Default for Wire {
    fn default() -> Self {
        Self::new()
    }
}

impl Wire {
    pub fn new() -> Self {
        let label0 = S::random();

        // free-XOR: label1 = label0 ^ Δ
        let label1 = label0 ^ get_delta();

        let hash0 = label0.hash();
        let hash1 = label1.hash();

        Self {
            label0,
            label1,
            hash0,
            hash1,
            value: None,
            label: None,
        }
    }

    pub fn select(&self, selector: bool) -> S {
        if selector {
            self.label1
        } else {
            self.label0
        }
    }

    pub fn select_hash(&self, selector: bool) -> S {
        if selector {
            self.hash1
        } else {
            self.hash0
        }
    }

    pub fn get_value(&self) -> bool {
        assert!(self.value.is_some());
        self.value.unwrap()
    }

    pub fn get_label(&self) -> S {
        assert!(self.value.is_some());
        self.label.unwrap()
    }

    pub fn set(&mut self, bit: bool) {
        assert!(self.value.is_none());
        self.value = Some(bit);
        self.label = Some(self.select(bit));
    }

    pub fn set2(&mut self, bit: bool, label: S) {
        assert!(self.value.is_none());
        self.value = Some(bit);
        self.label = Some(label);
    }

    /// Sets the wire’s `(label0, label1)` pair and their corresponding hashes.
    ///
    /// This is used during garbling to explicitly define the labels for a wire,
    /// typically an output of a gate. In FreeXOR-compatible garbling schemes,
    /// output wire labels for XOR and XNOR gates must be **deterministically derived**
    /// from the input labels (e.g., `label_c = label_a ⊕ label_b`) — not generated randomly.
    ///
    /// This method enforces single assignment. It must only be called once per wire.
    ///
    /// # Panics
    /// Panics if the wire has already been assigned (i.e., if `.label` is set or it has been evaluated).
    ///
    /// # Usage
    /// This is **not** for input wires or logical value assignment.  
    /// Use [`Wire::set`] to assign logical input values for evaluation.
    pub fn set_label_pair_and_hash(&mut self, label0: S, label1: S) {
        assert_eq!(self.value, None);
        assert_eq!(self.label, None);

        self.label0 = label0;
        self.label1 = label1;
        self.hash0 = label0.hash();
        self.hash1 = label1.hash();
    }

    pub fn commitment_script(&self) -> Script {
        script! {                                                  // x bit_x
            OP_TOALTSTACK                                          // x | bit_x
            { convert_between_blake3_and_normal_form() }
            for _ in 0..N_LIMBS {0}                                // x'0 | bit_x
            { blake3_compute_script_with_limb(32, LIMB_LEN) }
            { U256::transform_limbsize(4, LIMB_LEN.into()) }       // hx | bit_x
            OP_FROMALTSTACK                                        // hx bit_x
            OP_IF
                { U256::push_hex(&hex::encode(self.hash1.0)) }
            OP_ELSE
                { U256::push_hex(&hex::encode(self.hash0.0)) }
            OP_ENDIF                                               // hx hash
            { U256::equal(0, 1) }
        }
    }
}
