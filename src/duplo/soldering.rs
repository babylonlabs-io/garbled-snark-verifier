use super::*;

/// Represents a soldering instruction from an output wire to an input wire.
/// Contains decommitment material required for evaluator to adjust labels.
pub struct SolderingEdge {
    /// XOR of 0-keys: S = A0 ⊕ B0
    pub key_xor: S,

    /// XOR of Δ values: Δ₁ ⊕ Δ₂
    //pub delta_xor: S,

    /// XOR of σ (indicator bits): σ₁ ⊕ σ₂
    //pub sigma_xor: bool,

    /// Commitment to key_xor for verification
    pub key_xor_commitment: commitment::XorHomomorphic,
    ///// Commitment to delta_xor
    //pub delta_xor_commitment: commitment::XorHomomorphic,
    // Commitment to sigma_xor
    //pub sigma_xor_commitment: commitment::XorHomomorphic,
}

/// Performs soldering between two wirex values from different components,
/// producing a soldering edge containing XORs and their commitments.
pub fn solder_wire(
    output_wire: &Wirex,
    //output_delta: &S,
    //output_sigma: bool,
    input_wire: &Wirex,
    //input_delta: &S,
    //input_sigma: bool,
) -> SolderingEdge {
    // Compute S = A0 ⊕ B0
    // Full will be: S_K = A^0 ⊕ B^0 ⊕ (σ_i ⊕ σ_j)·Δ_j
    let key_xor = output_wire
        .borrow()
        .label0
        .bitxor(&input_wire.borrow().label0);

    // ∆₁ ⊕ ∆₂
    //let delta_xor = output_delta.bitxor(input_delta);

    // σ₁ ⊕ σ₂
    //let sigma_xor = output_sigma ^ input_sigma;

    // Commit to all of the above
    let key_xor_commitment = commitment::XorHomomorphic::commit(&key_xor);
    //let delta_xor_commitment = commitment::XorHomomorphic::commit(&delta_xor);
    //let sigma_xor_commitment = commitment::XorHomomorphic::commit(&([sigma_xor as u8]));

    SolderingEdge {
        key_xor,
        //delta_xor,
        //sigma_xor,
        key_xor_commitment,
        //delta_xor_commitment,
        //sigma_xor_commitment,
    }
}

pub fn solder_component_pair(
    output_component: &GarbledComponent,
    input_component: &GarbledComponent,
    connection: &[(WireId, WireId)],
) -> Vec<SolderingEdge> {
    connection
        .iter()
        .map(|(out_idx, in_idx)| {
            let out_wire = output_component.inner.get_output_wire(*out_idx).unwrap();
            let in_wire = input_component.inner.get_input_wire(*in_idx).unwrap();

            solder_wire(
                out_wire,
                //&output_component.delta,
                //out_wire.sigma_bit,
                in_wire,
                //&input_component.delta,
                //in_wire.sigma_bit,
            )
        })
        .collect()
}
