#![allow(dead_code)]

use std::ops::BitXor;

pub mod commitment;
pub mod soldering;

use crate::bag::{Circuit as SubCircuit, Wirex, S};

pub type Id = u128;
pub type WireId = usize;

pub struct Component {
    id: Id,
    inputs: Vec<WireId>,
    outputs: Vec<WireId>,
    sub_circuit: SubCircuit,
    delta: S,
}

impl Component {
    pub fn get_input_wire(&self, wire_id: usize) -> Option<&Wirex> {
        self.inputs
            .get(wire_id)
            .and(self.sub_circuit.0.get(wire_id))
    }

    pub fn get_output_wire(&self, wire_id: usize) -> Option<&Wirex> {
        self.outputs
            .get(wire_id)
            .and(self.sub_circuit.0.get(wire_id))
    }

    pub fn inputs(&self) -> impl Iterator<Item = &Wirex> {
        self.inputs
            .iter()
            .filter_map(|index| self.sub_circuit.0.get(*index))
    }

    pub fn outputs(&self) -> impl Iterator<Item = &Wirex> {
        self.outputs
            .iter()
            .filter_map(|index| self.sub_circuit.0.get(*index))
    }
}

pub struct GarbledComponent {
    /// Structural template (meta-information about components and relationships)
    pub inner: Component,

    /// Indicator bits σ
    //pub sigma_bits: Vec<bool>,

    /// XOR-homomomorphic commits for A⁰
    pub wire_key_commitments: Vec<commitment::XorHomomorphic>,

    ///// XOR-homomomorphic commits for σ
    //pub sigma_commitments: Vec<commitment::XorHomomorphic>,

    ///// Value ∆
    //pub delta: S,
    //
    ///// Pedersen-коммитмент к ∆
    //pub delta_commitment: commitment::Pedersen,
    //
    ///// Opening ∆ for Pedersen (needed to prove knowledge of ∆)
    //pub delta_opening: Option<commitment::Pedersen>,
    /// Instance identifier (inside the bucket)
    pub index_in_bucket: usize,
}

impl GarbledComponent {
    pub fn get_wire_zero_keys(&self) -> Vec<S> {
        todo!()
    }
}

pub struct Circuit {
    components: Vec<Component>,
}
