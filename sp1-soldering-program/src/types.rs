use rkyv::{Archive, Deserialize, Serialize};

#[repr(C, align(16))]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq))]
pub struct Wire {
    pub label0: u128,
    pub label1: u128,
}

impl Wire {
    #[inline]
    pub const fn new(label0: u128, label1: u128) -> Self {
        Self { label0, label1 }
    }
}

impl From<(u128, u128)> for Wire {
    #[inline]
    fn from((label0, label1): (u128, u128)) -> Self {
        Self::new(label0, label1)
    }
}

impl From<Wire> for (u128, u128) {
    #[inline]
    fn from(w: Wire) -> Self {
        (w.label0, w.label1)
    }
}

#[repr(C, align(16))]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq))]
pub struct WireDelta {
    pub delta0: u128,
    pub delta1: u128,
}

impl WireDelta {
    #[inline]
    pub const fn new(delta0: u128, delta1: u128) -> Self {
        Self { delta0, delta1 }
    }
}

impl From<(u128, u128)> for WireDelta {
    #[inline]
    fn from((delta0, delta1): (u128, u128)) -> Self {
        Self::new(delta0, delta1)
    }
}

impl From<WireDelta> for (u128, u128) {
    #[inline]
    fn from(delta: WireDelta) -> Self {
        (delta.delta0, delta.delta1)
    }
}

pub type InstancesWires = Vec<Wire>;
pub type Sha256Commit = [u8; 32];

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[rkyv(derive(Debug))]
pub struct WiresInput {
    pub instances_wires: Vec<InstancesWires>,
    pub nonce: u128,
}

#[repr(C, align(16))]
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct SolderedLabelsData {
    pub deltas: Vec<Vec<WireDelta>>,
    pub base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    pub base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    pub nonce: u128,
    pub commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
}
