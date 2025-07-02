use blake3::hash;
use rand::{Rng, rng};
use std::{
    iter::zip,
    ops::{Add, BitXor},
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct S(pub [u8; 32]);

impl S {
    pub const fn one() -> Self {
        let mut s = [0_u8; 32];
        s[31] = 1;
        Self(s)
    }

    pub fn random() -> Self {
        Self(rng().random::<[u8; 32]>())
    }

    pub fn neg(&self) -> Self {
        let mut s = self.0;
        for (i, si) in s.iter_mut().enumerate() {
            *si = 255 - self.0[i];
        }
        Self(s) + Self::one()
    }

    pub fn hash(&self) -> Self {
        Self(*hash(&self.0).as_bytes())
    }

    pub fn hash_together(a: Self, b: Self) -> Self {
        let mut h = a.0.to_vec();
        h.extend(b.0.to_vec());
        Self(*hash(&h).as_bytes())
    }
}

impl Add for S {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut s = [0_u8; 32];
        let mut carry = 0;
        for (i, (u, v)) in zip(self.0, rhs.0).enumerate().rev() {
            let x = (u as u32) + (v as u32) + carry;
            s[i] = (x % 256) as u8;
            carry = x / 256;
        }
        Self(s)
    }
}

impl BitXor for &S {
    type Output = S;

    fn bitxor(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl AsRef<[u8]> for S {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvm::{bigint::U256, treepp::*};

    #[test]
    fn test_s() {
        let a = S::random();
        let b = S::random();
        let c = a + b;
        let d = a.neg();

        let script = script! {
            { U256::push_hex(&hex::encode(a.0)) }
            { U256::push_hex(&hex::encode(b.0)) }
            { U256::add(0, 1) }
            { U256::push_hex(&hex::encode(c.0)) }
            { U256::equalverify(0, 1) }
            { U256::push_hex(&hex::encode(a.0)) }
            { U256::push_hex(&hex::encode(d.0)) }
            { U256::add(0, 1) }
            { U256::push_hex(&hex::encode([0_u8; 32])) }
            { U256::equalverify(0, 1) }
            OP_TRUE
        };
        println!("script len: {:?}", script.len());
        let result = execute_script(script);
        assert!(result.success);
    }
}
