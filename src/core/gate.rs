use crate::bag::*;
use crate::core::utils::{LIMB_LEN, N_LIMBS, bit_to_usize, convert_between_blake3_and_normal_form};
use bitvm::{bigint::U256, hash::blake3::blake3_compute_script_with_limb, treepp::*};
use std::ops::{Add, AddAssign};

#[derive(Clone, Debug, PartialEq)]
pub enum GateType {
    And,
    Or,
    Xor,
    Nand,
    Not,
    Xnor,
    Nimp,
    Nsor,
}

#[derive(Clone)]
pub struct Gate {
    pub wire_a: Rc<RefCell<Wire>>,
    pub wire_b: Rc<RefCell<Wire>>,
    pub wire_c: Rc<RefCell<Wire>>,
    pub gate_type: GateType,
}

impl Gate {
    pub fn new(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
        gate_type: GateType,
    ) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type,
        }
    }

    pub fn and(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::And)
    }

    pub fn nand(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Nand)
    }

    pub fn or(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Or)
    }

    pub fn xor(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Xor)
    }

    pub fn xnor(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Xnor)
    }

    pub fn not(wire_a: Rc<RefCell<Wire>>, wire_c: Rc<RefCell<Wire>>) -> Self {
        Self::new(wire_a.clone(), wire_a.clone(), wire_c, GateType::Not)
    }

    pub fn nimp(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a.clone(), wire_b.clone(), wire_c, GateType::Nimp)
    }

    pub fn nsor(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a.clone(), wire_b.clone(), wire_c, GateType::Nsor)
    }

    pub fn f(&self) -> fn(bool, bool) -> bool {
        match self.gate_type {
            GateType::And => {
                fn and(a: bool, b: bool) -> bool {
                    a & b
                }
                and
            }
            GateType::Or => {
                fn or(a: bool, b: bool) -> bool {
                    a | b
                }
                or
            }
            GateType::Xor => {
                fn xor(a: bool, b: bool) -> bool {
                    a ^ b
                }
                xor
            }
            GateType::Nand => {
                fn nand(a: bool, b: bool) -> bool {
                    !(a & b)
                }
                nand
            }
            GateType::Not => {
                fn not(a: bool, _b: bool) -> bool {
                    !a
                }
                not
            }
            GateType::Xnor => {
                fn xnor(a: bool, b: bool) -> bool {
                    !(a ^ b)
                }
                xnor
            }
            GateType::Nimp => {
                fn nimp(a: bool, b: bool) -> bool {
                    (a) && (!b)
                }
                nimp
            }
            GateType::Nsor => {
                fn nsor(a: bool, b: bool) -> bool {
                    a | (!b)
                }
                nsor
            }
        }
    }

    pub fn evaluation_script(&self) -> Script {
        match self.gate_type {
            GateType::And => script! { OP_BOOLAND },
            GateType::Or => script! { OP_BOOLOR },
            GateType::Xor => script! { OP_NUMNOTEQUAL },
            GateType::Nand => script! { OP_BOOLAND OP_NOT },
            GateType::Not => script! { OP_DROP OP_NOT },
            GateType::Xnor => script! { OP_NUMNOTEQUAL OP_NOT },
            GateType::Nimp => script! { OP_NOT OP_BOOLAND },
            GateType::Nsor => script! { OP_NOT OP_BOOLOR},
        }
    }

    pub fn evaluate(&mut self) {
        self.wire_c.borrow_mut().set((self.f())(
            self.wire_a.borrow().get_value(),
            self.wire_b.borrow().get_value(),
        ));
    }

    pub fn garbled(&self) -> Vec<S> {
        [(false, false), (true, false), (false, true), (true, true)]
            .iter()
            .map(|(i, j)| {
                let k = (self.f())(*i, *j);
                let a = self.wire_a.borrow().select(*i);
                let b = self.wire_b.borrow().select(*j);
                let c = self.wire_c.borrow().select(k);
                S::hash_together(a, b) + c.neg()
            })
            .collect()
    }

    pub fn check_garble(&self, garble: Vec<S>, bit: bool) -> (bool, S) {
        let a = self.wire_a.borrow().get_label();
        let b = self.wire_b.borrow().get_label();
        let index = bit_to_usize(self.wire_a.borrow().get_value())
            + 2 * bit_to_usize(self.wire_b.borrow().get_value());
        let row = garble[index];
        let c = S::hash_together(a, b) + row.neg();
        let hc = c.hash();
        (hc == self.wire_c.borrow().select_hash(bit), c)
    }

    pub fn script(&self, garbled: Vec<S>, correct: bool) -> Script {
        script! {                                                     // a bit_a b bit_b
            { N_LIMBS + 1 } OP_PICK                                   // a bit_a b bit_b bit_a
            OP_OVER                                                   // a bit_a b bit_b bit_a bit_b
            OP_TOALTSTACK OP_TOALTSTACK                               // a bit_a b bit_b | bit_a bit_b
            for _ in 0..N_LIMBS { {2 * N_LIMBS + 1} OP_PICK }         // a bit_a b bit_b a | bit_a bit_b
            for _ in 0..N_LIMBS { {2 * N_LIMBS} OP_PICK }             // a bit_a b bit_b a b | bit_a bit_b
            { U256::toaltstack() } { U256::toaltstack() }             // a bit_a b bit_b | a b bit_a bit_b
            OP_TOALTSTACK { U256::toaltstack() }                      // a bit_a | b bit_b a b bit_a bit_b
            { self.wire_a.borrow().commitment_script() } OP_VERIFY    // | b bit_b a b bit_a bit_b
            { U256::fromaltstack() } OP_FROMALTSTACK                  // b bit_b | a b bit_a bit_b
            { self.wire_b.borrow().commitment_script() } OP_VERIFY    // | a b bit_a bit_b
            { U256::fromaltstack() }                                  // a | b bit_a bit_b
            { convert_between_blake3_and_normal_form() }              // a' | b bit_a bit_b
            { U256::fromaltstack() }                                  // a' b | bit_a bit_b
            { convert_between_blake3_and_normal_form() }              // a' b' | bit_a bit_b
            { blake3_compute_script_with_limb(64, LIMB_LEN) }
            { U256::transform_limbsize(4, LIMB_LEN.into()) }          // hab | bit_a bit_b
            { U256::push_hex(&hex::encode(garbled[0].0)) }
            { U256::push_hex(&hex::encode(garbled[1].0)) }
            { U256::push_hex(&hex::encode(garbled[2].0)) }
            { U256::push_hex(&hex::encode(garbled[3].0)) }            // hab tau0 tau1 tau2 tau3 | bit_a bit_b
            OP_FROMALTSTACK OP_FROMALTSTACK                           // hab tau0 tau1 tau2 tau3 bit_a bit_b
            OP_2DUP OP_TOALTSTACK OP_TOALTSTACK                       // hab tau0 tau1 tau2 tau3 bit_a bit_b | bit_a bit_b
            OP_IF
                OP_IF
                // tau3
                { U256::toaltstack() }
                { U256::drop() }
                { U256::drop() }
                { U256::drop() }
                { U256::fromaltstack() }
                OP_ELSE
                // tau2
                { U256::drop() }
                { U256::toaltstack() }
                { U256::drop() }
                { U256::drop() }
                { U256::fromaltstack() }
                OP_ENDIF
            OP_ELSE
                OP_IF
                // tau1
                { U256::drop() }
                { U256::drop() }
                { U256::toaltstack() }
                { U256::drop() }
                { U256::fromaltstack() }
                OP_ELSE
                // tau0
                { U256::drop() }
                { U256::drop() }
                { U256::drop() }
                OP_ENDIF
            OP_ENDIF                                               // hab tau | bit_a bit_b
            { U256::sub(1, 0) }                                    // c=hab-tau | bit_a bit_b
            OP_FROMALTSTACK OP_FROMALTSTACK                        // c bit_a bit_b
            { self.evaluation_script() }                           // c bit_c
            { self.wire_c.borrow().commitment_script() }
            if correct {
                OP_VERIFY
            }
            else {
                OP_NOT OP_VERIFY
            }
            OP_TRUE
        }
    }
}

pub struct GateCount {
    pub and: usize,
    pub or: usize,
    pub xor: usize,
    pub nand: usize,
    pub not: usize,
    pub xnor: usize,
    pub nimp: usize,
    pub nsor: usize,
}

impl Add for GateCount {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self {
            and: self.and + other.and,
            or: self.or + other.or,
            xor: self.xor + other.xor,
            nand: self.nand + other.nand,
            not: self.not + other.not,
            xnor: self.xnor + other.xnor,
            nimp: self.nimp + other.nimp,
            nsor: self.nsor + other.nsor,
        }
    }
}

impl AddAssign for GateCount {
    fn add_assign(&mut self, other: Self) {
        self.and = self.and + other.and;
        self.or = self.or + other.or;
        self.xor = self.xor + other.xor;
        self.nand = self.nand + other.nand;
        self.not = self.not + other.not;
        self.xnor = self.xnor + other.xnor;
        self.nimp = self.nimp + other.nimp;
        self.nsor = self.nsor + other.nsor;
    }
}

impl GateCount {
    pub fn zero() -> Self {
        Self {
            and: 0,
            or: 0,
            xor: 0,
            nand: 0,
            not: 0,
            xnor: 0,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn total_gate_count(&self) -> usize {
        self.and + self.or + self.xor + self.nand + self.not + self.xnor + self.nimp + self.nsor
    }

    pub fn nonfree_gate_count(&self) -> usize {
        self.and + self.or + self.nand + self.nimp + self.nsor
    }

    pub fn print(&self) {
        println!("and:  {:?}", self.and);
        println!("or:   {:?}", self.or);
        println!("xor:  {:?}", self.xor);
        println!("nand: {:?}", self.nand);
        println!("not:  {:?}", self.not);
        println!("xnor: {:?}", self.xnor);
        println!("nimp: {:?}", self.nimp);
        println!("nsor: {:?}", self.nsor);
        println!();
        println!("total: {:?}", self.total_gate_count());
        println!("nonfree: {:?}", self.nonfree_gate_count());
    }
}

// these are here to speed up tests
impl GateCount {
    pub fn msm() -> Self {
        Self {
            and: 128808400,
            or: 51296850,
            xor: 128326975,
            nand: 213127590,
            not: 123282230,
            xnor: 51296850,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn msm_montgomery() -> Self {
        Self {
            and: 70952000,
            or: 89650,
            xor: 93972175,
            nand: 58898790,
            not: 19856230,
            xnor: 89650,
            nimp: 1078400,
            nsor: 0,
        }
    }

    pub fn fq12_square() -> Self {
        Self {
            and: 9875584,
            or: 3951608,
            xor: 9886180,
            nand: 11911584,
            not: 8004680,
            xnor: 3948560,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_square_montgomery() -> Self {
        Self {
            and: 5536354,
            or: 111068,
            xor: 7309570,
            nand: 344424,
            not: 247730,
            xnor: 108020,
            nimp: 80880,
            nsor: 0,
        }
    }

    pub fn fq12_cyclotomic_square() -> Self {
        Self {
            and: 5903509,
            or: 2357575,
            xor: 5910838,
            nand: 7090410,
            not: 4767360,
            xnor: 2357575,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_cyclotomic_square_montgomery() -> Self {
        Self {
            and: 3299971,
            or: 53251,
            xor: 4364872,
            nand: 150114,
            not: 113190,
            xnor: 53251,
            nimp: 48528,
            nsor: 0,
        }
    }

    pub fn fq12_mul() -> Self {
        Self {
            and: 14793358,
            or: 5916742,
            xor: 14804755,
            nand: 17836896,
            not: 11985288,
            xnor: 5912170,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_mul_montgomery() -> Self {
        Self {
            and: 8284513,
            or: 155932,
            xor: 10939840,
            nand: 486156,
            not: 349863,
            xnor: 151360,
            nimp: 121320,
            nsor: 0,
        }
    }

    pub fn fq12_inverse() -> Self {
        Self {
            and: 37917672,
            or: 12127813,
            xor: 37294593,
            nand: 39307008,
            not: 26014500,
            xnor: 11867464,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_inverse_montgomery() -> Self {
        Self {
            and: 25203015,
            or: 477163,
            xor: 30145479,
            nand: 4991100,
            not: 3002469,
            xnor: 473862,
            nimp: 240452,
            nsor: 0,
        }
    }

    pub fn double_in_place() -> Self {
        Self {
            and: 7285002,
            or: 3000110,
            xor: 7364962,
            nand: 9029700,
            not: 6066530,
            xnor: 3000110,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn double_in_place_montgomery() -> Self {
        Self {
            and: 4227835,
            or: 26095,
            xor: 5678201,
            nand: 72390,
            not: 59755,
            xnor: 26095,
            nimp: 58140,
            nsor: 0,
        }
    }

    pub fn add_in_place() -> Self {
        Self {
            and: 11969527,
            or: 4769941,
            xor: 11941035,
            nand: 14353794,
            not: 9644762,
            xnor: 4769941,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn add_in_place_montgomery() -> Self {
        Self {
            and: 6617810,
            or: 33275,
            xor: 8763216,
            nand: 87630,
            not: 77857,
            xnor: 33275,
            nimp: 99752,
            nsor: 0,
        }
    }

    pub fn ell() -> Self {
        Self {
            and: 13963948,
            or: 5564020,
            xor: 13946983,
            nand: 16741140,
            not: 11250566,
            xnor: 5564020,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn ell_montgomery() -> Self {
        Self {
            and: 7744385,
            or: 59246,
            xor: 10253842,
            nand: 161544,
            not: 132271,
            xnor: 59246,
            nimp: 115928,
            nsor: 0,
        }
    }

    pub fn ell_by_constant() -> Self {
        Self {
            and: 11438002,
            or: 5060584,
            xor: 11962235,
            nand: 15223236,
            not: 10232611,
            xnor: 5060584,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn ell_by_constant_montgomery() -> Self {
        Self {
            and: 7385523,
            or: 58734,
            xor: 10214534,
            nand: 158496,
            not: 130231,
            xnor: 58734,
            nimp: 80920,
            nsor: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate() {
        let wire_1 = new_wirex();
        let wire_2 = new_wirex();
        let wire_3 = new_wirex();
        let gate = Gate::and(wire_1, wire_2, wire_3);

        let correct_garbled = gate.garbled();
        let incorrect_garbled = vec![S::random(), S::random(), S::random(), S::random()];

        for (correct, garbled) in [(true, correct_garbled), (false, incorrect_garbled)] {
            println!(
                "testing {:?} garble",
                if correct { "correct" } else { "incorrect" }
            );
            for (bit_a, bit_b) in [(false, false), (true, false), (false, true), (true, true)] {
                let a = gate.wire_a.borrow().select(bit_a);
                let b = gate.wire_b.borrow().select(bit_b);
                let gate_script = gate.script(garbled.clone(), correct);
                let script = script! {
                    { U256::push_hex(&hex::encode(a.0)) }
                    { if bit_a {1} else {0} }
                    { U256::push_hex(&hex::encode(b.0)) }
                    { if bit_b {1} else {0} }
                    { gate_script }
                };
                println!("script len: {:?}", script.len());
                let result = execute_script(script);
                assert!(result.success);
            }
        }
    }
}
