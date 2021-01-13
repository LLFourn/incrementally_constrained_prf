use chacha20::cipher::NewStreamCipher;
use chacha20::cipher::SyncStreamCipher;
use std::marker::PhantomData;
const MAX_STORAGE: u8 = 49;
pub const ROOT: u64 = (u64::MAX >> (64 - MAX_STORAGE)) - 1;

pub struct SecretKey(pub [u8; 32]);
#[derive(Debug, PartialEq)]
pub struct ConstrainedKey([[u8; 32]; MAX_STORAGE as usize]);

impl Default for ConstrainedKey {
    fn default() -> Self {
        ConstrainedKey([[0u8; 32]; MAX_STORAGE as usize])
    }
}

pub trait Prg32To64 {
    fn generate(input: &[u8; 32]) -> [u8; 64];
    fn go_left(input: &mut [u8; 32]) {
        let output = Self::generate(input);
        input.copy_from_slice(&output[..32]);
    }
    fn go_right(input: &mut [u8; 32]) {
        let output = Self::generate(input);
        input.copy_from_slice(&output[32..]);
    }
}

pub struct ChaCha20;
impl Prg32To64 for ChaCha20 {
    fn generate(input: &[u8; 32]) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let mut chacha = chacha20::ChaCha20::new(input.into(), [0u8; 12].as_ref().into());
        chacha.apply_keystream(&mut bytes[..]);
        bytes
    }
}

pub struct Sha512;
use bitcoin_hashes::sha512;
use bitcoin_hashes::Hash;
impl Prg32To64 for Sha512 {
    fn generate(input: &[u8; 32]) -> [u8; 64] {
        sha512::Hash::hash(&input[..]).into_inner()
    }
}

pub struct IncrementallyConstrainedPrf<P>(PhantomData<P>);
impl<P> Default for IncrementallyConstrainedPrf<P> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P> IncrementallyConstrainedPrf<P>
where
    P: Prg32To64,
{
    pub fn evaluate(&self, sk: &SecretKey, index: u64) -> [u8; 32] {
        let mut output = sk.0.clone();
        Self::_descend(&mut output, index, ROOT);
        output
    }

    fn _descend(node: &mut [u8; 32], mut target: u64, cur_val: u64) {
        let mut left_val = cur_val;

        while left_val != target {
            left_val = (left_val >> 1) - 1;
            if left_val >= target {
                P::go_left(node);
            } else {
                P::go_right(node);
                target -= left_val + 1;
            }
        }
    }

    pub fn constrain(&self, sk: &SecretKey, constraint: u64) -> ConstrainedKey {
        let mut ck = [[0u8; 32]; MAX_STORAGE as usize];
        let mut target = constraint;
        let mut i = 0;
        let mut left_val = ROOT;
        let mut node = sk.0.clone();

        while left_val != target {
            left_val = (left_val >> 1) - 1;
            if left_val >= target {
                P::go_left(&mut node);
            } else {
                ck[i] = node;
                P::go_left(&mut ck[i]);
                i += 1;
                P::go_right(&mut node);
                target -= left_val + 1;
            }
        }
        ck[i] = node;

        ConstrainedKey(ck)
    }

    pub fn increment(
        &self,
        ck: &mut ConstrainedKey,
        next_val: u64,
        next: [u8; 32],
    ) -> Result<(), ()> {
        let mut left_val = ROOT;
        let mut target = next_val;
        let mut i = 0;

        while left_val != target {
            left_val = (left_val >> 1) - 1;
            if left_val < target {
                target -= left_val + 1;
                i += 1;
            }
        }

        if left_val == 0 {
            ck.0[i] = next;
        } else {
            let prg_output = P::generate(&next);

            if &prg_output[..32] != &ck.0[i][..] || &prg_output[32..] != &ck.0[i + 1][..] {
                return Err(());
            }

            ck.0[i] = next;
            ck.0[i + 1] = [0u8; 32];
        }

        Ok(())
    }

    pub fn constrained_eval(
        &self,
        ck: &ConstrainedKey,
        mut constraint: u64,
        mut index: u64,
    ) -> [u8; 32] {
        assert!(index <= constraint);
        let mut res;
        let mut cur_val = ROOT;
        let mut i = 0;

        loop {
            if cur_val == constraint {
                res = ck.0[i];
                Self::_descend(&mut res, index, cur_val);
                break;
            }

            let left_val = (cur_val >> 1) - 1;

            if index > left_val {
                cur_val -= left_val + 2;
                constraint -= left_val + 1;
                index -= left_val + 1;
                i += 1;
            } else if constraint < left_val {
                cur_val = left_val;
            } else {
                res = ck.0[i];
                Self::_descend(&mut res, index, left_val);
                break;
            }
        }

        res
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn debug_prf() {
        let prf = IncrementallyConstrainedPrf::<ChaCha20>::default();
        let sk = SecretKey([42u8; 32]);
        for c in 0..128 {
            let ck = prf.constrain(&sk, c);
            for i in 0..=c {
                assert_eq!(prf.constrained_eval(&ck, c, i), prf.evaluate(&sk, i));
            }
        }

        let mut ck = prf.constrain(&sk, 0);
        for c in 1..128 {
            dbg!(c);
            let next = prf.evaluate(&sk, c);
            prf.increment(&mut ck, c, next).unwrap();
            assert_eq!(ck, prf.constrain(&sk, c));
        }
    }
}
