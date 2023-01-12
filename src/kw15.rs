//! The protocol of [KW15] as described in Appendix D of [LegoSNARK]
//!
//! We use the notation of [LegoSNARK]'s Appendix.
//!
//! See the following:
//! * types:
//!    * [Matrix]
//!    * [ProvingKey]
//!    * [VerifyingKey]
//!    * [Proof]
//! * functions:
//!    * [key_gen]
//!    * [prove]
//!    * [verify]
//!
//! [KW15]: https://eprint.iacr.org/2015/216
//! [LegoSNARK]: https://eprint.iacr.org/2019/142

use crate::curve_io::{GroupReader, GroupWriter};
use crate::multicore::Worker;
use crate::multiexp::{multiexp, Exponent, FullDensity};
use ff::{Field, PrimeFieldBits};
use group::{Curve, Group};
use pairing::{Engine, MillerLoopResult, MultiMillerLoop};
use rand_core::RngCore;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

pub struct Matrix<E: Engine> {
    /// The number of commitments (l)
    num_cmts: usize,
    /// The number of witnesses (t)
    num_wits: usize,
    /// The entries of the matrix: (cmt_i, wit_i, value)
    nonzero_entries: Vec<(usize, usize, E::G1)>,
}

impl<E: Engine> Matrix<E> {
    /// Create a new, all-zero, matrix
    pub fn new(num_cmts: usize, num_wits: usize) -> Self {
        Self {
            num_cmts,
            num_wits,
            nonzero_entries: vec![],
        }
    }
    /// Add `value` to the entry for commitment `cmt_i` and witness `wit_i`.
    pub fn add_entry(&mut self, cmt_i: usize, wit_i: usize, value: E::G1) {
        assert!(cmt_i < self.num_cmts);
        assert!(wit_i < self.num_wits);
        self.nonzero_entries.push((cmt_i, wit_i, value));
    }
}

pub struct ProvingKey<E: Engine> {
    p_g1: Vec<E::G1Affine>,
}

impl<E: Engine> std::cmp::PartialEq for ProvingKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.p_g1 == other.p_g1
    }
}

impl<E: Engine> ProvingKey<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_groups_uncompressed(&self.p_g1)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let p_g1 = reader.read_groups_uncompressed::<E::G1Affine>(false, true)?;
        Ok(ProvingKey { p_g1 })
    }
}

pub struct VerifyingKey<E: Engine> {
    c_g2: Vec<E::G2Affine>,
    a_g2: E::G2Affine,
}

impl<E: Engine> std::cmp::PartialEq for VerifyingKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.a_g2 == other.a_g2 && self.c_g2 == other.c_g2
    }
}

impl<E: Engine> VerifyingKey<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_groups_uncompressed(&self.c_g2)?;
        writer.write_group_uncompressed(&self.a_g2)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let c_g2 = reader.read_groups_uncompressed::<E::G2Affine>(false, true)?;
        let a_g2 = reader.read_group_uncompressed::<E::G2Affine>(false, true)?;
        Ok(VerifyingKey { c_g2, a_g2 })
    }
}

pub struct Proof<E: Engine> {
    pi_g1: E::G1Affine,
}

impl<E: Engine> std::cmp::PartialEq for Proof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.pi_g1 == other.pi_g1
    }
}

impl<E: Engine> Proof<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_group_uncompressed(&self.pi_g1)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let pi_g1 = reader.read_group_uncompressed::<E::G1Affine>(false, true)?;
        Ok(Proof { pi_g1 })
    }
}

pub fn key_gen<E, R>(m: &Matrix<E>, mut rng: &mut R) -> (ProvingKey<E>, VerifyingKey<E>)
where
    E: Engine,
    R: RngCore,
{
    let k: Vec<E::Fr> = (0..m.num_cmts).map(|_| E::Fr::random(&mut rng)).collect();
    let a: E::Fr = E::Fr::random(&mut rng);

    // Compute [P]_1 in parallel
    let p_g1: Arc<Vec<Mutex<E::G1>>> = Arc::new((0..m.num_wits).map(|_| Mutex::new(E::G1::identity())).collect());
    let worker = Worker::new();
    let nonzero_entries = Arc::new(m.nonzero_entries.clone());
    let k_arc = Arc::new(k.clone());
    worker.scope(nonzero_entries.len(), |scope, chunk| {
        for nz in nonzero_entries.chunks(chunk) {
            let p_g1 = p_g1.clone();
            let k_arc = k_arc.clone();
            scope.spawn(move |_scope| {
                for (cmt_i, wit_i, val) in nz {
                    let add = val.clone() * k_arc[*cmt_i];
                    *p_g1[*wit_i].lock().unwrap() += add;
                }
            })
        }
    });

    // Compute vk
    let a_g2 = E::G2::identity() * &a;
    let c_g2: Vec<E::G2> = k
        .into_iter()
        .map(|k_i| E::G2::identity() * (k_i * &a))
        .collect();
    (
        ProvingKey {
            p_g1: p_g1.iter().map(|p| p.lock().unwrap().to_affine()).collect(),
        },
        VerifyingKey {
            a_g2: a_g2.to_affine(),
            c_g2: c_g2.iter().map(Curve::to_affine).collect(),
        },
    )
}

pub fn prove<E>(pk: &ProvingKey<E>, wits: &[E::Fr]) -> Proof<E>
where
    E: Engine,
    E::Fr: PrimeFieldBits,
{
    let worker = Worker::new();
    let bases: Arc<Vec<E::G1Affine>> = Arc::new(pk.p_g1.clone());
    let coeffs: Arc<Vec<Exponent<E::Fr>>> =
        Arc::new(wits.iter().map(|w| Exponent::from(w)).collect());
    assert_eq!(pk.p_g1.len(), coeffs.len());
    let pi_g1: E::G1 = multiexp(&worker, (bases, 0), FullDensity, coeffs)
        .wait()
        .unwrap();
    Proof {
        pi_g1: pi_g1.to_affine(),
    }
}

pub struct PreparedVerifyingKey<E: MultiMillerLoop> {
    c_g2: Vec<E::G2Prepared>,
    neg_a_g2: E::G2Prepared,
}

impl<E: MultiMillerLoop> std::convert::From<&VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(vk: &VerifyingKey<E>) -> Self {
        PreparedVerifyingKey {
            c_g2: vk.c_g2.iter().map(|p| p.clone().into()).collect(),
            neg_a_g2: (-vk.a_g2).into(),
        }
    }
}

pub fn verify<E>(vk: &PreparedVerifyingKey<E>, cmts: &[E::G1Affine], pf: &Proof<E>) -> bool
where
    E: MultiMillerLoop,
{
    assert_eq!(cmts.len(), vk.c_g2.len());
    let mut multi_miller_inputs: Vec<(&E::G1Affine, &E::G2Prepared)> = Vec::new();
    for (cmt, c) in cmts.iter().zip(&vk.c_g2) {
        multi_miller_inputs.push((cmt, c));
    }
    multi_miller_inputs.push((&pf.pi_g1, &vk.neg_a_g2));
    let res = E::multi_miller_loop(multi_miller_inputs.as_slice()).final_exponentiation();
    bool::from(res.is_identity())
}

#[cfg(test)]
mod test;
