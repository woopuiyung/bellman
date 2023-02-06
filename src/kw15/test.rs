use super::*;

use group::Group;
use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use crate::mirage::tests::DummyEngine;
use bls12_381::Bls12;

pub fn test_rng() -> Box<dyn RngCore> {
    Box::new(ChaChaRng::from_seed([0u8; 32]))
}

fn random_statement<E: Engine, R: RngCore>(num_cmts: usize, num_wits: usize, rng: &mut R) ->
(Matrix<E>, Vec<E::G1Affine>, Vec<E::Fr>) {
    let mut matrix = Matrix::<E>::new(num_cmts, num_wits);
    for i in 0..num_cmts {
        for j in 0..num_wits {
            matrix.add_entry(i, j, E::G1::random(&mut *rng).into());
        }
    }
    let wits: Vec<E::Fr> = (0..num_wits).map(|_| E::Fr::random(&mut *rng)).collect();
    let mut cmts = vec![E::G1::identity(); num_cmts];
    for (cmt_i, wit_i, value) in matrix.nonzero_entries.iter() {
        cmts[*cmt_i] += value.clone() * wits[*wit_i];
    }
    (matrix, cmts.iter().map(Curve::to_affine).collect(), wits)
}

fn random_test<E>(num_cmts: usize, num_wits: usize)
where
    E: MultiMillerLoop,
    E::Fr: PrimeFieldBits,
{
    let rng = &mut test_rng();
    let (matrix, cmts, wits) = random_statement::<E, _>(num_cmts, num_wits, rng);
    let (pk, vk) = key_gen(&matrix, rng);
    let pf = prove(&pk, &wits);
    let pvk = PreparedVerifyingKey::from(&vk);
    assert!(verify(&pvk, &cmts, &pf));
}

#[test]
fn dummy_one_by_one() {
    random_test::<DummyEngine>(1, 1);
}

#[test]
fn dummy_two_by_ten() {
    random_test::<DummyEngine>(2, 10);
}

#[test]
fn bls12_381_two_by_ten() {
    random_test::<Bls12>(2, 10);
}

fn random_serde_test<E>(num_cmts: usize, num_wits: usize)
where
    E: MultiMillerLoop,
    E::Fr: PrimeFieldBits,
{
    let rng = &mut test_rng();
    let (matrix, _, wits) = random_statement::<E, _>(num_cmts, num_wits, rng);
    let (pk, vk) = key_gen(&matrix, rng);
    let pf = prove(&pk, &wits);
    let mut ser_pk: Vec<u8> = Vec::new();
    let mut ser_vk: Vec<u8> = Vec::new();
    let mut ser_pf: Vec<u8> = Vec::new();
    pk.write(&mut ser_pk).unwrap();
    vk.write(&mut ser_vk).unwrap();
    pf.write(&mut ser_pf).unwrap();
    let pk2 = ProvingKey::<E>::read(&ser_pk[..]).unwrap();
    let vk2 = VerifyingKey::<E>::read(&ser_vk[..]).unwrap();
    let pf2 = Proof::<E>::read(&ser_pf[..]).unwrap();
    assert!(pk == pk2);
    assert!(pf == pf2);
    assert!(vk == vk2);
}

#[test]
fn bls12_381_two_by_ten_serde() {
    random_serde_test::<Bls12>(2, 10);
}
