use super::*;
use crate::mirage::tests::DummyEngine;
use bls12_381::Bls12;
use ff::Field;
use group::Group;

fn rand_ck<E: Engine, R: RngCore>(len: usize, rng: &mut R) -> CommitKey<E> {
    CommitKey::new(
        Arc::new(
            std::iter::repeat_with(|| E::G1::random(&mut *rng).into())
                .take(len)
                .collect(),
        ),
        E::G1::random(&mut *rng).into(),
    )
}

/// Returns (vecs, rands1, rands2, ck1, cks2, cmts1, cmts2)
fn random_statement<E, R>(
    num_cmts: usize,
    len: usize,
    rng: &mut R,
) -> (
    Vec<Vec<E::Fr>>,
    Vec<E::Fr>,
    Vec<E::Fr>,
    CommitKey<E>,
    Vec<CommitKey<E>>,
    Vec<E::G1Affine>,
    Vec<E::G1Affine>,
)
where
    E: Engine,
    R: RngCore,
    E::Fr: PrimeFieldBits,
{
    let ck1 = rand_ck(len, rng);
    let cks2: Vec<_> = std::iter::repeat_with(|| rand_ck(len, rng))
        .take(num_cmts)
        .collect();
    let vecs: Vec<Vec<E::Fr>> = std::iter::repeat_with(|| {
        std::iter::repeat_with(|| E::Fr::random(&mut *rng))
            .take(len)
            .collect()
    })
    .take(num_cmts)
    .collect();
    let rands1: Vec<E::Fr> = std::iter::repeat_with(|| E::Fr::random(&mut *rng))
        .take(num_cmts)
        .collect();
    let rands2: Vec<E::Fr> = std::iter::repeat_with(|| E::Fr::random(&mut *rng))
        .take(num_cmts)
        .collect();
    let cmts1 = vecs
        .iter()
        .zip(&rands1)
        .map(|(vec, rand)| E::G1Affine::from(ck1.commit(&vec, *rand)))
        .collect();
    let cmts2 = vecs
        .iter()
        .zip(&rands1)
        .zip(&cks2)
        .map(|((vec, rand), ck)| E::G1Affine::from(ck.commit(&vec, *rand)))
        .collect();
    (vecs, rands1, rands2, ck1, cks2, cmts1, cmts2)
}

fn random_test<E>(num_cmts: usize, len: usize)
where
    E: MultiMillerLoop,
    E::Fr: PrimeFieldBits,
{
    let rng = &mut crate::kw15::test::test_rng();
    let (vecs, rands1, rands2, ck1, cks2, cmts1, cmts2) =
        random_statement::<E, _>(num_cmts, len, rng);
    let (pk, vk) = key_gen(&ck1, &cks2, rng);
    let pf = prove(&pk, vecs, rands1, rands2);
    assert!(verify(&vk, &cmts1, &cmts2, &pf));
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

fn random_test_serde<E>(num_cmts: usize, len: usize)
where
    E: MultiMillerLoop,
    E::Fr: PrimeFieldBits,
{
    let rng = &mut crate::kw15::test::test_rng();
    let (vecs, rands1, rands2, ck1, cks2, _cmts1, _cmts2) =
        random_statement::<E, _>(num_cmts, len, rng);
    let (pk, vk) = key_gen(&ck1, &cks2, rng);
    let pf = prove(&pk, vecs, rands1, rands2);
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
    random_test_serde::<Bls12>(2, 10);
}
