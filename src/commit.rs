//! Pedersen commitments

use ff::PrimeFieldBits;
use pairing::Engine;
use std::sync::Arc;

use crate::multicore::Worker;
use crate::multiexp::{multiexp, FullDensity};

/// A commitment key
pub struct CommitKey<E: Engine> {
    generators: Arc<Vec<E::G1Affine>>,
    blind_generator: E::G1Affine,
}

impl<E> CommitKey<E>
where
    E: Engine,
{
    /// Create a new commmitment key.
    pub fn new(generators: Arc<Vec<E::G1Affine>>, blind_generator: E::G1Affine) -> Self {
        Self {
            generators,
            blind_generator,
        }
    }
}

impl<E> CommitKey<E>
where
    E: Engine,
    E::Fr: PrimeFieldBits,
{
    /// Commit to a list of values, with some blind.
    pub fn commit(&self, values: &[E::Fr], blind: E::Fr) -> E::G1 {
        let worker = Worker::new();
        let exponents = Arc::new(
            values
                .into_iter()
                .map(|s| s.clone().into())
                .collect::<Vec<_>>(),
        );
        let mut commitment: E::G1 = multiexp(
            &worker,
            (self.generators.clone(), 0),
            FullDensity,
            exponents,
        )
        .wait()
        .unwrap();
        commitment += &(self.blind_generator * blind);
        commitment
    }
}

pub mod cp_link {
    /// Relation:
    /// * Index
    ///   * K be a commitment key to a length-n vector
    ///   * Ji be commitment keys for i in 0..k
    /// * Instance: (Ci, Di) for i in 0..k
    /// * Witness: Xi (vector of length-n) for i in 0..k, ri for i in 0..k
    /// * Relation: Ci = Commit(K, Xi, ri) and Di = Commit(Ji, Xi, ri)
    use super::*;
    use crate::kw15;
    use pairing::MultiMillerLoop;
    use rand_core::RngCore;

    type ProvingKey<E> = kw15::ProvingKey<E>;
    type VerifyingKey<E> = kw15::VerifyingKey<E>;
    type Proof<E> = kw15::Proof<E>;

    pub fn key_gen<E, R>(
        k: &CommitKey<E>,
        js: &[CommitKey<E>],
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        E: Engine,
        R: RngCore,
    {
        let n_commits = 2 * js.len();
        let len = k.generators.len();
        let n_wits = (len + 2) * js.len();
        let mut matrix = kw15::Matrix::new(n_commits, n_wits);
        // witness layout: repeat(vec || rand_1 || rand_2)
        // commitments layout: repeat(com_1 || com_2)
        for vec_i in 0..js.len() {
            let cmt_i_1 = 2 * vec_i;
            let cmt_i_2 = 2 * vec_i + 1;
            let wit_i_start = (len + 2) * vec_i;
            let rand_i_1 = (len + 2) * vec_i + len;
            let rand_i_2 = (len + 2) * vec_i + len + 1;
            for j in 0..len {
                let wit_i = wit_i_start + j;
                matrix.add_entry(cmt_i_1, wit_i, k.generators[j]);
                matrix.add_entry(cmt_i_1, wit_i, js[vec_i].generators[j]);
            }
            matrix.add_entry(cmt_i_1, rand_i_1, k.blind_generator);
            matrix.add_entry(cmt_i_2, rand_i_2, js[vec_i].blind_generator);
        }
        kw15::key_gen(&matrix, rng)
    }

    pub fn prove<E>(
        pk: &ProvingKey<E>,
        vectors: Vec<Vec<E::Fr>>,
        rands_1: Vec<E::Fr>,
        rands_2: Vec<E::Fr>,
    ) -> Proof<E>
    where
        E: Engine,
        E::Fr: PrimeFieldBits,
    {
        let mut wit: Vec<E::Fr> = Vec::new();
        for ((vec, r1), r2) in vectors.into_iter().zip(rands_1).zip(rands_2) {
            wit.extend(vec);
            wit.push(r1);
            wit.push(r2);
        }
        kw15::prove(pk, &wit)
    }

    pub fn verify<E>(
        vk: &VerifyingKey<E>,
        cmts_1: &[E::G1Affine],
        cmts_2: &[E::G1Affine],
        pf: &Proof<E>,
    ) -> bool
    where
        E: MultiMillerLoop,
    {
        let mut cmts: Vec<E::G1Affine> = Vec::new();
        for (c1, c2) in cmts_1.into_iter().zip(cmts_2) {
            cmts.push(*c1);
            cmts.push(*c2);
        }
        let pvk = kw15::PreparedVerifyingKey::from(vk);
        kw15::verify(&pvk, &cmts, pf)
    }

    #[cfg(test)]
    mod test {
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
    }
}
