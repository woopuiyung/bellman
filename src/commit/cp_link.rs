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
mod test;
