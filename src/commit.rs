//! Pedersen commitments

use ff::PrimeFieldBits;
use pairing::Engine;
use std::sync::Arc;

use crate::multicore::Worker;
use crate::multiexp::{multiexp, FullDensity};

pub mod cp_link;

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
