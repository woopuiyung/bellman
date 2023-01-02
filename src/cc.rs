//! Interface to a commitment-carrying zkSNARK (CC-zkSNARK).

use crate::{ConstraintSystem, SynthesisError, Variable};
use ff::PrimeField;

/// A constraint system builder for a CC-zkSNARK.
pub trait CcConstraintSystem<Scalar: PrimeField>: ConstraintSystem<Scalar> {
    /// Mark all auxiliary variables before this (but after the last block)
    /// as a new "block".
    ///
    /// The CC-zkSNARK will generate a pedersen commitment scheme for these, which is usuable
    /// outside the CC-zkSNARK.
    fn end_aux_block<A, AR>(&mut self, annotation: A) -> Result<(), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>;

    /// Allocate a random variable.
    ///
    /// Returns the variable *and* its scalar value (which is filled only in proving mode).
    fn alloc_random<A, AR>(
        &mut self,
        annotation: A,
    ) -> Result<(Variable, Option<Scalar>), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>;
}

/// For synthesizing a constraint system for a CC-zkSNARK.
pub trait CcCircuit<Scalar: PrimeField> {
    /// Synthesize
    fn synthesize<CS: CcConstraintSystem<Scalar>>(self, cs: &mut CS)
        -> Result<(), SynthesisError>;
    /// How many auxilary blocks will this circuit produce?
    fn num_aux_blocks(&self) -> usize;
}
