use rand_core::RngCore;
use std::ops::{AddAssign, MulAssign};
use std::sync::Arc;

use ff::{Field, PrimeField, PrimeFieldBits};
use group::{prime::PrimeCurveAffine, Curve, UncompressedEncoding};
use merlin::Transcript;
use pairing::Engine;

use super::{merlin_rng, ParameterSource, Proof, VerifyingKey};

use crate::{
    cc::{CcCircuit, CcConstraintSystem},
    ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};

use crate::domain::{EvaluationDomain, Scalar};

use crate::multiexp::{multiexp, DensityTracker, FullDensity};

use crate::multicore::Worker;
use crate::{start_timer, end_timer};

fn eval<S: PrimeField>(
    lc: &LinearCombination<S>,
    mut input_density: Option<&mut DensityTracker>,
    mut aux_density: Option<&mut DensityTracker>,
    input_assignment: &[S],
    aux_assignment: &[S],
) -> S {
    let mut acc = S::zero();

    for &(index, coeff) in lc.0.iter() {
        let mut tmp;

        if !coeff.is_zero_vartime() {
            match index {
                Variable(Index::Input(i)) => {
                    tmp = input_assignment[i];
                    if let Some(ref mut v) = input_density {
                        v.inc(i);
                    }
                }
                Variable(Index::Aux(i)) => {
                    tmp = aux_assignment[i];
                    if let Some(ref mut v) = aux_density {
                        v.inc(i);
                    }
                }
            }

            if coeff != S::one() {
                tmp *= coeff;
            }
            acc += tmp;
        }
    }

    acc
}

pub struct ProvingAssignment<'p, E: Engine, P: ParameterSource<E> + 'p> {
    // Density of queries
    a_aux_density: DensityTracker,
    b_input_density: DensityTracker,
    b_aux_density: DensityTracker,

    // Evaluations of A, B, C polynomials
    a: Vec<Scalar<E::Fr>>,
    b: Vec<Scalar<E::Fr>>,
    c: Vec<Scalar<E::Fr>>,

    // Assignments of variables
    input_assignment: Vec<E::Fr>,
    aux_assignment: Vec<E::Fr>,

    // proof randomness
    kappa_3s: Vec<E::Fr>,
    pi_ds: Vec<E::G1Affine>,
    /// The scalars underlying the pi_ds.
    aux_blocks: Vec<Vec<E::Fr>>,
    vk: &'p VerifyingKey<E>,
    params: &'p mut P,

    /// The length of this is equal to the number of aux blocks.
    /// Each entry indicates the first aux index *after* the block.
    aux_block_indices: Vec<usize>,
    transcript: Transcript,
}

impl<'p, E: Engine, P: ParameterSource<E> + 'p> ConstraintSystem<E::Fr>
    for ProvingAssignment<'p, E, P>
{
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.aux_assignment.push(f()?);
        self.a_aux_density.add_element();
        self.b_aux_density.add_element();

        Ok(Variable(Index::Aux(self.aux_assignment.len() - 1)))
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.input_assignment.push(f()?);
        self.transcript.append_message(
            b"input",
            self.input_assignment.last().unwrap().to_repr().as_ref(),
        );
        self.b_input_density.add_element();

        Ok(Variable(Index::Input(self.input_assignment.len() - 1)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LB: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LC: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.a.push(Scalar(eval(
            &a,
            // Inputs have full density in the A query
            // because there are constraints of the
            // form x * 0 = 0 for each input.
            None,
            Some(&mut self.a_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        )));
        self.b.push(Scalar(eval(
            &b,
            Some(&mut self.b_input_density),
            Some(&mut self.b_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        )));
        self.c.push(Scalar(eval(
            &c,
            // There is no C polynomial query,
            // though there is an (beta)A + (alpha)B + C
            // query for all aux variables.
            // However, that query has full density.
            None,
            None,
            &self.input_assignment,
            &self.aux_assignment,
        )));
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

impl<'p, E: Engine, P: ParameterSource<E> + 'p> CcConstraintSystem<E::Fr>
    for ProvingAssignment<'p, E, P>
where
    E::Fr: PrimeFieldBits,
{
    fn alloc_random<A, AR>(
        &mut self,
        annotation: A,
    ) -> Result<(Variable, Option<E::Fr>), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let mut rng = merlin_rng(&mut self.transcript, b"random");
        let value = E::Fr::random(&mut *rng);
        let var = self.alloc_input(annotation, || Ok(value.clone()))?;
        Ok((var, Some(value)))
    }

    #[allow(unused_variables)]
    fn end_aux_block<A, AR>(&mut self, _annotation: A) -> Result<(), SynthesisError>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let worker = Worker::new();
        let i = self.aux_block_indices.len();
        let start = self.aux_block_indices.last().copied().unwrap_or(0);
        let end = self.aux_assignment.len();
        assert!(end > start);
        self.aux_blocks
            .push(self.aux_assignment[start..end].to_vec());
        let aux_assignment: Arc<Vec<_>> = Arc::new(
            self.aux_assignment[start..end]
                .into_iter()
                .map(|s| s.clone().into())
                .collect::<Vec<_>>(),
        );
        let mut pi_d: E::G1 = multiexp(
            &worker,
            self.params.get_l(end - start, i)?,
            FullDensity,
            aux_assignment,
        )
        .wait()?;
        // [ J_i(s)/delta_i + delta_last * k_i ]_1
        AddAssign::<&E::G1>::add_assign(
            &mut pi_d,
            &(self.vk.deltas_g1.last().unwrap().clone() * self.kappa_3s[i]),
        );
        let pi_d = pi_d.to_affine();
        self.transcript
            .append_message(b"aux_commit", pi_d.to_uncompressed().as_ref());
        self.pi_ds.push(pi_d);
        self.aux_block_indices.push(self.aux_assignment.len());
        Ok(())
    }
}

pub fn create_random_proof<E, C, R, P: ParameterSource<E>>(
    circuit: C,
    params: P,
    mut rng: &mut R,
) -> Result<(Proof<E>, Vec<Vec<E::Fr>>), SynthesisError>
where
    E: Engine,
    E::Fr: PrimeFieldBits,
    C: CcCircuit<E::Fr>,
    R: RngCore,
{
    let r = E::Fr::random(&mut rng);
    let s = E::Fr::random(&mut rng);
    let num_kappa_3s = circuit.num_aux_blocks();
    let kappa_3s: Vec<_> = (0..num_kappa_3s).map(|_| E::Fr::random(&mut rng)).collect();

    create_proof::<E, C, P>(circuit, params, r, s, kappa_3s)
}

#[allow(clippy::many_single_char_names)]
pub fn create_proof<E, C, P: ParameterSource<E>>(
    circuit: C,
    mut params: P,
    r: E::Fr,
    s: E::Fr,
    kappa_3s: Vec<E::Fr>,
) -> Result<(Proof<E>, Vec<Vec<E::Fr>>), SynthesisError>
where
    E: Engine,
    E::Fr: PrimeFieldBits,
    C: CcCircuit<E::Fr>,
{
    assert_eq!(kappa_3s.len(), circuit.num_aux_blocks());

    // we're assuming the arg doesn't matter
    let vk = params.get_vk(1337)?;

    let mut prover = ProvingAssignment {
        a_aux_density: DensityTracker::new(),
        b_input_density: DensityTracker::new(),
        b_aux_density: DensityTracker::new(),
        a: vec![],
        b: vec![],
        c: vec![],
        kappa_3s: kappa_3s.clone(),
        params: &mut params,
        vk: &vk,
        pi_ds: vec![],
        aux_blocks: vec![],
        input_assignment: vec![],
        aux_assignment: vec![],
        aux_block_indices: vec![],
        transcript: Transcript::new(b"mirage_aozdemir_1"),
    };

    prover.alloc_input(|| "", || Ok(E::Fr::one()))?;

    let t_synth = start_timer!(|| "synthesis");
    circuit.synthesize(&mut prover)?;
    end_timer!(t_synth);
    let t_nosynth = start_timer!(|| "post-synth");

    for i in 0..prover.input_assignment.len() {
        prover.enforce(|| "", |lc| lc + Variable(Index::Input(i)), |lc| lc, |lc| lc);
    }

    let worker = Worker::new();

    let t_h = start_timer!(|| "h commit");
    let h = {
        let t_h_coeffs = start_timer!(|| "h coeffs");
        let mut a = EvaluationDomain::from_coeffs(prover.a)?;
        let mut b = EvaluationDomain::from_coeffs(prover.b)?;
        let mut c = EvaluationDomain::from_coeffs(prover.c)?;
        a.ifft(&worker);
        a.coset_fft(&worker);
        b.ifft(&worker);
        b.coset_fft(&worker);
        c.ifft(&worker);
        c.coset_fft(&worker);

        a.mul_assign(&worker, &b);
        drop(b);
        a.sub_assign(&worker, &c);
        drop(c);
        a.divide_by_z_on_coset(&worker);
        a.icoset_fft(&worker);
        let mut a = a.into_coeffs();
        let a_len = a.len() - 1;
        a.truncate(a_len);
        // TODO: parallelize if it's even helpful
        let a = Arc::new(a.into_iter().map(|s| s.0.into()).collect::<Vec<_>>());
        end_timer!(t_h_coeffs);

        multiexp(&worker, prover.params.get_h(a.len())?, FullDensity, a)
    };
    end_timer!(t_h);
    let t = start_timer!(|| "msm setup");

    // TODO: parallelize if it's even helpful
    let input_assignment = Arc::new(
        prover
            .input_assignment
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<_>>(),
    );
    let final_block_aux_assignment = Arc::new({
        let start = prover.aux_block_indices.last().cloned().unwrap_or(0);
        prover.aux_assignment[start..]
            .iter()
            .cloned()
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<_>>()
    });
    let aux_assignment = Arc::new(
        prover
            .aux_assignment
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<_>>(),
    );

    let l = multiexp(
        &worker,
        prover.params.get_l(
            final_block_aux_assignment.len(),
            prover.aux_block_indices.len(),
        )?,
        FullDensity,
        final_block_aux_assignment.clone(),
    );

    let a_aux_density_total = prover.a_aux_density.get_total_density();

    let (a_inputs_source, a_aux_source) = prover
        .params
        .get_a(input_assignment.len(), a_aux_density_total)?;

    let a_inputs = multiexp(
        &worker,
        a_inputs_source,
        FullDensity,
        input_assignment.clone(),
    );
    let a_aux = multiexp(
        &worker,
        a_aux_source,
        Arc::new(prover.a_aux_density),
        aux_assignment.clone(),
    );

    let b_input_density = Arc::new(prover.b_input_density);
    let b_input_density_total = b_input_density.get_total_density();
    let b_aux_density = Arc::new(prover.b_aux_density);
    let b_aux_density_total = b_aux_density.get_total_density();

    let (b_g1_inputs_source, b_g1_aux_source) = prover
        .params
        .get_b_g1(b_input_density_total, b_aux_density_total)?;

    let b_g1_inputs = multiexp(
        &worker,
        b_g1_inputs_source,
        b_input_density.clone(),
        input_assignment.clone(),
    );
    let b_g1_aux = multiexp(
        &worker,
        b_g1_aux_source,
        b_aux_density.clone(),
        aux_assignment.clone(),
    );

    let (b_g2_inputs_source, b_g2_aux_source) = prover
        .params
        .get_b_g2(b_input_density_total, b_aux_density_total)?;

    let b_g2_inputs = multiexp(
        &worker,
        b_g2_inputs_source,
        b_input_density,
        input_assignment,
    );
    let b_g2_aux = multiexp(&worker, b_g2_aux_source, b_aux_density, aux_assignment);

    for i in 0..vk.deltas_g1.len() {
        if bool::from(vk.deltas_g1[i].is_identity() | vk.deltas_g2[i].is_identity()) {
            // If this element is zero, someone is trying to perform a
            // subversion-CRS attack.
            return Err(SynthesisError::UnexpectedIdentity);
        }
    }
    end_timer!(t);
    let t = start_timer!(|| "pre-msm wait");

    let last = vk.deltas_g1.len() - 1;
    let mut g_a = vk.deltas_g1[last] * r;
    AddAssign::<&E::G1Affine>::add_assign(&mut g_a, &vk.alpha_g1);
    let mut g_b = vk.deltas_g2[last] * s;
    AddAssign::<&E::G2Affine>::add_assign(&mut g_b, &vk.beta_g2);
    let mut g_c;
    {
        let mut rs = r;
        rs.mul_assign(&s);

        g_c = vk.deltas_g1[last] * rs;
        let tf = start_timer!(|| "mirage extra group fold");
        for i in 0..kappa_3s.len() {
            AddAssign::<&E::G1>::add_assign(&mut g_c, &(-vk.deltas_g1[i] * kappa_3s[i]));
        }
        end_timer!(tf);
        AddAssign::<&E::G1>::add_assign(&mut g_c, &(vk.alpha_g1 * s));
        AddAssign::<&E::G1>::add_assign(&mut g_c, &(vk.beta_g1 * r));
    }
    end_timer!(t);
    let t = start_timer!(|| "wait for MSMs and fold");
    let mut a_answer = a_inputs.wait()?;
    AddAssign::<&E::G1>::add_assign(&mut a_answer, &a_aux.wait()?);
    AddAssign::<&E::G1>::add_assign(&mut g_a, &a_answer);
    MulAssign::<E::Fr>::mul_assign(&mut a_answer, s);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &a_answer);

    let mut b1_answer: E::G1 = b_g1_inputs.wait()?;
    AddAssign::<&E::G1>::add_assign(&mut b1_answer, &b_g1_aux.wait()?);
    let mut b2_answer = b_g2_inputs.wait()?;
    AddAssign::<&E::G2>::add_assign(&mut b2_answer, &b_g2_aux.wait()?);

    AddAssign::<&E::G2>::add_assign(&mut g_b, &b2_answer);
    MulAssign::<E::Fr>::mul_assign(&mut b1_answer, r);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &b1_answer);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &h.wait()?);
    AddAssign::<&E::G1>::add_assign(&mut g_c, &l.wait()?);
    end_timer!(t);

    let r = Ok((
        Proof {
            a: g_a.to_affine(),
            b: g_b.to_affine(),
            c: g_c.to_affine(),
            ds: prover.pi_ds,
        },
        prover.aux_blocks,
    ));
    end_timer!(t_nosynth);
    r
}
