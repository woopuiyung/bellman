use ff::{Field, PrimeField};

mod dummy_engine;
pub use self::dummy_engine::*;

use std::marker::PhantomData;
use std::ops::{AddAssign, MulAssign, SubAssign};

use crate::cc::{CcCircuit, CcConstraintSystem};
use crate::SynthesisError;

use super::{create_proof, generate_parameters, prepare_verifying_key, verify_proof};

struct XorDemo<Scalar: PrimeField> {
    a: Option<bool>,
    b: Option<bool>,
    _marker: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> CcCircuit<Scalar> for XorDemo<Scalar> {
    fn synthesize<CS: CcConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let a_var = cs.alloc(
            || "a",
            || {
                if self.a.is_some() {
                    if self.a.unwrap() {
                        Ok(Scalar::one())
                    } else {
                        Ok(Scalar::zero())
                    }
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "a_boolean_constraint",
            |lc| lc + CS::one() - a_var,
            |lc| lc + a_var,
            |lc| lc,
        );

        let b_var = cs.alloc(
            || "b",
            || {
                if self.b.is_some() {
                    if self.b.unwrap() {
                        Ok(Scalar::one())
                    } else {
                        Ok(Scalar::zero())
                    }
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "b_boolean_constraint",
            |lc| lc + CS::one() - b_var,
            |lc| lc + b_var,
            |lc| lc,
        );

        let c_var = cs.alloc_input(
            || "c",
            || {
                if self.a.is_some() && self.b.is_some() {
                    if self.a.unwrap() ^ self.b.unwrap() {
                        Ok(Scalar::one())
                    } else {
                        Ok(Scalar::zero())
                    }
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        cs.enforce(
            || "c_xor_constraint",
            |lc| lc + a_var + a_var,
            |lc| lc + b_var,
            |lc| lc + a_var + b_var - c_var,
        );

        Ok(())
    }

    fn num_aux_blocks(&self) -> usize {
        0
    }
}

#[test]
fn test_xordemo() {
    let g1 = Fr::one();
    let g2 = Fr::one();
    let alpha = Fr::from(48577);
    let beta = Fr::from(22580);
    let gamma = Fr::from(53332);
    let delta = Fr::from(5481);
    let tau = Fr::from(3673);

    let params = {
        let c = XorDemo {
            a: None,
            b: None,
            _marker: PhantomData,
        };

        generate_parameters::<DummyEngine, _>(c, g1, g2, alpha, beta, gamma, vec![delta], tau)
            .unwrap()
    };

    // This will synthesize the constraint system:
    //
    // public inputs: a_0 = 1, a_1 = c
    // aux inputs: a_2 = a, a_3 = b
    // constraints:
    //     (a_0 - a_2) * (a_2) = 0
    //     (a_0 - a_3) * (a_3) = 0
    //     (a_2 + a_2) * (a_3) = (a_2 + a_3 - a_1)
    //     (a_0) * 0 = 0
    //     (a_1) * 0 = 0

    // The evaluation domain is 8. The H query should
    // have 7 elements (it's a quotient polynomial)
    assert_eq!(7, params.h.len());

    let mut root_of_unity = Fr::root_of_unity();

    // We expect this to be a 2^10 root of unity
    assert_eq!(Fr::one(), root_of_unity.pow_vartime(&[1u64 << 10]));

    // Let's turn it into a 2^3 root of unity.
    root_of_unity = root_of_unity.pow_vartime(&[1u64 << 7]);
    assert_eq!(Fr::one(), root_of_unity.pow_vartime(&[1u64 << 3]));
    assert_eq!(Fr::from(20201), root_of_unity);

    // Let's compute all the points in our evaluation domain.
    let mut points = Vec::with_capacity(8);
    for i in 0u64..8 {
        points.push(root_of_unity.pow_vartime(&[i]));
    }

    // Let's compute t(tau) = (tau - p_0)(tau - p_1)...
    //                      = tau^8 - 1
    let mut t_at_tau = tau.pow_vartime(&[8u64]);
    t_at_tau.sub_assign(&Fr::one());
    {
        let mut tmp = Fr::one();
        for p in &points {
            let mut term = tau;
            term.sub_assign(p);
            tmp.mul_assign(&term);
        }
        assert_eq!(tmp, t_at_tau);
    }

    // We expect our H query to be 7 elements of the form...
    // {tau^i t(tau) / delta}
    let delta_inverse = delta.invert().unwrap();
    let gamma_inverse = gamma.invert().unwrap();
    {
        let mut coeff = delta_inverse;
        coeff.mul_assign(&t_at_tau);

        let mut cur = Fr::one();
        for h in params.h.iter() {
            let mut tmp = cur;
            tmp.mul_assign(&coeff);

            assert_eq!(*h, tmp);

            cur.mul_assign(&tau);
        }
    }

    // The density of the IC query is 2 (2 inputs)
    assert_eq!(2, params.vk.ic.len());

    // The density of the L query is 2 (2 aux variables)
    assert_eq!(2, params.ls[0].len());

    // The density of the A query is 4 (each variable is in at least one A term)
    assert_eq!(4, params.a.len());

    // The density of the B query is 2 (two variables are in at least one B term)
    assert_eq!(2, params.b_g1.len());
    assert_eq!(2, params.b_g2.len());

    /*
    Lagrange interpolation polynomials in our evaluation domain:

    ,-------------------------------. ,-------------------------------. ,-------------------------------.
    |            A TERM             | |            B TERM             | |            C TERM             |
    `-------------------------------. `-------------------------------' `-------------------------------'
    | a_0   | a_1   | a_2   | a_3   | | a_0   | a_1   | a_2   | a_3   | | a_0   | a_1   | a_2   | a_3   |
    | 1     | 0     | 64512 | 0     | | 0     | 0     | 1     | 0     | | 0     | 0     | 0     | 0     |
    | 1     | 0     | 0     | 64512 | | 0     | 0     | 0     | 1     | | 0     | 0     | 0     | 0     |
    | 0     | 0     | 2     | 0     | | 0     | 0     | 0     | 1     | | 0     | 64512 | 1     | 1     |
    | 1     | 0     | 0     | 0     | | 0     | 0     | 0     | 0     | | 0     | 0     | 0     | 0     |
    | 0     | 1     | 0     | 0     | | 0     | 0     | 0     | 0     | | 0     | 0     | 0     | 0     |
    `-------'-------'-------'-------' `-------'-------'-------'-------' `-------'-------'-------'-------'

    Example for u_0:

    sage: r = 64513
    sage: Fr = GF(r)
    sage: omega = (Fr(5)^63)^(2^7)
    sage: tau = Fr(3673)
    sage: R.<x> = PolynomialRing(Fr, 'x')
    sage: def eval(tau, c0, c1, c2, c3, c4):
    ....:     p = R.lagrange_polynomial([(omega^0, c0), (omega^1, c1), (omega^2, c2), (omega^3, c3), (omega^4, c4), (omega^5, 0), (omega^6, 0), (omega^7, 0)])
    ....:     return p.substitute(tau)
    sage: eval(tau, 1, 1, 0, 1, 0)
    59158
    */

    let u_i = [59158, 48317, 21767, 10402]
        .iter()
        .map(|e| Fr::from(*e))
        .collect::<Vec<Fr>>();
    let v_i = [0, 0, 60619, 30791]
        .iter()
        .map(|e| Fr::from(*e))
        .collect::<Vec<Fr>>();
    let w_i = [0, 23320, 41193, 41193]
        .iter()
        .map(|e| Fr::from(*e))
        .collect::<Vec<Fr>>();

    for (u, a) in u_i.iter().zip(&params.a[..]) {
        assert_eq!(u, a);
    }

    for (v, b) in v_i
        .iter()
        .filter(|&&e| e != Fr::zero())
        .zip(&params.b_g1[..])
    {
        assert_eq!(v, b);
    }

    for (v, b) in v_i
        .iter()
        .filter(|&&e| e != Fr::zero())
        .zip(&params.b_g2[..])
    {
        assert_eq!(v, b);
    }

    for i in 0..4 {
        let mut tmp1 = beta;
        tmp1.mul_assign(&u_i[i]);

        let mut tmp2 = alpha;
        tmp2.mul_assign(&v_i[i]);

        tmp1.add_assign(&tmp2);
        tmp1.add_assign(&w_i[i]);

        if i < 2 {
            // Check the correctness of the IC query elements
            tmp1.mul_assign(&gamma_inverse);

            assert_eq!(tmp1, params.vk.ic[i]);
        } else {
            // Check the correctness of the L query elements
            tmp1.mul_assign(&delta_inverse);

            assert_eq!(tmp1, params.ls[0][i - 2]);
        }
    }

    // Check consistency of the other elements
    assert_eq!(alpha, params.vk.alpha_g1);
    assert_eq!(beta, params.vk.beta_g1);
    assert_eq!(beta, params.vk.beta_g2);
    assert_eq!(gamma, params.vk.gamma_g2);
    assert_eq!(delta, params.vk.deltas_g1[0]);
    assert_eq!(delta, params.vk.deltas_g2[0]);

    let pvk = prepare_verifying_key(&params.vk);
    assert_eq!(-delta.clone(), pvk.neg_deltas_g2[0]);
    assert_eq!(-gamma.clone(), pvk.neg_gamma_g2);

    let r = Fr::from(27134);
    let s = Fr::from(17146);

    let proof = {
        let c = XorDemo {
            a: Some(true),
            b: Some(false),
            _marker: PhantomData,
        };

        create_proof(c, &params, r, s, vec![]).unwrap()
    };

    // A(x) =
    //  a_0 * (44865*x^7 + 56449*x^6 + 44865*x^5 + 8064*x^4 + 3520*x^3 + 56449*x^2 + 3520*x + 40321) +
    //  a_1 * (8064*x^7 + 56449*x^6 + 8064*x^5 + 56449*x^4 + 8064*x^3 + 56449*x^2 + 8064*x + 56449) +
    //  a_2 * (16983*x^7 + 24192*x^6 + 63658*x^5 + 56449*x^4 + 16983*x^3 + 24192*x^2 + 63658*x + 56449) +
    //  a_3 * (5539*x^7 + 27797*x^6 + 6045*x^5 + 56449*x^4 + 58974*x^3 + 36716*x^2 + 58468*x + 8064) +
    {
        // proof A = alpha + A(tau) + delta * r
        let mut expected_a = delta;
        expected_a.mul_assign(&r);
        expected_a.add_assign(&alpha);
        expected_a.add_assign(&u_i[0]); // a_0 = 1
        expected_a.add_assign(&u_i[1]); // a_1 = 1
        expected_a.add_assign(&u_i[2]); // a_2 = 1
                                        // a_3 = 0
        assert_eq!(proof.a, expected_a);
    }

    // B(x) =
    // a_0 * (0) +
    // a_1 * (0) +
    // a_2 * (56449*x^7 + 56449*x^6 + 56449*x^5 + 56449*x^4 + 56449*x^3 + 56449*x^2 + 56449*x + 56449) +
    // a_3 * (31177*x^7 + 44780*x^6 + 21752*x^5 + 42255*x^3 + 35861*x^2 + 33842*x + 48385)
    {
        // proof B = beta + B(tau) + delta * s
        let mut expected_b = delta;
        expected_b.mul_assign(&s);
        expected_b.add_assign(&beta);
        expected_b.add_assign(&v_i[0]); // a_0 = 1
        expected_b.add_assign(&v_i[1]); // a_1 = 1
        expected_b.add_assign(&v_i[2]); // a_2 = 1
                                        // a_3 = 0
        assert_eq!(proof.b, expected_b);
    }

    // C(x) =
    // a_0 * (0) +
    // a_1 * (27797*x^7 + 56449*x^6 + 36716*x^5 + 8064*x^4 + 27797*x^3 + 56449*x^2 + 36716*x + 8064) +
    // a_2 * (36716*x^7 + 8064*x^6 + 27797*x^5 + 56449*x^4 + 36716*x^3 + 8064*x^2 + 27797*x + 56449) +
    // a_3 * (36716*x^7 + 8064*x^6 + 27797*x^5 + 56449*x^4 + 36716*x^3 + 8064*x^2 + 27797*x + 56449)
    //
    // If A * B = C at each point in the domain, then the following polynomial...
    // P(x) = A(x) * B(x) - C(x)
    //      = 49752*x^14 + 13914*x^13 + 29243*x^12 + 27227*x^11 + 62362*x^10 + 35703*x^9 + 4032*x^8 + 14761*x^6 + 50599*x^5 + 35270*x^4 + 37286*x^3 + 2151*x^2 + 28810*x + 60481
    //
    // ... should be divisible by t(x), producing the quotient polynomial:
    // h(x) = P(x) / t(x)
    //      = 49752*x^6 + 13914*x^5 + 29243*x^4 + 27227*x^3 + 62362*x^2 + 35703*x + 4032
    {
        let mut expected_c = Fr::zero();

        // A * s
        let mut tmp = proof.a;
        tmp.mul_assign(&s);
        expected_c.add_assign(&tmp);

        // B * r
        let mut tmp = proof.b;
        tmp.mul_assign(&r);
        expected_c.add_assign(&tmp);

        // delta * r * s
        let mut tmp = delta;
        tmp.mul_assign(&r);
        tmp.mul_assign(&s);
        expected_c.sub_assign(&tmp);

        // L query answer
        // a_2 = 1, a_3 = 0
        expected_c.add_assign(&params.ls[0][0]);

        // H query answer
        for (i, coeff) in [5040, 11763, 10755, 63633, 128, 9747, 8739]
            .iter()
            .enumerate()
        {
            let coeff = Fr::from(*coeff);

            let mut tmp = params.h[i];
            tmp.mul_assign(&coeff);
            expected_c.add_assign(&tmp);
        }

        assert_eq!(expected_c, proof.c);
    }
    assert_eq!(proof.ds.len(), 0);

    assert!(verify_proof(&pvk, &proof, &[Fr::one()]).is_ok());
}

struct MultWithZeroCoeffs<F> {
    a: Option<F>,
    b: Option<F>,
    c: Option<F>,
    /// Whether to attach the zero coefficient to the "1" variable, or a different variable.
    one_var: bool,
}

impl<F: ff::PrimeField> CcCircuit<F> for &MultWithZeroCoeffs<F> {
    fn synthesize<CS: CcConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let a = cs.alloc(|| "a", || Ok(self.a.unwrap()))?;
        let b = cs.alloc(|| "b", || Ok(self.b.unwrap()))?;
        let c = cs.alloc(|| "c", || Ok(self.c.unwrap()))?;
        if self.one_var {
            cs.enforce(
                || "cs",
                // notice the zero coefficient on the B term
                |z| z + a,
                |z| z + (F::from(0), CS::one()) + b,
                |z| z + c,
            );
        } else {
            cs.enforce(
                || "cs",
                // notice the zero coefficient on the B term
                |z| z + a,
                |z| z + (F::from(0), a) + b,
                |z| z + c,
            );
        }
        Ok(())
    }

    fn num_aux_blocks(&self) -> usize {
        0
    }
}

fn zero_coeff_test(one_var: bool) {
    let m = MultWithZeroCoeffs {
        a: Some(Fr::from(5)),
        b: Some(Fr::from(6)),
        c: Some(Fr::from(30)),
        one_var,
    };
    let g1 = Fr::one();
    let g2 = Fr::one();
    let alpha = Fr::from(48577);
    let beta = Fr::from(22580);
    let gamma = Fr::from(53332);
    let delta = Fr::from(5481);
    let tau = Fr::from(3673);
    let pk =
        generate_parameters::<DummyEngine, _>(&m, g1, g2, alpha, beta, gamma, vec![delta], tau)
            .unwrap();
    let r = Fr::from(27134);
    let s = Fr::from(17146);
    let pf = create_proof(&m, &pk, r, s, vec![]).unwrap();
    let pvk = prepare_verifying_key(&pk.vk);
    verify_proof(&pvk, &pf, &[]).unwrap();
}

#[test]
fn zero_coeff_one_var() {
    zero_coeff_test(true);
}

#[test]
fn zero_coeff_non_one_var() {
    zero_coeff_test(false);
}

#[test]
fn coin1() {
    struct Coin1<F> {
        a: Vec<Option<F>>,
        b: Vec<Option<F>>,
    }

    impl<F: ff::PrimeField> CcCircuit<F> for &Coin1<F> {
        fn synthesize<CS: CcConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
            use crate::gadgets::num::AllocatedNum;
            use crate::gadgets::Assignment;
            let as_ = self
                .a
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("a{}", i)), || {
                        a.get().map(Clone::clone)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let bs_ = self
                .b
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("b{}", i)), || {
                        b.get().map(Clone::clone)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            cs.end_aux_block(|| "perms")?;
            let (k, val_k) = cs.alloc_random(|| "k")?;
            let k = AllocatedNum {
                variable: k,
                value: val_k,
            };
            let ak = as_
                .into_iter()
                .try_fold(k.clone(), |k, a| k.mul(cs.namespace(|| "mul"), &a))?;
            let bk = bs_
                .into_iter()
                .try_fold(k, |k, b| k.mul(cs.namespace(|| "mul"), &b))?;
            cs.enforce(
                || "eq",
                |lc| lc,
                |lc| lc,
                |lc| lc + ak.get_variable() - bk.get_variable(),
            );
            Ok(())
        }

        fn num_aux_blocks(&self) -> usize {
            1
        }
    }
    let m = Coin1 {
        a: vec![Some(Fr::from(5)), Some(Fr::from(6))],
        b: vec![Some(Fr::from(10)), Some(Fr::from(3))],
    };
    let g1 = Fr::one();
    let g2 = Fr::one();
    let alpha = Fr::from(48577);
    let beta = Fr::from(22580);
    let gamma = Fr::from(53332);
    let delta = Fr::from(5481);
    let delta2 = Fr::from(5482);
    let tau = Fr::from(3673);
    let pk = generate_parameters::<DummyEngine, _>(
        &m,
        g1,
        g2,
        alpha,
        beta,
        gamma,
        vec![delta, delta2],
        tau,
    )
    .unwrap();
    let r = Fr::from(27134);
    let s = Fr::from(17146);
    let k = vec![Fr::from(1)];
    let pf = create_proof(&m, &pk, r, s, k).unwrap();
    let pvk = prepare_verifying_key(&pk.vk);
    verify_proof(&pvk, &pf, &[]).unwrap();
}

#[test]
fn test_3blocks_2coins() {
    struct Test<F> {
        a: Option<F>,
        b: Option<F>,
        c: Option<F>,
        d: Option<F>,
        e: Option<F>,
    }

    impl<F: ff::PrimeField> CcCircuit<F> for &Test<F> {
        fn synthesize<CS: CcConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
            use crate::gadgets::num::AllocatedNum;
            use crate::gadgets::Assignment;
            let a = AllocatedNum::alloc(cs.namespace(|| "a"), || self.a.get().map(Clone::clone))?;
            a.inputize(cs.namespace(|| "input a"))?;
            let b = AllocatedNum::alloc(cs.namespace(|| "b"), || self.b.get().map(Clone::clone))?;
            cs.end_aux_block(|| "ab")?;
            let c = AllocatedNum::alloc(cs.namespace(|| "c"), || self.c.get().map(Clone::clone))?;
            cs.end_aux_block(|| "c")?;
            let (j, val_j) = cs.alloc_random(|| "j")?;
            let j = AllocatedNum {
                variable: j,
                value: val_j,
            };
            let d = AllocatedNum::alloc(cs.namespace(|| "d"), || self.d.get().map(Clone::clone))?;
            let e = AllocatedNum::alloc(cs.namespace(|| "e"), || self.e.get().map(Clone::clone))?;
            cs.end_aux_block(|| "de")?;
            let (k, val_k) = cs.alloc_random(|| "k")?;
            let k = AllocatedNum {
                variable: k,
                value: val_k,
            };
            let product = a
                .mul(cs.namespace(|| "*b"), &b)?
                .mul(cs.namespace(|| "*c"), &c)?
                .mul(cs.namespace(|| "*d"), &d)?
                .mul(cs.namespace(|| "*e"), &e)?
                .mul(cs.namespace(|| "*j"), &j)?
                .mul(cs.namespace(|| "*k"), &k)?;
            let jk = j.mul(cs.namespace(|| "*jk"), &k)?;
            cs.enforce(
                || "eq",
                |lc| lc,
                |lc| lc,
                |lc| lc + product.get_variable() - jk.get_variable(),
            );
            Ok(())
        }

        fn num_aux_blocks(&self) -> usize {
            3
        }
    }
    let m = Test {
        a: Some(Fr::from(1)),
        b: Some(Fr::from(1)),
        c: Some(Fr::from(1)),
        d: Some(Fr::from(1)),
        e: Some(Fr::from(1)),
    };
    let g1 = Fr::one();
    let g2 = Fr::one();
    let alpha = Fr::from(48577);
    let beta = Fr::from(22580);
    let gamma = Fr::from(53332);
    let delta = Fr::from(5481);
    let delta2 = Fr::from(5482);
    let delta3 = Fr::from(5483);
    let delta4 = Fr::from(5483);
    let tau = Fr::from(3673);
    let pk = generate_parameters::<DummyEngine, _>(
        &m,
        g1,
        g2,
        alpha,
        beta,
        gamma,
        vec![delta, delta2, delta3, delta4],
        tau,
    )
    .unwrap();
    let r = Fr::from(27134);
    let s = Fr::from(17146);
    let k = vec![Fr::from(1), Fr::from(15), Fr::from(5)];
    let pf = create_proof(&m, &pk, r, s, k).unwrap();
    let pvk = prepare_verifying_key(&pk.vk);
    verify_proof(&pvk, &pf, &[Fr::from(1)]).unwrap();
}
