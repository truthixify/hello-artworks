use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

#[derive(Clone)]
pub struct MultiplierCircuit<F: Field> {
    pub a: Option<F>, // Private input
    pub b: Option<F>, // Private input
}

impl<F: Field> ConstraintSynthesizer<F> for MultiplierCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_witness_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test() {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);

        println!("Creating proofs...");

        let c = MultiplierCircuit::<Fr> {
            a: Some(Fr::from(2u64)),
            b: Some(Fr::from(3u64)),
        };

        let v = Fr::from(2u64) * Fr::from(3u64); // c.a.unwrap() * c.b.unwrap();

        println!("Setting up circuit...");

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c.clone(), rng).unwrap();

        println!("Proving...");
        let proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();

        println!("Processing verifier key...");
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();

        println!("Verifying...");
        assert!(Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &vec![v], &proof).unwrap());
    }
}
