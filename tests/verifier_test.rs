use std::{fs, path::Path};
use ultrahonk_rust_verifier::{UltraHonkVerifier, VerifierError};

fn run(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir);

    // Proof bytes
    let proof_bytes: Vec<u8> = fs::read(path.join("proof"))?;

    // Use binary VK
    let vk_bytes = fs::read(path.join("vk"))?;
    let verifier = UltraHonkVerifier::new_from_bytes(&vk_bytes).ok_or("vk parse")?;

    // Public inputs bytes
    let public_inputs = fs::read(path.join("public_inputs"))?;
    verifier.verify(&proof_bytes, &public_inputs)?;
    Ok(())
}

#[test]
fn simple_circuit_proof_verifies() -> Result<(), Box<dyn std::error::Error>> {
    run("circuits/simple_circuit/target")
}

#[test]
fn fib_chain_proof_verifies() -> Result<(), Box<dyn std::error::Error>> {
    run("circuits/fib_chain/target")
}
