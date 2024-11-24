// main.rs
extern crate aes;
extern crate rand;
extern crate rsa;
extern crate sha2;
extern crate sp_core;

mod ring;
mod sym;

use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::time::Instant;
use crate::ring::{RSA_Ring_Signer, verify};

fn main() {
    // Configure parameters
    let key_size = 2048;  // RSA key size in bits
    let ring_size = 5;    // Number of participants in the ring
    let signer_index = 2; // Index of the actual signer (0-based)

    println!("RSA Ring Signature Demo");
    println!("----------------------");
    println!("Key size: {} bits", key_size);
    println!("Ring size: {} participants", ring_size);
    println!("Signer index: {}", signer_index);

    // Generate keys
    println!("\nGenerating {} RSA key pairs ({} bits each)...", ring_size, key_size);
    let start = Instant::now();
    let private_keys = generate_keys(key_size, ring_size);
    println!("Key generation took: {:?}", start.elapsed());

    // Create public key list and get signer's private key
    let mut public_keys: Vec<RsaPublicKey> = Vec::new();
    for private_key in private_keys.iter() {
        public_keys.push(RsaPublicKey::from(private_key.clone()));
    }
    let signer_private_key = private_keys[signer_index as usize].clone();

    // Initialize the ring signer
    println!("\nInitializing RSA Ring Signer...");
    let ring_signer = RSA_Ring_Signer::init(public_keys.clone(), signer_private_key);

    // Test messages to sign
    let test_messages = vec![
        String::from("Hello, World!"),
        String::from("This is a test message"),
        String::from("RSA Ring Signatures are anonymous"),
    ];

    // Sign and verify each message
    for (i, message) in test_messages.iter().enumerate() {
        println!("\nTest Case {}", i + 1);
        println!("Message: \"{}\"", message);

        // Sign the message
        let start = Instant::now();
        let (xi_list, glue) = ring_signer.sign(message.clone());
        let signing_time = start.elapsed();
        println!("Signing took: {:?}", signing_time);

        // Verify the signature
        let start = Instant::now();
        let is_valid = verify(
            public_keys.clone(),
            xi_list.clone(),
            glue.clone(),
            message.clone(),
        );
        let verification_time = start.elapsed();
        
        println!("Verification took: {:?}", verification_time);
        println!("Signature valid: {}", is_valid);

        // Optional: Print detailed information about the signature
        if cfg!(debug_assertions) {
            println!("\nSignature Details:");
            println!("Xi list length: {}", xi_list.len());
            println!("Glue value length: {} bytes", glue.to_bytes_be().len());
        }
    }

    // Demonstrate invalid signature case
    println!("\nTesting Invalid Signature Case");
    let invalid_message = String::from("Modified message");
    let (xi_list, glue) = ring_signer.sign(test_messages[0].clone());
    let is_valid = verify(
        public_keys.clone(),
        xi_list.clone(),
        glue.clone(),
        invalid_message,
    );
    println!("Invalid signature verification (should be false): {}", is_valid);
}

// Helper function to generate RSA key pairs
fn generate_keys(bits: usize, count: u8) -> Vec<RsaPrivateKey> {
    let mut private_keys = Vec::new();
    let mut rng = OsRng;

    for i in 0..count {
        match RsaPrivateKey::new(&mut rng, bits) {
            Ok(private_key) => {
                private_keys.push(private_key);
                if cfg!(debug_assertions) {
                    println!("Generated key pair {}/{}", i + 1, count);
                }
            }
            Err(e) => {
                eprintln!("Failed to generate key pair: {}", e);
                std::process::exit(1);
            }
        }
    }

    private_keys
}