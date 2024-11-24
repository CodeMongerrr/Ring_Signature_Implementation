// extern crates
extern crate aes;
extern crate rand;
extern crate rsa;
extern crate sha2;
extern crate sp_core;

#[path = "sym.rs"]
mod sym;

// standard imports from th library
use std::vec;

// extern imports 
use rand::{rngs::OsRng, RngCore};
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use sp_core::hashing::blake2_128;

impl RSA_Ring_Signer {
    pub fn init(list:Vec<RsaPublicKey>, signer:RsaPrivateKey ) -> RSA_Ring_Signer{
        RSA_Ring_Signer {
            list: list,
            signer: signer
        }
    }

    pub fn sign(&self, message: String) -> (Vec<BigUint>, BigUint) {

        let key = hash(message);

        let glue = rand256Bytes();

        let mut xi_arr: Vec<BigUint> = vec![];
        let mut yi_arr: Vec<BigUint> = vec![];
        let mut j: u8 = 0;
        let mut s: u8 = 0;

        for i in self.list.iter() {
            if *i != RsaPublicKey::from(self.signer.clone()) {
                let x = rand256Bytes();
                xi_arr.push(x.clone());
                let y = compute_trapdoor(x.clone(), i.clone());
                yi_arr.push(y);
            }
            else{
                yi_arr.push(BigUint::from_bytes_be(b""));
                xi_arr.push(BigUint::from_bytes_be(b""));
                s = j;
            }
            j +=1;
        }

        // C_k,v (y1,y2 , . . . , yr)
        let mut e = glue.clone();
        for k in 0..s {
            let c = e ^ yi_arr[k as usize].clone();
            e = sym::encrypt(key.clone(), c.clone());
        }
        let mut v = glue.clone();
        for k in ((s + 1)..j).rev() {
            let d = sym::decrypt(key.clone(), v);
            v = d ^ yi_arr[k as usize].clone();
        }

        // C_k,v (y1,y2 , . . . , yr) = v for ys
        let mut ys = sym::decrypt(key.clone(), v);
        ys = ys ^ e;

        let pk = RsaPublicKey::from(self.signer.clone());
        let d = self.signer.d();
        let n = pk.n();
        let q = ys.clone() /n;
        let fr = ys.clone() % n;
        let r = fr.modpow(d, n);

        let xs = q * n + r.clone();
        xi_arr[s as usize] = xs;
        return (xi_arr, glue);
    }
}


pub struct RSA_Ring_Signer {
    list: Vec<RsaPublicKey>,
    signer: RsaPrivateKey,
}

pub fn verify(
    list: Vec<RsaPublicKey>,
    xi_arr: Vec<BigUint>,
    glue: BigUint,
    message: String,
) -> bool {
    // Generate yi values
    let mut yi_arr = vec![];
    for i in 0..xi_arr.len() {
        let y = compute_trapdoor(xi_arr[i].clone(), list[i].clone());
        yi_arr.push(y);
    }

    // Hash the message to generate the symmetric key
    let key = hash(message);

    // Forward chain computation using the glue value
    let mut e = glue.clone();
    for j in 0..xi_arr.len() {
        let c = e ^ yi_arr[j as usize].clone();
        e = sym::encrypt(key.clone(), c.clone());
    }

    // Check if the chain loops back to the glue value
    if e == glue {
        return true;
    }
    return false;
}

pub fn hash(message: String) -> BigUint {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(message.into_bytes());
    // read hash digest and consume hasher
    let result = hasher.finalize();
    let x = result.as_slice();

    let hash128 = blake2_128(x);
    return BigUint::from_bytes_be(&hash128);
}
pub fn rand256Bytes() -> BigUint {
    let mut key = [0u8; 256];
    OsRng.fill_bytes(&mut key);
    let rand_number = BigUint::from_bytes_be(&key);
    return rand_number >> 1;
}

// Trapdoor function
fn compute_trapdoor(input: BigUint, public_key: RsaPublicKey) -> BigUint {
    let modulus = public_key.n();
    let exponent = public_key.e();

    let quotient = &input / modulus;
    let remainder = &input % modulus;

    let transformed_remainder = remainder.modpow(exponent, modulus);

    let result = quotient * modulus + transformed_remainder;

    result
}