RSA Ring Signature Implementation
=================================

Overview
--------

This project implements RSA ring signatures based on the seminal paper ["How to Leak a Secret"](https://people.csail.mit.edu/rivest/pubs/RST01.pdf) by Ronald L. Rivest, Adi Shamir, and Yael Tauman. Ring signatures allow a member of a group to sign a message on behalf of the group without revealing their identity, providing anonymity within the group.

Research Background
-------------------

The concept of ring signatures was introduced in 2001 by Rivest, Shamir, and Tauman. Unlike group signatures, ring signatures don't require:

-   Initial setup
-   Special signing keys
-   Coordination among group members
-   Group managers

A user can conscript any group of other users as part of their signing group, without their knowledge or cooperation.

Technical Implementation
------------------------

### Core Components

1.  **Key Structure (`RsaRingSigner` struct)**

rust

Copy

`pub struct RsaRingSigner {
    pub list: Vec<RsaPublicKey>,  // List of all public keys in the ring
    pub signer: RsaPrivateKey     // Private key of the actual signer
}`

1.  **Symmetric Encryption (AES-128)** Located in `sym.rs`, handles the encryption/decryption operations using AES-128 in ECB mode:

rust

Copy

`pub fn encrypt(key: BigUint, plaintext: BigUint) -> BigUint
pub fn decrypt(key: BigUint, ciphertext: BigUint) -> BigUint`

### Key Algorithms

1\. Trapdoor Function
---------------------

rust

Copy

`fn compute_trapdoor(input: BigUint, public_key: RsaPublicKey) -> BigUint {
    let modulus = public_key.n();
    let exponent = public_key.e();
    let quotient = &input / modulus;
    let remainder = &input % modulus;
    let transformed_remainder = remainder.modpow(exponent, modulus);
    quotient * modulus + transformed_remainder
}`

This function implements the RSA trapdoor permutation, which is key to the ring signature's security. It:

-   Takes an input value and a public key
-   Performs RSA encryption operation
-   Preserves the quotient to maintain the range
-   Returns the transformed value

2\. Signing Process
-------------------

The signing algorithm in `sign()` function works in these steps:

a. **Initialization**:

rust

Copy

`let key = hash(message);           // Generate symmetric key
let glue = rand256_bytes();        // Generate random glue value`

b. **Ring Member Processing**:

rust

Copy

`for i in self.list.iter() {
    if *i != RsaPublicKey::from(self.signer.clone()) {
        // For non-signers: generate random values
        let x = rand256_bytes();
        xi_arr.push(x.clone());
        let y = compute_trapdoor(x.clone(), i.clone());
        yi_arr.push(y);
    } else {
        // For the actual signer: placeholder values
        yi_arr.push(BigUint::from_bytes_be(b""));
        xi_arr.push(BigUint::from_bytes_be(b""));
        s = j;
    }
    j += 1;
}`

c. **Ring Construction**:

rust

Copy

`// Forward ring construction
let mut e = glue.clone();
for k in 0..s {
    let c = e.clone() ^ yi_arr[k as usize].clone();
    e = sym::encrypt(key.clone(), c);
}

// Backward ring construction
let mut v = glue.clone();
for k in ((s + 1)..j).rev() {
    let d = sym::decrypt(key.clone(), v);
    v = d ^ yi_arr[k as usize].clone();
}`

3\. Verification Process
------------------------

rust

Copy

`pub fn verify(
    list: Vec<RsaPublicKey>,
    xi_arr: Vec<BigUint>,
    glue: BigUint,
    message: String,
) -> bool {
    // Generate yi values using trapdoor function
    let mut yi_arr = vec![];
    for i in 0..xi_arr.len() {
        let y = compute_trapdoor(xi_arr[i].clone(), list[i].clone());
        yi_arr.push(y);
    }

    // Forward chain computation
    let key = hash(message);
    let mut e = glue.clone();
    for j in 0..xi_arr.len() {
        let c = e ^ yi_arr[j].clone();
        e = sym::encrypt(key.clone(), c);
    }

    // Verify if the chain closes
    e == glue
}`

Security Features
-----------------

1.  **Unforgeability**: The RSA trapdoor function ensures that only the actual signer can create valid signatures.
2.  **Anonymity**: The random values and symmetric encryption make it computationally infeasible to determine which key was used to sign.
3.  **Non-linkability**: Different signatures by the same signer are indistinguishable from signatures by different signers.

Usage
-----

### Prerequisites

toml

Copy

`[dependencies]
aes = "0.7"
rand = "0.8"
rsa = "0.5"
sha2 = "0.9"
sp-core = "6.0"`

### Basic Usage Example

rust

Copy

`// Generate keys for ring members
let private_keys = generate_keys(2048, 5);
let mut public_keys: Vec<RsaPublicKey> = Vec::new();
for private_key in private_keys.iter() {
    public_keys.push(RsaPublicKey::from(private_key.clone()));
}

// Initialize signer
let signer_private_key = private_keys[2].clone();
let ring_signer = RsaRingSigner::init(public_keys.clone(), signer_private_key);

// Sign a message
let message = String::from("Hello, World!");
let (xi_list, glue) = ring_signer.sign(message.clone());

// Verify the signature
let is_valid = verify(
    public_keys.clone(),
    xi_list.clone(),
    glue.clone(),
    message.clone(),
);
println!("Signature valid: {}", is_valid);`

Recommended Security Practices
------------------------------

1.  Use key sizes of at least 2048 bits for RSA keys
2.  Generate fresh random values for each signature
3.  Keep private keys secure and never share them
4.  Use cryptographically secure random number generators
5.  Verify message integrity before signing

References
----------

1.  Rivest, R. L., Shamir, A., & Tauman, Y. (2001). ["How to leak a secret"](https://people.csail.mit.edu/rivest/pubs/RST01.pdf). International Conference on the Theory and Application of Cryptology and Information Security (pp. 552-565).
2.  Shamir, A. (1984). ["Identity-Based Cryptosystems and Signature Schemes"](https://link.springer.com/chapter/10.1007/3-540-39568-7_5). Advances in Cryptology (pp. 47-53).

Contributing
------------

Contributions are welcome! Please feel free to submit a Pull Request.

License
-------

This project is licensed under the MIT License - see the LICENSE file for details.