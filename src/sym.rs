use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::{Aes128, Block};
use rsa::BigUint;

#[allow(dead_code)]
// Encrypts multiple 128-bit blocks using a 128-bit key
pub fn encrypt(key: BigUint, plaintext: BigUint) -> BigUint {
    // Convert the key and plaintext into byte arrays
    let key_bytes = key.to_bytes_be();
    let plaintext_bytes = plaintext.to_bytes_be();
    let block_count = plaintext_bytes.len() / 16;

    // Ensure the key is exactly 128 bits (16 bytes)
    assert_eq!(key_bytes.len(), 16);
    let aes_key = GenericArray::from_slice(&key_bytes);

    let mut encrypted_bytes: Vec<u8> = vec![];

    // Process each 128-bit block
    for block_index in 0..block_count {
        let mut block_data: Vec<u8> = vec![];

        // Extract a single 128-bit block
        for byte_index in 0..16 {
            block_data.push(plaintext_bytes[(block_index * 16) + byte_index]);
        }

        // Create and encrypt the block
        let block = Block::from_slice(&block_data);
        let mut encrypted_block = block.clone();

        // Initialize AES cipher and encrypt the block in-place
        let aes_cipher = Aes128::new(&aes_key);
        aes_cipher.encrypt_block(&mut encrypted_block);

        // Append the encrypted block to the result
        encrypted_bytes.extend_from_slice(encrypted_block.as_slice());
    }

    // Return the encrypted data as a BigUint
    BigUint::from_bytes_be(&encrypted_bytes)
}

#[allow(dead_code)]
// Decrypts multiple 128-bit blocks using a 128-bit key
pub fn decrypt(key: BigUint, ciphertext: BigUint) -> BigUint {
    // Convert the key and ciphertext into byte arrays
    let key_bytes = key.to_bytes_be();
    let ciphertext_bytes = ciphertext.to_bytes_be();
    let block_count = ciphertext_bytes.len() / 16;

    // Ensure the key is exactly 128 bits (16 bytes)
    assert_eq!(key_bytes.len(), 16);
    let aes_key = GenericArray::from_slice(&key_bytes);

    let mut decrypted_bytes: Vec<u8> = vec![];

    // Process each 128-bit block
    for block_index in 0..block_count {
        let mut block_data: Vec<u8> = vec![];

        // Extract a single 128-bit block
        for byte_index in 0..16 {
            block_data.push(ciphertext_bytes[(block_index * 16) + byte_index]);
        }

        // Create and decrypt the block
        let block = Block::from_slice(&block_data);
        let mut decrypted_block = block.clone();

        // Initialize AES cipher and decrypt the block in-place
        let aes_cipher = Aes128::new(&aes_key);
        aes_cipher.decrypt_block(&mut decrypted_block);

        // Append the decrypted block to the result
        decrypted_bytes.extend_from_slice(decrypted_block.as_slice());
    }

    // Return the decrypted data as a BigUint
    BigUint::from_bytes_be(&decrypted_bytes)
}