use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use ed25519_dalek::Signer;
use std::slice;

/// Generate a new ed25519 keypair
/// Returns: 32-byte private key || 32-byte public key (64 bytes total)
#[no_mangle]
pub extern "C" fn blocknet_generate_keypair(output: *mut u8) -> i32 {
    if output.is_null() {
        return -1;
    }

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let verifying_key = signing_key.verifying_key();

    unsafe {
        let output_slice = slice::from_raw_parts_mut(output, 64);
        output_slice[..32].copy_from_slice(&signing_key.to_bytes());
        output_slice[32..].copy_from_slice(&verifying_key.to_bytes());
    }

    0
}

/// Sign a message with ed25519
#[no_mangle]
pub extern "C" fn blocknet_sign(
    private_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
) -> i32 {
    if private_key.is_null() || message.is_null() || signature_out.is_null() {
        return -1;
    }

    unsafe {
        let key_bytes = slice::from_raw_parts(private_key, 32);
        let msg_bytes = slice::from_raw_parts(message, message_len);

        let signing_key = SigningKey::from_bytes(
            key_bytes.try_into().expect("slice with incorrect length")
        );

        let signature = signing_key.sign(msg_bytes);

        let sig_out = slice::from_raw_parts_mut(signature_out, 64);
        sig_out.copy_from_slice(&signature.to_bytes());
    }

    0
}

/// Verify an ed25519 signature
#[no_mangle]
pub extern "C" fn blocknet_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> i32 {
    if public_key.is_null() || message.is_null() || signature.is_null() {
        return -1;
    }

    unsafe {
        let pub_bytes = slice::from_raw_parts(public_key, 32);
        let msg_bytes = slice::from_raw_parts(message, message_len);
        let sig_bytes = slice::from_raw_parts(signature, 64);

        let verifying_key = match VerifyingKey::from_bytes(
            pub_bytes.try_into().expect("slice with incorrect length")
        ) {
            Ok(key) => key,
            Err(_) => return -1,
        };

        let sig = Signature::from_bytes(
            sig_bytes.try_into().expect("slice with incorrect length")
        );

        match verifying_key.verify(msg_bytes, &sig) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let mut output = [0u8; 64];
        let result = blocknet_generate_keypair(output.as_mut_ptr());
        assert_eq!(result, 0);
        assert_ne!(&output[..32], &[0u8; 32]);
    }

    #[test]
    fn test_sign_verify() {
        let mut keypair = [0u8; 64];
        blocknet_generate_keypair(keypair.as_mut_ptr());

        let message = b"Hello, blocknet!";
        let mut signature = [0u8; 64];

        let sign_result = blocknet_sign(
            keypair.as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
        );
        assert_eq!(sign_result, 0);

        let verify_result = blocknet_verify(
            keypair[32..].as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
        );
        assert_eq!(verify_result, 0);
    }
}

