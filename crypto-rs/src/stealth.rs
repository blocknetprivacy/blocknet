//! Stealth Addresses
//!
//! Provides receiver privacy by generating one-time addresses for each transaction.
//!
//! How it works:
//! 1. Receiver publishes: (spend_pubkey, view_pubkey)
//! 2. Sender generates random `r`, computes:
//!    - R = r * G (tx public key, included in transaction)
//!    - shared_secret = H(r * view_pubkey)
//!    - one_time_pubkey = shared_secret * G + spend_pubkey
//! 3. Receiver scans each tx:
//!    - shared_secret = H(view_privkey * R)
//!    - expected_pubkey = shared_secret * G + spend_pubkey
//!    - If matches output, compute: one_time_privkey = shared_secret + spend_privkey

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::slice;

/// Generate a stealth keypair (spend_key, view_key)
/// Output: 64 bytes spend (32 priv + 32 pub) || 64 bytes view (32 priv + 32 pub)
#[no_mangle]
pub extern "C" fn blocknet_stealth_keygen(output: *mut u8) -> i32 {
    if output.is_null() {
        return -1;
    }

    // Generate spend keypair
    let spend_privkey = Scalar::random(&mut rand::thread_rng());
    let spend_pubkey = &spend_privkey * RISTRETTO_BASEPOINT_TABLE;

    // Generate view keypair
    let view_privkey = Scalar::random(&mut rand::thread_rng());
    let view_pubkey = &view_privkey * RISTRETTO_BASEPOINT_TABLE;

    unsafe {
        let out = slice::from_raw_parts_mut(output, 128);
        out[0..32].copy_from_slice(spend_privkey.as_bytes());
        out[32..64].copy_from_slice(spend_pubkey.compress().as_bytes());
        out[64..96].copy_from_slice(view_privkey.as_bytes());
        out[96..128].copy_from_slice(view_pubkey.compress().as_bytes());
    }

    0
}

/// Generate a transaction keypair (sender side)
///
/// tx_privkey_out: 32-byte buffer for transaction private key (r)
/// tx_pubkey_out: 32-byte buffer for transaction public key (R = r*G)
#[no_mangle]
pub extern "C" fn blocknet_stealth_tx_keygen(
    tx_privkey_out: *mut u8,
    tx_pubkey_out: *mut u8,
) -> i32 {
    if tx_privkey_out.is_null() || tx_pubkey_out.is_null() {
        return -1;
    }

    // Generate random transaction private key
    let r = Scalar::random(&mut rand::thread_rng());

    // R = r * G (transaction public key)
    let tx_pub = &r * RISTRETTO_BASEPOINT_TABLE;

    unsafe {
        let tx_priv_out = slice::from_raw_parts_mut(tx_privkey_out, 32);
        tx_priv_out.copy_from_slice(r.as_bytes());

        let tx_pub_out = slice::from_raw_parts_mut(tx_pubkey_out, 32);
        tx_pub_out.copy_from_slice(tx_pub.compress().as_bytes());
    }

    0
}

/// Derive a one-time stealth public key using a provided tx private key (sender side)
///
/// spend_pubkey: receiver's 32-byte spend public key
/// view_pubkey: receiver's 32-byte view public key
/// tx_privkey: 32-byte transaction private key (r)
/// onetime_pubkey_out: 32-byte buffer for one-time public key
#[no_mangle]
pub extern "C" fn blocknet_stealth_derive_onetime_pubkey(
    spend_pubkey: *const u8,
    view_pubkey: *const u8,
    tx_privkey: *const u8,
    onetime_pubkey_out: *mut u8,
) -> i32 {
    if spend_pubkey.is_null() || view_pubkey.is_null() || tx_privkey.is_null() || onetime_pubkey_out.is_null() {
        return -1;
    }

    unsafe {
        let spend_bytes = slice::from_raw_parts(spend_pubkey, 32);
        let view_bytes = slice::from_raw_parts(view_pubkey, 32);
        let tx_priv_bytes = slice::from_raw_parts(tx_privkey, 32);

        // Decompress public keys
        let spend_pub = match CompressedRistretto::from_slice(spend_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let view_pub = match CompressedRistretto::from_slice(view_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        // Parse tx privkey as scalar
        let r = match Scalar::from_canonical_bytes(tx_priv_bytes.try_into().expect("slice length"))
            .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        // shared_secret = H(r * view_pubkey)
        let shared_point = r * view_pub;
        let shared_secret = hash_to_scalar(shared_point.compress().as_bytes());

        // one_time_pubkey = shared_secret * G + spend_pubkey
        let onetime_pub = &shared_secret * RISTRETTO_BASEPOINT_TABLE + spend_pub;

        let onetime_out = slice::from_raw_parts_mut(onetime_pubkey_out, 32);
        onetime_out.copy_from_slice(onetime_pub.compress().as_bytes());
    }

    0
}

/// Derive a one-time stealth address (sender side)
///
/// spend_pubkey: receiver's 32-byte spend public key
/// view_pubkey: receiver's 32-byte view public key  
/// tx_privkey_out: 32-byte buffer for transaction private key (r)
/// tx_pubkey_out: 32-byte buffer for transaction public key (R = r*G)
/// onetime_pubkey_out: 32-byte buffer for one-time public key
#[no_mangle]
pub extern "C" fn blocknet_stealth_derive_address(
    spend_pubkey: *const u8,
    view_pubkey: *const u8,
    tx_privkey_out: *mut u8,
    tx_pubkey_out: *mut u8,
    onetime_pubkey_out: *mut u8,
) -> i32 {
    if spend_pubkey.is_null()
        || view_pubkey.is_null()
        || tx_privkey_out.is_null()
        || tx_pubkey_out.is_null()
        || onetime_pubkey_out.is_null()
    {
        return -1;
    }

    unsafe {
        let spend_bytes = slice::from_raw_parts(spend_pubkey, 32);
        let view_bytes = slice::from_raw_parts(view_pubkey, 32);

        // Decompress public keys
        let spend_pub = match CompressedRistretto::from_slice(spend_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let view_pub = match CompressedRistretto::from_slice(view_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        // Generate transaction keypair
        let r = Scalar::random(&mut rand::thread_rng());
        let tx_pub = &r * RISTRETTO_BASEPOINT_TABLE;

        // shared_secret = H(r * view_pubkey)
        let shared_point = r * view_pub;
        let shared_secret = hash_to_scalar(shared_point.compress().as_bytes());

        // one_time_pubkey = shared_secret * G + spend_pubkey
        let onetime_pub = &shared_secret * RISTRETTO_BASEPOINT_TABLE + spend_pub;

        // Output results
        let tx_priv_out = slice::from_raw_parts_mut(tx_privkey_out, 32);
        tx_priv_out.copy_from_slice(r.as_bytes());

        let tx_pub_out = slice::from_raw_parts_mut(tx_pubkey_out, 32);
        tx_pub_out.copy_from_slice(tx_pub.compress().as_bytes());

        let onetime_out = slice::from_raw_parts_mut(onetime_pubkey_out, 32);
        onetime_out.copy_from_slice(onetime_pub.compress().as_bytes());
    }

    0
}

/// Check if a one-time address belongs to us (receiver side)
///
/// spend_pubkey: our 32-byte spend public key
/// view_privkey: our 32-byte view private key
/// tx_pubkey: 32-byte transaction public key (R) from the tx
/// onetime_pubkey: 32-byte one-time public key to check
///
/// Returns: 0 if it's ours, -1 if not
#[no_mangle]
pub extern "C" fn blocknet_stealth_check_output(
    spend_pubkey: *const u8,
    view_privkey: *const u8,
    tx_pubkey: *const u8,
    onetime_pubkey: *const u8,
) -> i32 {
    if spend_pubkey.is_null()
        || view_privkey.is_null()
        || tx_pubkey.is_null()
        || onetime_pubkey.is_null()
    {
        return -1;
    }

    unsafe {
        let spend_bytes = slice::from_raw_parts(spend_pubkey, 32);
        let view_priv_bytes = slice::from_raw_parts(view_privkey, 32);
        let tx_pub_bytes = slice::from_raw_parts(tx_pubkey, 32);
        let onetime_bytes = slice::from_raw_parts(onetime_pubkey, 32);

        // Parse keys
        let spend_pub = match CompressedRistretto::from_slice(spend_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let view_priv = match Scalar::from_canonical_bytes(
            view_priv_bytes.try_into().expect("slice length")
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        let tx_pub = match CompressedRistretto::from_slice(tx_pub_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let onetime_pub = CompressedRistretto::from_slice(onetime_bytes).expect("slice length");

        // Compute: shared_secret = H(view_privkey * R)
        let shared_point = view_priv * tx_pub;
        let shared_secret = hash_to_scalar(shared_point.compress().as_bytes());

        // Compute expected: shared_secret * G + spend_pubkey
        let expected = &shared_secret * RISTRETTO_BASEPOINT_TABLE + spend_pub;

        if expected.compress() == onetime_pub {
            0 // It's ours!
        } else {
            -1 // Not ours
        }
    }
}

/// Derive the one-time private key to spend an output (receiver side)
///
/// spend_privkey: our 32-byte spend private key
/// view_privkey: our 32-byte view private key
/// tx_pubkey: 32-byte transaction public key (R)
/// onetime_privkey_out: 32-byte buffer for derived private key
#[no_mangle]
pub extern "C" fn blocknet_stealth_derive_privkey(
    spend_privkey: *const u8,
    view_privkey: *const u8,
    tx_pubkey: *const u8,
    onetime_privkey_out: *mut u8,
) -> i32 {
    if spend_privkey.is_null()
        || view_privkey.is_null()
        || tx_pubkey.is_null()
        || onetime_privkey_out.is_null()
    {
        return -1;
    }

    unsafe {
        let spend_priv_bytes = slice::from_raw_parts(spend_privkey, 32);
        let view_priv_bytes = slice::from_raw_parts(view_privkey, 32);
        let tx_pub_bytes = slice::from_raw_parts(tx_pubkey, 32);

        let spend_priv = match Scalar::from_canonical_bytes(
            spend_priv_bytes.try_into().expect("slice length")
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        let view_priv = match Scalar::from_canonical_bytes(
            view_priv_bytes.try_into().expect("slice length")
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        let tx_pub = match CompressedRistretto::from_slice(tx_pub_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        // shared_secret = H(view_privkey * R)
        let shared_point = view_priv * tx_pub;
        let shared_secret = hash_to_scalar(shared_point.compress().as_bytes());

        // one_time_privkey = shared_secret + spend_privkey
        let onetime_priv = shared_secret + spend_priv;

        let out = slice::from_raw_parts_mut(onetime_privkey_out, 32);
        out.copy_from_slice(onetime_priv.as_bytes());
    }

    0
}

/// Hash bytes to a scalar (for deriving shared secrets)
fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"blocknet_stealth_hs");
    hasher.update(data);
    let hash = hasher.finalize();

    // Reduce hash to scalar
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive the shared secret from tx_pubkey and view_privkey
/// shared_secret = H(view_privkey * tx_pubkey)
/// Used for amount decryption and blinding factor derivation
#[no_mangle]
pub extern "C" fn blocknet_stealth_derive_secret(
    tx_pubkey: *const u8,
    view_privkey: *const u8,
    secret_out: *mut u8,
) -> i32 {
    if tx_pubkey.is_null() || view_privkey.is_null() || secret_out.is_null() {
        return -1;
    }

    unsafe {
        let tx_pub_bytes = slice::from_raw_parts(tx_pubkey, 32);
        let view_priv_bytes = slice::from_raw_parts(view_privkey, 32);

        // Parse tx_pubkey as compressed Ristretto point
        let tx_pub = match CompressedRistretto::from_slice(tx_pub_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        // Parse view_privkey as scalar
        let view_priv = match Scalar::from_canonical_bytes(
            view_priv_bytes.try_into().expect("slice length")
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        // shared_secret = H(view_privkey * tx_pubkey)
        let shared_point = view_priv * tx_pub;
        let shared_secret = hash_to_scalar(shared_point.compress().as_bytes());

        let out = slice::from_raw_parts_mut(secret_out, 32);
        out.copy_from_slice(shared_secret.as_bytes());
    }

    0
}

/// Derive the shared secret from tx_privkey and view_pubkey (sender side)
/// shared_secret = H(tx_privkey * view_pubkey)
/// This computes the same secret as blocknet_stealth_derive_secret
#[no_mangle]
pub extern "C" fn blocknet_stealth_derive_secret_sender(
    tx_privkey: *const u8,
    view_pubkey: *const u8,
    secret_out: *mut u8,
) -> i32 {
    if tx_privkey.is_null() || view_pubkey.is_null() || secret_out.is_null() {
        return -1;
    }

    unsafe {
        let tx_priv_bytes = slice::from_raw_parts(tx_privkey, 32);
        let view_pub_bytes = slice::from_raw_parts(view_pubkey, 32);

        // Parse tx_privkey as scalar
        let tx_priv = match Scalar::from_canonical_bytes(
            tx_priv_bytes.try_into().expect("slice length")
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        // Parse view_pubkey as compressed Ristretto point
        let view_pub = match CompressedRistretto::from_slice(view_pub_bytes)
            .expect("slice length")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        // shared_secret = H(tx_privkey * view_pubkey)
        let shared_point = tx_priv * view_pub;
        let shared_secret = hash_to_scalar(shared_point.compress().as_bytes());

        let out = slice::from_raw_parts_mut(secret_out, 32);
        out.copy_from_slice(shared_secret.as_bytes());
    }

    0
}

/// Derive the one-time public key from one-time private key (for verification)
#[no_mangle]
pub extern "C" fn blocknet_scalar_to_pubkey(
    privkey: *const u8,
    pubkey_out: *mut u8,
) -> i32 {
    if privkey.is_null() || pubkey_out.is_null() {
        return -1;
    }

    unsafe {
        let priv_bytes = slice::from_raw_parts(privkey, 32);

        let scalar = match Scalar::from_canonical_bytes(
            priv_bytes.try_into().expect("slice length")
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        let pubkey = &scalar * RISTRETTO_BASEPOINT_TABLE;

        let out = slice::from_raw_parts_mut(pubkey_out, 32);
        out.copy_from_slice(pubkey.compress().as_bytes());
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_full_flow() {
        // 1. Receiver generates stealth keypair
        let mut receiver_keys = [0u8; 128];
        assert_eq!(blocknet_stealth_keygen(receiver_keys.as_mut_ptr()), 0);

        let spend_priv = &receiver_keys[0..32];
        let spend_pub = &receiver_keys[32..64];
        let view_priv = &receiver_keys[64..96];
        let view_pub = &receiver_keys[96..128];

        // 2. Sender derives one-time address
        let mut tx_priv = [0u8; 32];
        let mut tx_pub = [0u8; 32];
        let mut onetime_pub = [0u8; 32];

        assert_eq!(
            blocknet_stealth_derive_address(
                spend_pub.as_ptr(),
                view_pub.as_ptr(),
                tx_priv.as_mut_ptr(),
                tx_pub.as_mut_ptr(),
                onetime_pub.as_mut_ptr(),
            ),
            0
        );

        // 3. Receiver checks if output is theirs
        let check_result = blocknet_stealth_check_output(
            spend_pub.as_ptr(),
            view_priv.as_ptr(),
            tx_pub.as_ptr(),
            onetime_pub.as_ptr(),
        );
        assert_eq!(check_result, 0); // Should be ours!

        // 4. Receiver derives private key to spend
        let mut onetime_priv = [0u8; 32];
        assert_eq!(
            blocknet_stealth_derive_privkey(
                spend_priv.as_ptr(),
                view_priv.as_ptr(),
                tx_pub.as_ptr(),
                onetime_priv.as_mut_ptr(),
            ),
            0
        );

        // 5. Verify the derived private key matches the public key
        let mut derived_pub = [0u8; 32];
        assert_eq!(
            blocknet_scalar_to_pubkey(onetime_priv.as_ptr(), derived_pub.as_mut_ptr()),
            0
        );
        assert_eq!(onetime_pub, derived_pub);
    }

    #[test]
    fn test_stealth_wrong_receiver() {
        // Receiver 1
        let mut receiver1_keys = [0u8; 128];
        blocknet_stealth_keygen(receiver1_keys.as_mut_ptr());

        // Receiver 2 (different person)
        let mut receiver2_keys = [0u8; 128];
        blocknet_stealth_keygen(receiver2_keys.as_mut_ptr());

        // Sender sends to receiver 1
        let mut tx_priv = [0u8; 32];
        let mut tx_pub = [0u8; 32];
        let mut onetime_pub = [0u8; 32];

        blocknet_stealth_derive_address(
            receiver1_keys[32..64].as_ptr(), // receiver 1's spend pub
            receiver1_keys[96..128].as_ptr(), // receiver 1's view pub
            tx_priv.as_mut_ptr(),
            tx_pub.as_mut_ptr(),
            onetime_pub.as_mut_ptr(),
        );

        // Receiver 2 tries to claim it - should fail
        let check_result = blocknet_stealth_check_output(
            receiver2_keys[32..64].as_ptr(), // receiver 2's spend pub
            receiver2_keys[64..96].as_ptr(), // receiver 2's view priv
            tx_pub.as_ptr(),
            onetime_pub.as_ptr(),
        );
        assert_eq!(check_result, -1); // Not theirs!
    }
}

