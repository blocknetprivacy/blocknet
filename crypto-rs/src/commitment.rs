use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use std::slice;

/// Create a Pedersen commitment to a value
/// commitment = value*G + blinding*H
/// 
/// value: 64-bit amount to commit to
/// blinding_out: 32-byte buffer to store the random blinding factor
/// commitment_out: 32-byte buffer to store the compressed commitment
#[no_mangle]
pub extern "C" fn blocknet_pedersen_commit(
    value: u64,
    blinding_out: *mut u8,
    commitment_out: *mut u8,
) -> i32 {
    if blinding_out.is_null() || commitment_out.is_null() {
        return -1;
    }

    let pc_gens = PedersenGens::default();
    
    // Generate random blinding factor
    let blinding = Scalar::random(&mut rand::thread_rng());
    
    // Create commitment: v*B + r*B_blinding
    let commitment = pc_gens.commit(Scalar::from(value), blinding);
    let compressed = commitment.compress();

    unsafe {
        let blind_slice = slice::from_raw_parts_mut(blinding_out, 32);
        blind_slice.copy_from_slice(blinding.as_bytes());
        
        let commit_slice = slice::from_raw_parts_mut(commitment_out, 32);
        commit_slice.copy_from_slice(compressed.as_bytes());
    }

    0
}

/// Create a Pedersen commitment with a specific blinding factor
/// commitment = value*G + blinding*H
#[no_mangle]
pub extern "C" fn blocknet_pedersen_commit_with_blinding(
    value: u64,
    blinding: *const u8,
    commitment_out: *mut u8,
) -> i32 {
    if blinding.is_null() || commitment_out.is_null() {
        return -1;
    }

    unsafe {
        let blind_bytes = slice::from_raw_parts(blinding, 32);

        // Use from_bytes_mod_order to handle non-canonical scalars (hash outputs)
        let blind_scalar = Scalar::from_bytes_mod_order(
            blind_bytes.try_into().expect("slice length")
        );

        let pc_gens = PedersenGens::default();
        let commitment = pc_gens.commit(Scalar::from(value), blind_scalar);

        let out = slice::from_raw_parts_mut(commitment_out, 32);
        out.copy_from_slice(commitment.compress().as_bytes());
    }

    0
}

/// Verify that a commitment opens to a specific value with given blinding factor
#[no_mangle]
pub extern "C" fn blocknet_pedersen_verify(
    value: u64,
    blinding: *const u8,
    commitment: *const u8,
) -> i32 {
    if blinding.is_null() || commitment.is_null() {
        return -1;
    }

    unsafe {
        let blind_bytes = slice::from_raw_parts(blinding, 32);
        let commit_bytes = slice::from_raw_parts(commitment, 32);

        // Use from_bytes_mod_order to handle non-canonical scalars (hash outputs)
        let blind_scalar = Scalar::from_bytes_mod_order(
            blind_bytes.try_into().expect("slice length")
        );

        let compressed = CompressedRistretto::from_slice(commit_bytes)
            .expect("slice length");

        let pc_gens = PedersenGens::default();
        let expected = pc_gens.commit(Scalar::from(value), blind_scalar);

        if expected.compress() == compressed {
            0
        } else {
            -1
        }
    }
}

/// Add two Pedersen commitments: C1 + C2
/// Used for summing commitments in transaction validation
#[no_mangle]
pub extern "C" fn blocknet_commitment_add(
    c1: *const u8,
    c2: *const u8,
    result_out: *mut u8,
) -> i32 {
    if c1.is_null() || c2.is_null() || result_out.is_null() {
        return -1;
    }

    unsafe {
        let c1_bytes = slice::from_raw_parts(c1, 32);
        let c2_bytes = slice::from_raw_parts(c2, 32);

        let p1 = match CompressedRistretto::from_slice(c1_bytes)
            .expect("len")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let p2 = match CompressedRistretto::from_slice(c2_bytes)
            .expect("len")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let sum = p1 + p2;
        let out = slice::from_raw_parts_mut(result_out, 32);
        out.copy_from_slice(sum.compress().as_bytes());
    }

    0
}

/// Subtract two Pedersen commitments: C1 - C2
#[no_mangle]
pub extern "C" fn blocknet_commitment_sub(
    c1: *const u8,
    c2: *const u8,
    result_out: *mut u8,
) -> i32 {
    if c1.is_null() || c2.is_null() || result_out.is_null() {
        return -1;
    }

    unsafe {
        let c1_bytes = slice::from_raw_parts(c1, 32);
        let c2_bytes = slice::from_raw_parts(c2, 32);

        let p1 = match CompressedRistretto::from_slice(c1_bytes)
            .expect("len")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let p2 = match CompressedRistretto::from_slice(c2_bytes)
            .expect("len")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        let diff = p1 - p2;
        let out = slice::from_raw_parts_mut(result_out, 32);
        out.copy_from_slice(diff.compress().as_bytes());
    }

    0
}

/// Check if a commitment point is the identity (zero)
/// Returns 0 if identity, -1 if not
#[no_mangle]
pub extern "C" fn blocknet_commitment_is_zero(commitment: *const u8) -> i32 {
    if commitment.is_null() {
        return -1;
    }

    unsafe {
        let bytes = slice::from_raw_parts(commitment, 32);

        let point = match CompressedRistretto::from_slice(bytes)
            .expect("len")
            .decompress()
        {
            Some(p) => p,
            None => return -1,
        };

        use curve25519_dalek::traits::Identity;
        if point == RistrettoPoint::identity() {
            0
        } else {
            -1
        }
    }
}

/// Create a commitment to the fee (fee * H where H is the blinding generator)
/// This is needed for balance verification
#[no_mangle]
pub extern "C" fn blocknet_fee_commitment(
    fee: u64,
    commitment_out: *mut u8,
) -> i32 {
    if commitment_out.is_null() {
        return -1;
    }

    let pc_gens = PedersenGens::default();
    
    // Fee commitment = fee * B (value generator only, no blinding)
    let commitment = Scalar::from(fee) * pc_gens.B;

    unsafe {
        let out = slice::from_raw_parts_mut(commitment_out, 32);
        out.copy_from_slice(commitment.compress().as_bytes());
    }

    0
}

/// Compute blinding factor: result = b1 + b2
#[no_mangle]
pub extern "C" fn blocknet_blinding_add(
    b1: *const u8,
    b2: *const u8,
    result_out: *mut u8,
) -> i32 {
    if b1.is_null() || b2.is_null() || result_out.is_null() {
        return -1;
    }

    unsafe {
        let b1_bytes = slice::from_raw_parts(b1, 32);
        let b2_bytes = slice::from_raw_parts(b2, 32);

        // Use from_bytes_mod_order for hash-derived blindings
        let s1 = Scalar::from_bytes_mod_order(b1_bytes.try_into().expect("len"));
        let s2 = Scalar::from_bytes_mod_order(b2_bytes.try_into().expect("len"));

        let sum = s1 + s2;
        let out = slice::from_raw_parts_mut(result_out, 32);
        out.copy_from_slice(sum.as_bytes());
    }

    0
}

/// Compute blinding factor: result = b1 - b2
#[no_mangle]
pub extern "C" fn blocknet_blinding_sub(
    b1: *const u8,
    b2: *const u8,
    result_out: *mut u8,
) -> i32 {
    if b1.is_null() || b2.is_null() || result_out.is_null() {
        return -1;
    }

    unsafe {
        let b1_bytes = slice::from_raw_parts(b1, 32);
        let b2_bytes = slice::from_raw_parts(b2, 32);

        // Use from_bytes_mod_order for hash-derived blindings
        let s1 = Scalar::from_bytes_mod_order(b1_bytes.try_into().expect("len"));
        let s2 = Scalar::from_bytes_mod_order(b2_bytes.try_into().expect("len"));

        let diff = s1 - s2;
        let out = slice::from_raw_parts_mut(result_out, 32);
        out.copy_from_slice(diff.as_bytes());
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_arithmetic() {
        // Create two commitments
        let mut b1 = [0u8; 32];
        let mut c1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        let mut c2 = [0u8; 32];

        blocknet_pedersen_commit(100, b1.as_mut_ptr(), c1.as_mut_ptr());
        blocknet_pedersen_commit(50, b2.as_mut_ptr(), c2.as_mut_ptr());

        // Add them
        let mut c_sum = [0u8; 32];
        assert_eq!(blocknet_commitment_add(c1.as_ptr(), c2.as_ptr(), c_sum.as_mut_ptr()), 0);

        // c_sum should be commitment to 150 with blinding b1+b2
        let mut b_sum = [0u8; 32];
        blocknet_blinding_add(b1.as_ptr(), b2.as_ptr(), b_sum.as_mut_ptr());

        assert_eq!(blocknet_pedersen_verify(150, b_sum.as_ptr(), c_sum.as_ptr()), 0);
    }

    #[test]
    fn test_commitment_balance() {
        // Simulate: input of 100, outputs of 70 + 25, fee of 5
        let mut b_in = [0u8; 32];
        let mut c_in = [0u8; 32];
        blocknet_pedersen_commit(100, b_in.as_mut_ptr(), c_in.as_mut_ptr());

        let mut b_out1 = [0u8; 32];
        let mut c_out1 = [0u8; 32];
        blocknet_pedersen_commit(70, b_out1.as_mut_ptr(), c_out1.as_mut_ptr());

        // For balance: b_out2 = b_in - b_out1
        let mut b_out2 = [0u8; 32];
        blocknet_blinding_sub(b_in.as_ptr(), b_out1.as_ptr(), b_out2.as_mut_ptr());

        // Create c_out2 with the computed blinding
        let pc_gens = PedersenGens::default();
        let b2_scalar = Scalar::from_canonical_bytes(b_out2).unwrap();
        let c_out2_point = pc_gens.commit(Scalar::from(25u64), b2_scalar);
        let c_out2 = c_out2_point.compress().to_bytes();

        // Fee commitment
        let mut c_fee = [0u8; 32];
        blocknet_fee_commitment(5, c_fee.as_mut_ptr());

        // Verify balance: c_in - c_out1 - c_out2 - c_fee = 0
        let mut temp1 = [0u8; 32];
        let mut temp2 = [0u8; 32];
        let mut temp3 = [0u8; 32];

        blocknet_commitment_sub(c_in.as_ptr(), c_out1.as_ptr(), temp1.as_mut_ptr());
        blocknet_commitment_sub(temp1.as_ptr(), c_out2.as_ptr(), temp2.as_mut_ptr());
        blocknet_commitment_sub(temp2.as_ptr(), c_fee.as_ptr(), temp3.as_mut_ptr());

        assert_eq!(blocknet_commitment_is_zero(temp3.as_ptr()), 0);
    }

    #[test]
    fn test_pedersen_commit_verify() {
        let value = 1000u64;
        let mut blinding = [0u8; 32];
        let mut commitment = [0u8; 32];

        let result = blocknet_pedersen_commit(
            value,
            blinding.as_mut_ptr(),
            commitment.as_mut_ptr(),
        );
        assert_eq!(result, 0);

        let verify_result = blocknet_pedersen_verify(
            value,
            blinding.as_ptr(),
            commitment.as_ptr(),
        );
        assert_eq!(verify_result, 0);

        // Wrong value should fail
        let wrong_result = blocknet_pedersen_verify(
            value + 1,
            blinding.as_ptr(),
            commitment.as_ptr(),
        );
        assert_eq!(wrong_result, -1);
    }
}

