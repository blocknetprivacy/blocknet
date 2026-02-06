use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::slice;

const TRANSCRIPT_LABEL: &[u8] = b"Blocknet Range Proof";
const RANGE_BITS: usize = 64;

/// Create a bulletproof range proof for a committed value
/// Proves that value is in range [0, 2^64) without revealing value
///
/// value: the secret value
/// blinding: 32-byte blinding factor (from pedersen_commit)
/// proof_out: buffer for the proof (max 1024 bytes)
/// proof_len_out: actual length of proof written
#[no_mangle]
pub extern "C" fn blocknet_range_proof_create(
    value: u64,
    blinding: *const u8,
    proof_out: *mut u8,
    proof_len_out: *mut usize,
) -> i32 {
    if blinding.is_null() || proof_out.is_null() || proof_len_out.is_null() {
        return -1;
    }

    unsafe {
        let blind_bytes = slice::from_raw_parts(blinding, 32);
        
        // Use from_bytes_mod_order to handle non-canonical scalars (hash outputs)
        let blind_scalar = Scalar::from_bytes_mod_order(
            blind_bytes.try_into().expect("slice length")
        );

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);

        let (proof, _committed_value) = match RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            value,
            &blind_scalar,
            RANGE_BITS,
        ) {
            Ok(result) => result,
            Err(_) => return -1,
        };

        let proof_bytes = proof.to_bytes();
        let proof_len = proof_bytes.len();

        if proof_len > 1024 {
            return -2; // Buffer too small
        }

        let out_slice = slice::from_raw_parts_mut(proof_out, proof_len);
        out_slice.copy_from_slice(&proof_bytes);
        *proof_len_out = proof_len;
    }

    0
}

/// Verify a bulletproof range proof
/// 
/// commitment: 32-byte Pedersen commitment
/// proof: the range proof bytes
/// proof_len: length of proof
#[no_mangle]
pub extern "C" fn blocknet_range_proof_verify(
    commitment: *const u8,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    if commitment.is_null() || proof.is_null() {
        return -1;
    }

    unsafe {
        let commit_bytes = slice::from_raw_parts(commitment, 32);
        let proof_bytes = slice::from_raw_parts(proof, proof_len);

        let compressed = CompressedRistretto::from_slice(commit_bytes)
            .expect("slice length");

        let range_proof = match RangeProof::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return -1,
        };

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);

        match range_proof.verify_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &compressed,
            RANGE_BITS,
        ) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::blocknet_pedersen_commit;

    #[test]
    fn test_range_proof() {
        let value = 1000u64;
        let mut blinding = [0u8; 32];
        let mut commitment = [0u8; 32];

        blocknet_pedersen_commit(value, blinding.as_mut_ptr(), commitment.as_mut_ptr());

        let mut proof = [0u8; 1024];
        let mut proof_len: usize = 0;

        let create_result = blocknet_range_proof_create(
            value,
            blinding.as_ptr(),
            proof.as_mut_ptr(),
            &mut proof_len,
        );
        assert_eq!(create_result, 0);
        assert!(proof_len > 0);

        let verify_result = blocknet_range_proof_verify(
            commitment.as_ptr(),
            proof.as_ptr(),
            proof_len,
        );
        assert_eq!(verify_result, 0);
    }
}

