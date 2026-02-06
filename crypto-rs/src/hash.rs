use sha2::{Digest, Sha256};
use std::slice;

/// Hash data using SHA256
#[no_mangle]
pub extern "C" fn blocknet_sha256(
    data: *const u8,
    data_len: usize,
    hash_out: *mut u8,
) -> i32 {
    if data.is_null() || hash_out.is_null() {
        return -1;
    }

    unsafe {
        let input = slice::from_raw_parts(data, data_len);
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        
        let out_slice = slice::from_raw_parts_mut(hash_out, 32);
        out_slice.copy_from_slice(&result);
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let mut hash = [0u8; 32];

        let result = blocknet_sha256(
            data.as_ptr(),
            data.len(),
            hash.as_mut_ptr(),
        );
        assert_eq!(result, 0);
        
        // Known SHA256 of "hello world"
        let expected = hex::decode(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ).unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }
}

