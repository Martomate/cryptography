use crate::md::md2::*;
use crate::md::md4::*;

fn check_hash(hash_fn: impl FnOnce(&[u8]) -> [u8; 16], input: &[u8], expected_hash: u128) {
    let expected_hash = expected_hash.to_be_bytes();
    assert_eq!(hash_fn(input), expected_hash, "input = {:?}", input);
}

#[test]
fn md2_examples() {
    check_hash(md2, b"", 0x_8350e5a3e24c153df2275c9f80692773_u128);
    check_hash(
        md2,
        b"The quick brown fox jumps over the lazy dog",
        0x_03d85a0d629d2c442e987525319fc471_u128,
    );
    check_hash(
        md2,
        b"The quick brown fox jumps over the lazy cog",
        0x_6b890c9292668cdbbfda00a4ebf31f05_u128,
    );
}

#[test]
fn md4_examples() {
    check_hash(md4, b"", 0x_31d6cfe0d16ae931b73c59d7e0c089c0_u128);
    check_hash(md4, b"a", 0x_bde52cb31de33e46245e05fbdbd6fb24_u128);
    check_hash(
        md4,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        0x_043f8582f241db351ce627e153e7f0e4_u128,
    );
    check_hash(
        md4,
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        0x_e33b4ddc9c38f2199c3e7b164fcc0536_u128,
    );
}
