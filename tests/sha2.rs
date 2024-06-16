use cryptography::sha::{sha224, sha256, sha384, sha512, Hash224, Hash256, Hash384, Hash512};
use hex::FromHex;

#[test]
fn empty_string_224() {
    assert_eq!(
        sha224(b""),
        Hash224::from_hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
            .unwrap(),
    );
}

#[test]
fn font_example_224() {
    assert_eq!(
        sha224(b"The quick brown fox jumps over the lazy dog"),
        Hash224::from_hex("730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525")
            .unwrap(),
    );
}

#[test]
fn empty_string_256() {
    assert_eq!(
        sha256(b""),
        Hash256::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap(),
    );
}

#[test]
fn empty_string_384() {
    assert_eq!(
        sha384(b""),
        Hash384::from_hex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
            .unwrap(),
    );
}

#[test]
fn empty_string_512() {
    assert_eq!(
        sha512(b""),
        Hash512::from_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
            .unwrap(),
    );
}
