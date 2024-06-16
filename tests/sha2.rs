use cryptography::sha::{sha224, sha256, Hash224, Hash256};
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
fn empty_string_256() {
    assert_eq!(
        sha256(b""),
        Hash256::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap(),
    );
}
