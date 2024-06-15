use cryptography::sha::{sha2, Hash256};
use hex::FromHex;

#[test]
fn empty_string_256() {
    assert_eq!(
        sha2(b""),
        Hash256::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap(),
    );
}
