use cryptography::sha::{sha1, Hash160};
use hex::FromHex;

#[test]
fn empty_string() {
    assert_eq!(
        sha1(b""),
        Hash160::from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
    );
}

#[test]
fn short_string() {
    assert_eq!(
        sha1(b"A"),
        Hash160::from_hex("6dcd4ce23d88e2ee9568ba546c007c63d9131c1b").unwrap(),
    );
}

#[test]
fn font_example() {
    assert_eq!(
        sha1(b"The quick brown fox jumps over the lazy dog"),
        Hash160::from_hex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap(),
    );
}

#[test]
fn large_message() {
    let message = &[b'A'; 10000];
    assert_eq!(
        sha1(message),
        Hash160::from_hex("bf6db7112b56812702e99d48a7b1dab62d09b3f6").unwrap(),
    );
}
