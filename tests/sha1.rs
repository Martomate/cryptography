use cryptography::sha::{sha1, Hash160};

#[test]
fn empty_string() {
    assert_eq!(
        sha1(b""),
        Hash160::from([0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709]),
    );
}

#[test]
fn short_string() {
    assert_eq!(
        sha1(b"A"),
        Hash160::from([0x6dcd4ce2, 0x3d88e2ee, 0x9568ba54, 0x6c007c63, 0xd9131c1b]),
    );
}

#[test]
fn font_example() {
    assert_eq!(
        sha1(b"The quick brown fox jumps over the lazy dog"),
        Hash160::from([0x2fd4e1c6, 0x7a2d28fc, 0xed849ee1, 0xbb76e739, 0x1b93eb12]),
    );
}

#[test]
fn large_message() {
    let message = &[b'A'; 10000];
    assert_eq!(
        sha1(message),
        Hash160::from([0xbf6db711, 0x2b568127, 0x02e99d48, 0xa7b1dab6, 0x2d09b3f6]),
    );
}
