use cryptography::rsa::{create_keys, RsaEncryption, RsaPadding};

#[test]
fn tiny_example_without_padding() {
    let (priv_key, pub_key) = create_keys(61, 53, 17);
    let ciphertext = RsaEncryption::from(priv_key).encrypt(b"a");
    assert_eq!(RsaEncryption::from(pub_key).decrypt(&ciphertext), b"a");
}

#[test]
#[ignore]
fn tiny_example_with_padding() {
    let (priv_key, pub_key) = create_keys(785087788831, 730813580449, 13);
    let ciphertext = RsaEncryption::from(priv_key).encrypt_message(b"a", RsaPadding);
    assert_eq!(RsaEncryption::from(pub_key).decrypt_message(&ciphertext, RsaPadding), b"a");
}
