mod encryption {
    use cryptography::*;

    #[test]
    fn aes_128_basic_with_zero_key() {
        let key: Block<16> = [0; 16];

        let cipher = aes::aes_128(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext[..16],
            &0xb49cbf19d357e6e1f6845c30fd5b63e3_u128.to_be_bytes()
        );
    }

    #[test]
    fn aes_128_basic_with_actual_key() {
        let key: Block<16> = 0x12345678901234567890123456789012_u128.to_be_bytes();

        let cipher = aes::aes_128(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext[..16],
            &0x6137ea77f33803f0b809f6aa5cf86616_u128.to_be_bytes()
        );
        assert_eq!(
            &ciphertext[16..32],
            &0x4923331c01b6fe7d220360df6a7f6fb2_u128.to_be_bytes()
        );
    }
}

mod decryption {
    use cryptography::*;

    #[test]
    fn aes_128_basic_with_zero_key() {
        let key: Block<16> = [0; 16];

        let cipher = aes::aes_128(key);

        let ciphertext = [
            0xb49cbf19d357e6e1f6845c30fd5b63e3_u128.to_be_bytes(),
            0x143db63ee66b0cdff9f69917680151e_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }

    #[test]
    fn aes_128_basic_with_actual_key() {
        let key: Block<16> = 0x12345678901234567890123456789012_u128.to_be_bytes();

        let cipher = aes::aes_128(key);

        let ciphertext = [
            0x6137ea77f33803f0b809f6aa5cf86616_u128.to_be_bytes(),
            0x4923331c01b6fe7d220360df6a7f6fb2_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }
}
