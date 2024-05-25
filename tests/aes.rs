mod encryption {
    use cryptography::aes::{Aes, Key128, Key192, Key256};
    use cryptography::*;

    #[test]
    fn aes_128_basic_with_zero_key() {
        let key = Key128::from([0u64, 0u64]);
        let cipher = Aes::from(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext,
            &[
                0xb49cbf19d357e6e1f6845c30fd5b63e3_u128.to_be_bytes(),
                0x0143db63ee66b0cdff9f69917680151e_u128.to_be_bytes(),
            ]
            .concat()
        );
    }

    #[test]
    fn aes_128_basic_with_actual_key() {
        let key = Key128::from([0x1234567890123456_u64, 0x7890123456789012_u64]);
        let cipher = Aes::from(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext,
            &[
                0x6137ea77f33803f0b809f6aa5cf86616_u128.to_be_bytes(),
                0x4923331c01b6fe7d220360df6a7f6fb2_u128.to_be_bytes()
            ].concat()
        );
    }

    #[test]
    fn aes_192_basic_with_zero_key() {
        let key = Key192::from([0u64, 0u64, 0u64]);
        let cipher = Aes::from(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext,
            &[
                0x485e404701da678874724d32da51d124_u128.to_be_bytes(),
                0x02bb292527e726fd51eb29894d6f0aad_u128.to_be_bytes(),
            ].concat()
        );
    }

    #[test]
    fn aes_192_basic_with_actual_key() {
        let key = Key192::from([
            0x1234567890123456_u64,
            0x7890123456789012_u64,
            0x3456789012345678_u64,
        ]);
        let cipher = Aes::from(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext,
            &[
                0xb0c07954a70642e19e4e3d63953f3879_u128.to_be_bytes(),
                0x9b210281fdbeb72a59b2ffd354000680_u128.to_be_bytes(),
            ].concat()
        );
    }

    #[test]
    fn aes_256_basic_with_zero_key() {
        let key = Key256::from([0u64, 0u64, 0u64, 0u64]);
        let cipher = Aes::from(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext,
            &[
                0x7e0e7577ef9c30a6bf0b25e0621e827e_u128.to_be_bytes(),
                0x1f788fe6d86c317549697fbf0c07fa43_u128.to_be_bytes(),
            ].concat()
        );
    }

    #[test]
    fn aes_256_basic_with_actual_key() {
        let key = Key256::from([
            0x1234567890123456_u64,
            0x7890123456789012_u64,
            0x3456789012345678_u64,
            0x9012345678901234_u64,
        ]);
        let cipher = Aes::from(key);

        let plaintext = "AAAAAAAAAAAAAAAA".as_bytes();

        let mut ciphertext = Vec::new();
        BlockEncryption::encrypt(cipher, EcbMode, plaintext, |b| ciphertext.push(b));

        assert_eq!(
            &ciphertext,
            &[
                0xd9e18e553e64ee1e838b8955f7bc2f63_u128.to_be_bytes(),
                0xd16ca6866d9baf8029ebeec07830b231_u128.to_be_bytes(),
            ].concat()
        );
    }
}

mod decryption {
    use cryptography::aes::{Aes, Key128, Key192, Key256};
    use cryptography::*;

    #[test]
    fn aes_128_basic_with_zero_key() {
        let key = Key128::from([0u64, 0u64]);
        let cipher = Aes::from(key);

        let ciphertext = [
            0xb49cbf19d357e6e1f6845c30fd5b63e3_u128.to_be_bytes(),
            0x0143db63ee66b0cdff9f69917680151e_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }

    #[test]
    fn aes_128_basic_with_actual_key() {
        let key = Key128::from([0x1234567890123456_u64, 0x7890123456789012_u64]);
        let cipher = Aes::from(key);

        let ciphertext = [
            0x6137ea77f33803f0b809f6aa5cf86616_u128.to_be_bytes(),
            0x4923331c01b6fe7d220360df6a7f6fb2_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }

    #[test]
    fn aes_192_basic_with_zero_key() {
        let key = Key192::from([0u64, 0u64, 0u64]);
        let cipher = Aes::from(key);

        let ciphertext = [
            0x485e404701da678874724d32da51d124_u128.to_be_bytes(),
            0x02bb292527e726fd51eb29894d6f0aad_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }

    #[test]
    fn aes_192_basic_with_actual_key() {
        let key = Key192::from([
            0x1234567890123456_u64,
            0x7890123456789012_u64,
            0x3456789012345678_u64,
        ]);
        let cipher = Aes::from(key);

        let ciphertext = [
            0xb0c07954a70642e19e4e3d63953f3879_u128.to_be_bytes(),
            0x9b210281fdbeb72a59b2ffd354000680_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }

    #[test]
    fn aes_256_basic_with_zero_key() {
        let key = Key256::from([0u64, 0u64, 0u64, 0u64]);
        let cipher = Aes::from(key);

        let ciphertext = [
            0x7e0e7577ef9c30a6bf0b25e0621e827e_u128.to_be_bytes(),
            0x1f788fe6d86c317549697fbf0c07fa43_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }

    #[test]
    fn aes_256_basic_with_actual_key() {
        let key = Key256::from([
            0x1234567890123456_u64,
            0x7890123456789012_u64,
            0x3456789012345678_u64,
            0x9012345678901234_u64,
        ]);
        let cipher = Aes::from(key);

        let ciphertext = [
            0xd9e18e553e64ee1e838b8955f7bc2f63_u128.to_be_bytes(),
            0xd16ca6866d9baf8029ebeec07830b231_u128.to_be_bytes(),
        ]
        .concat();

        let mut plaintext = Vec::new();
        BlockEncryption::decrypt(cipher, EcbMode, &ciphertext, |b| plaintext.push(b));

        assert_eq!(plaintext, "AAAAAAAAAAAAAAAA".as_bytes());
    }
}
