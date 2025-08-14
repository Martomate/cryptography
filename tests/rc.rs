use cryptography::{rc2, rc4, BlockEncryption, EcbMode};

#[test]
fn rc2_ecb_examples_80() {
    let mut output = Vec::new();
    BlockEncryption::encrypt(
        rc2::from_key(
            &[0x26, 0x1E, 0x57, 0x8E, 0xC9, 0x62, 0xBF, 0xB8, 0x3E, 0x96],
            80,
        ),
        EcbMode,
        &[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, //
        ],
        |b| output.push(b),
    );
    assert_eq!(
        &output,
        &[
            0xF9, 0x9A, 0x3A, 0xDB, 0x00, 0x3B, 0x7A, 0xEB, //
            0x81, 0xE3, 0x6B, 0xA9, 0xE5, 0x37, 0x10, 0xD1, //
            0xFC, 0x68, 0x98, 0x27, 0x2E, 0xCA, 0xA1, 0xA1, //
        ]
    );
}

#[test]
fn rc2_ecb_examples_128() {
    let mut output = Vec::new();
    BlockEncryption::encrypt(
        rc2::from_key(
            &[0x26, 0x1E, 0x57, 0x8E, 0xC9, 0x62, 0xBF, 0xB8, 0x3E, 0x96],
            128,
        ),
        EcbMode,
        &[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, //
        ],
        |b| output.push(b),
    );
    assert_eq!(
        &output,
        &[
            0x0A, 0xD2, 0x1F, 0xAD, 0x6C, 0xA1, 0x86, 0xBD, //
            0xEB, 0xDD, 0x07, 0x27, 0x75, 0x87, 0xDC, 0x5E, //
            0xF4, 0x26, 0xE8, 0xA0, 0x90, 0xE7, 0x5D, 0x07, //
        ]
    );
}

#[test]
fn rc4_examples() {
    fn check(key: &[u8], plaintext: &[u8], expected_ciphertext_hex: &str) {
        let expected_ciphertext = hex::decode(expected_ciphertext_hex).unwrap();
        
        let ciphertext = rc4::new(key).encrypt(plaintext);
        assert_eq!(ciphertext, expected_ciphertext);

        let decrypted = rc4::new(key).decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    check(b"Key", b"Plaintext", "BBF316E8D940AF0AD3");
    check(b"Wiki", b"pedia", "1021BF0420");
    check(b"Secret", b"Attack at dawn", "45A01F645FC35B383552544B9BF5");
}
