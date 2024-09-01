use std::str::FromStr;

use cryptography::{big::BigUint, pem::PEM, rsa::{create_keys, PrivateKey, PublicKey, RsaEncryption, RsaPadding}};

#[test]
fn tiny_example_without_padding() {
    let (priv_key, pub_key) = create_keys(61.into(), 53.into(), 17.into());
    let ciphertext = RsaEncryption::from(priv_key).encrypt(BigUint::from_be_bytes(b"a"));
    assert_eq!(RsaEncryption::from(pub_key).decrypt(ciphertext), BigUint::from_be_bytes(b"a"));
}

#[test]
fn tiny_example_without_padding_but_bigger_primes() {
    let (priv_key, pub_key) = create_keys(190238395574637701.into(), 725918707442996609.into(), 17.into());
    let ciphertext = RsaEncryption::from(priv_key).encrypt(BigUint::from_be_bytes(b"a"));
    assert_eq!(RsaEncryption::from(pub_key).decrypt(ciphertext), BigUint::from_be_bytes(b"a"));
}

static EXAMPLE_PRIVATE_KEY: &str = "
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCj23oTvEIyLdFI
qqbsif/P28saN2ObxkPSPbi2uv4Tq7wZK9Ccc/QEXYW3CB3GACLuvbRyRz2Db8Qr
6Uz0NlA2osiyFv4sZBhJKXeJ9o5UWvuFgO/XyBcLjbWHGlFBFBRCvd01lMEz3Ld1
q/NDVVTRJYYQytCVR6xtKHVjpxoNXJsFCBLGVI2wwWvWDY06Dmvx+Yf+q53frpvV
T4qJOqd8lcSjC6f7+PRPS9rRLZ0xX5ro3RWd2u+HEj8oL1ynGvqk/lTGbyjPdWy2
AYgxwlAFyfYqfwS0g25Xu+RyS5d9WCc1mDyweoU5S4HMnRUxILOXpw9NXIDlIhDg
BT6GT/WjAgMBAAECggEAA9PScAKTk0N8Yij7pDEnBLkaxJPVo6OyctyWjiIjttw/
P7aadVpvW+i+q63+BWF8b2eGqa1d/k4j3sNg1PWDKHuN75Gs7JGGpbLZGXkPuGBg
WVfP17z97iWoagL53JN2U7FxU4PpgrzIRkXhdUmuz6yDi1c0HxXhAl28ZuWrgfNb
EnoMqt1cmt3BHLrx2WWQE2lKKo8AAcWgsnJRPYRJQo+fKZWIAb/dK2FZYnZFS2k6
9KjGOA9mJ7IvJpXc+eldgDDsxa517u5KElSLo09LYelnWOtVaYyjEpvKMvw8PUbA
WuRFEhcl4YJiUCOz6jyVaVf6nBPP79SY8tcTY995rQKBgQDUkhSEt8iiSAEWkehn
MWaIKXhN6gJRGUX6lYJOYO0OSjRcGj20MsTAb6JSqQ643k6l88Nw0E1j7TRyjRaw
eIjp2cVkP0RPqvvVm4PeScP7gKdF/CHCXm2qsLPuC3mYb4FCMCJdfJ6IpHTEdudy
x//ZX8Rd/dNQaEZJWM2vQLSuvQKBgQDFVZUS/ZFjMNYwHbNkPeCVxm/ZlkOV8rOx
bh8shXkkqeKx4r3MqcIxmmX7k5E71qvjnKc5PxwSe7x9kqYjXtCYmjV2Nb5aX39b
98ySxOoeeHY7SiZaPeJgaqgPlFFNwuT5wv5rufDImkHhLHT9wXs3CutQDrhDFQDi
r3zBB/or3wKBgDYuBYzOSxURxTU7e0DSFpAeAcvaGT0SdAOql8viaIl74FyZU6Da
T8u8qGLpNBdqkiE6QFZAwXj2vKd1zpKsJjl0iBtFBORJcGbBfJrrskgoQnpUCUbB
SrJ212WVBykTQp7cJeYuHTo2sIxiwhs/XrbI8gQC7hlQepm3SLWiiGsBAoGASYeO
OLlLR06XQO6QPbXgzW5XlxgqruD0nBSQgSJq9YJn+iim2HAY8Cq7/XYLE+T1v6ZL
mUUuzKRWo+PVDDD0QSiU6yszdrFG35oCHF5LbncsdwM2L0IH7C1R2hxF/1ezwm0q
KDHsypLQIXtTTIqfwu7Kp9YUSsq0vcLuFW9HhLkCgYA3gnUWPjqadRfGR90ln2EK
HyIQLTxqjR6cYCZt/9PFDHDo+MWmelW0eiB+dU5pDqA0BKpQDXUqaG88loTgSXvC
X63EaFCijMfKf+XAkFSxROwc1JANNmmpMQeXPO4QK6F3aLb4DUatsHt8bWOnhDHo
2JSZ+LvcL83PncYRSsCA+w==
-----END PRIVATE KEY-----
";

static EXAMPLE_PUBLIC_KEY: &str = "
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo9t6E7xCMi3RSKqm7In/
z9vLGjdjm8ZD0j24trr+E6u8GSvQnHP0BF2FtwgdxgAi7r20ckc9g2/EK+lM9DZQ
NqLIshb+LGQYSSl3ifaOVFr7hYDv18gXC421hxpRQRQUQr3dNZTBM9y3davzQ1VU
0SWGEMrQlUesbSh1Y6caDVybBQgSxlSNsMFr1g2NOg5r8fmH/qud366b1U+KiTqn
fJXEowun+/j0T0va0S2dMV+a6N0VndrvhxI/KC9cpxr6pP5Uxm8oz3VstgGIMcJQ
Bcn2Kn8EtINuV7vkckuXfVgnNZg8sHqFOUuBzJ0VMSCzl6cPTVyA5SIQ4AU+hk/1
owIDAQAB
-----END PUBLIC KEY-----
";

#[test]
fn example_encrypt_e2e_big() {
    let private_key_pem = PEM::from_str(EXAMPLE_PRIVATE_KEY).unwrap();
    let public_key_pem = PEM::from_str(EXAMPLE_PUBLIC_KEY).unwrap();

    let private_key = PrivateKey::try_from(private_key_pem).unwrap();
    let public_key = PublicKey::try_from(public_key_pem).unwrap();

    let plaintext = b"Hello World!";
    let ciphertext = RsaEncryption::from(public_key).encrypt_message(plaintext, RsaPadding);
    let decrypted = RsaEncryption::from(private_key).decrypt_message(&ciphertext, RsaPadding);

    assert_eq!(decrypted, plaintext);
}
