use crate::{big::BigUint, pem::asn1::Asn1};

pub struct PrivateKeyInfo {
    version: u32,
    private_key_algorithm: AlgorithmIdentifier,
    pub private_key: PrivateKey,
}

pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    pub subject_public_key: PublicKey,
}

struct AlgorithmIdentifier {
    algorithm: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrivateKey {
    version: u8,
    pub modulus: BigUint,          // n
    pub public_exponent: BigUint,  // e
    pub private_exponent: BigUint, // d
    pub prime1: BigUint,           // p
    pub prime2: BigUint,           // q
    pub exponent1: BigUint,        // d % (p-1)
    pub exponent2: BigUint,        // d % (q-1)
    pub coefficient: BigUint,      // (inverse of q) mod p
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub modulus: BigUint,         // n
    pub public_exponent: BigUint, // e
}

impl PrivateKeyInfo {
    fn from_asn1(asn: Asn1) -> Result<Self, String> {
        let Asn1::Sequence(seq) = asn else {
            return Err(format!(
                "expected content to be wrapped in a sequence tag, but found tag {:?}",
                asn
            ));
        };
        if seq.len() != 3 {
            return Err("expected three elements".to_string());
        }
        if seq[0] != Asn1::Integer(vec![0]) {
            return Err("expected first element to be be zero".to_string());
        }
        let algo = AlgorithmIdentifier::try_from(seq[1].clone())?;
        if algo.algorithm != vec![42, 134, 72, 134, 247, 13, 1, 1, 1] {
            // RSA encryption: 1 2 840 113549 1 1 1
            return Err("expected private key algorithm to be RSA".to_string());
        }

        let Asn1::OctetString(bytes) = seq[2].clone() else {
            return Err("expected third element to be an octet string".to_string());
        };

        let asn = Asn1::try_from(bytes.as_slice())
            .map_err(|e| format!("failed to parse ASN.1: {}", e))?;
        let pr: PrivateKey = PrivateKey::try_from(asn)
            .map_err(|e| format!("failed to extract private key from ASN.1: {}", e))?;

        Ok(Self {
            version: 0,
            private_key_algorithm: algo,
            private_key: pr,
        })
    }
}

impl SubjectPublicKeyInfo {
    fn from_asn1(asn: Asn1) -> Result<Self, String> {
        let Asn1::Sequence(seq) = asn else {
            return Err(format!(
                "expected content to be wrapped in a sequence tag, but found tag {:?}",
                asn
            ));
        };
        if seq.len() != 2 {
            return Err("expected two elements".to_string());
        }
        let algo = AlgorithmIdentifier::try_from(seq[0].clone())?;
        if algo.algorithm != vec![42, 134, 72, 134, 247, 13, 1, 1, 1] {
            // RSA encryption: 1 2 840 113549 1 1 1
            return Err("expected algorithm to be RSA".to_string());
        }

        let Asn1::BitString(bytes, unusued_bits) = seq[1].clone() else {
            return Err("expected second element to be a bit string".to_string());
        };
        if unusued_bits != 0 {
            return Err("bit string had unused bits which is not supported yet".to_string());
        }

        let pb: PublicKey = Asn1::try_from(bytes.as_slice())
            .map_err(|e| format!("failed to parse subject public key: {}", e))?
            .try_into()
            .map_err(|e| format!("failed to convert ASN.1 into public key: {}", e))?;

        Ok(Self {
            algorithm: algo,
            subject_public_key: pb,
        })
    }
}

impl AlgorithmIdentifier {
    fn from_asn1(asn: Asn1) -> Result<Self, String> {
        let Asn1::Sequence(seq) = asn else {
            return Err("expected sequence".to_string());
        };
        let [Asn1::ObjectIdentifier(algo), Asn1::Null] = seq.as_slice() else {
            return Err("expected object identifier".to_string());
        };

        Ok(Self {
            algorithm: algo.clone(),
        })
    }
}

impl PrivateKey {
    fn from_asn1(asn: Asn1) -> Result<Self, String> {
        let Asn1::Sequence(seq) = asn else {
            return Err(format!(
                "expected content to be wrapped in a sequence tag, but found tag {:?}",
                asn
            ));
        };

        if seq.len() != 9 {
            return Err("expected 9 elements".to_string());
        }
        #[rustfmt::skip]
        let [
            Asn1::Integer(version),
            Asn1::Integer(modulus),
            Asn1::Integer(public_exponent),
            Asn1::Integer(private_exponent),
            Asn1::Integer(prime1),
            Asn1::Integer(prime2),
            Asn1::Integer(exponent1),
            Asn1::Integer(exponent2),
            Asn1::Integer(coefficient),
        ] = seq.as_slice() else {
            return Err("expected integers".to_string());
        };

        if version.len() != 1 {
            return Err("version field must be one byte".to_string());
        }

        Ok(Self {
            version: version[0],
            modulus: BigUint::from_bytes(modulus),
            public_exponent: BigUint::from_bytes(public_exponent),
            private_exponent: BigUint::from_bytes(private_exponent),
            prime1: BigUint::from_bytes(prime1),
            prime2: BigUint::from_bytes(prime2),
            exponent1: BigUint::from_bytes(exponent1),
            exponent2: BigUint::from_bytes(exponent2),
            coefficient: BigUint::from_bytes(coefficient),
        })
    }
}

impl PublicKey {
    fn from_asn1(asn: Asn1) -> Result<Self, String> {
        let Asn1::Sequence(seq) = asn else {
            return Err(format!(
                "expected content to be wrapped in a sequence tag, but found tag {:?}",
                asn
            ));
        };

        if seq.len() != 2 {
            return Err("expected 2 elements".to_string());
        }

        #[rustfmt::skip]
        let [
            Asn1::Integer(modulus),
            Asn1::Integer(public_exponent),
        ] = seq.as_slice() else {
            return Err("expected integers".to_string());
        };

        Ok(Self {
            modulus: BigUint::from_bytes(modulus),
            public_exponent: BigUint::from_bytes(public_exponent),
        })
    }
}

impl TryFrom<Asn1> for PrivateKeyInfo {
    type Error = String;

    fn try_from(asn: Asn1) -> Result<Self, Self::Error> {
        PrivateKeyInfo::from_asn1(asn)
    }
}

impl TryFrom<Asn1> for SubjectPublicKeyInfo {
    type Error = String;

    fn try_from(asn: Asn1) -> Result<Self, Self::Error> {
        SubjectPublicKeyInfo::from_asn1(asn)
    }
}

impl TryFrom<Asn1> for AlgorithmIdentifier {
    type Error = String;

    fn try_from(asn: Asn1) -> Result<Self, Self::Error> {
        AlgorithmIdentifier::from_asn1(asn)
    }
}

impl TryFrom<Asn1> for PrivateKey {
    type Error = String;

    fn try_from(asn: Asn1) -> Result<Self, Self::Error> {
        PrivateKey::from_asn1(asn)
    }
}

impl TryFrom<Asn1> for PublicKey {
    type Error = String;

    fn try_from(asn: Asn1) -> Result<Self, Self::Error> {
        PublicKey::from_asn1(asn)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::pem::PEM;

    use super::*;

    #[test]
    fn decode_private_key_basic_example() {
        let der_hex = b"301b02010002014d02010702012b02010702010b020101020103020102";
        let der_bytes = hex::decode(der_hex).unwrap();

        let asn1 = Asn1::try_from(der_bytes.as_slice()).unwrap();
        let asn1 = PrivateKey::try_from(asn1).unwrap();

        let expected_asn1 = PrivateKey {
            version: 0,
            modulus: BigUint::from(77),
            public_exponent: BigUint::from(7),
            private_exponent: BigUint::from(43),
            prime1: BigUint::from(7),
            prime2: BigUint::from(11),
            exponent1: BigUint::from(1),
            exponent2: BigUint::from(3),
            coefficient: BigUint::from(2),
        };
        assert_eq!(asn1, expected_asn1);
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

    static EXAMPLE_N_HEX: &str = "\
        00\
        a3db7a13bc42322dd148aaa6ec89ffcfdbcb1a37639bc643d23db8b6bafe13ab\
        bc192bd09c73f4045d85b7081dc60022eebdb472473d836fc42be94cf4365036\
        a2c8b216fe2c641849297789f68e545afb8580efd7c8170b8db5871a51411414\
        42bddd3594c133dcb775abf3435554d1258610cad09547ac6d287563a71a0d5c\
        9b050812c6548db0c16bd60d8d3a0e6bf1f987feab9ddfae9bd54f8a893aa77c\
        95c4a30ba7fbf8f44f4bdad12d9d315f9ae8dd159ddaef87123f282f5ca71afa\
        a4fe54c66f28cf756cb6018831c25005c9f62a7f04b4836e57bbe4724b977d58\
        2735983cb07a85394b81cc9d153120b397a70f4d5c80e52210e0053e864ff5a3\
    ";

    static EXAMPLE_D_HEX: &str = "\
        03d3d270029393437c6228fba4312704b91ac493d5a3a3b272dc968e2223b6dc\
        3f3fb69a755a6f5be8beabadfe05617c6f6786a9ad5dfe4e23dec360d4f58328\
        7b8def91acec9186a5b2d919790fb860605957cfd7bcfdee25a86a02f9dc9376\
        53b1715383e982bcc84645e17549aecfac838b57341f15e1025dbc66e5ab81f3\
        5b127a0caadd5c9addc11cbaf1d9659013694a2a8f0001c5a0b272513d844942\
        8f9f29958801bfdd2b61596276454b693af4a8c6380f6627b22f2695dcf9e95d\
        8030ecc5ae75eeee4a12548ba34f4b61e96758eb55698ca3129bca32fc3c3d46\
        c05ae445121725e182625023b3ea3c956957fa9c13cfefd498f2d71363df79ad\
    ";

    static EXAMPLE_E_HEX: &str = "\
        010001\
    ";

    #[test]
    fn private_key_from_pem() {
        let pem = PEM::from_str(EXAMPLE_PRIVATE_KEY).unwrap();

        let expected_n = BigUint::from_bytes(hex::decode(EXAMPLE_N_HEX).unwrap());
        let expected_d = BigUint::from_bytes(hex::decode(EXAMPLE_D_HEX).unwrap());

        let asn1 = Asn1::try_from(pem.data.as_slice()).unwrap();
        let info = PrivateKeyInfo::try_from(asn1).unwrap();

        assert_eq!(info.version, 0);
        assert_eq!(
            info.private_key_algorithm.algorithm,
            vec![42, 134, 72, 134, 247, 13, 1, 1, 1]
        );
        assert_eq!(info.private_key.modulus, expected_n);
        assert_eq!(info.private_key.private_exponent, expected_d);
    }

    #[test]
    fn public_key_from_pem() {
        let pem = PEM::from_str(EXAMPLE_PUBLIC_KEY).unwrap();

        let expected_n = BigUint::from_bytes(hex::decode(EXAMPLE_N_HEX).unwrap());
        let expected_e = BigUint::from_bytes(hex::decode(EXAMPLE_E_HEX).unwrap());

        let asn1 = Asn1::try_from(pem.data.as_slice()).unwrap();
        let info = SubjectPublicKeyInfo::try_from(asn1).unwrap();

        assert_eq!(
            info.algorithm.algorithm,
            vec![42, 134, 72, 134, 247, 13, 1, 1, 1]
        );
        assert_eq!(info.subject_public_key.modulus, expected_n);
        assert_eq!(info.subject_public_key.public_exponent, expected_e);
    }
}
