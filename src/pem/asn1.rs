#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Asn1 {
    Integer(Vec<u8>),
    OctetString(Vec<u8>),
    BitString(Vec<u8>, u8), // bytes of data, unused bits in last byte (lsb)
    Null,
    ObjectIdentifier(Vec<u8>),
    Sequence(Vec<Asn1>),
}

impl Asn1 {
    fn parse_from_bytes(bytes: &[u8]) -> Result<(Asn1, &[u8]), String> {
        if bytes.len() == 1 {
            return Err("tag had no length".to_string());
        }
        let tag = bytes[0];
        let (rest, length) = if bytes[1] & 0x80 != 0 {
            let length_bytes = (bytes[1] & !0x80) as usize;
            let mut length = 0u128.to_be_bytes();
            length[(16 - length_bytes)..].copy_from_slice(&bytes[2..(2 + length_bytes)]);
            (
                &bytes[(2 + length_bytes)..],
                <u128>::from_be_bytes(length) as usize,
            )
        } else {
            (&bytes[2..], bytes[1] as usize)
        };

        if length > rest.len() {
            let actual_length = rest.len();
            return Err(format!(
                "tag ({tag}) had too little data, expected {length} bytes, got {actual_length}"
            ));
        }

        let asn1 = match tag {
            0x02 => Asn1::Integer(rest[..length].to_owned()),
            0x04 => Asn1::OctetString(rest[..length].to_owned()),
            0x03 => Asn1::BitString(rest[1..length].to_owned(), rest[0]),
            0x05 => Asn1::Null,
            0x06 => Asn1::ObjectIdentifier(rest[..length].to_owned()),
            0x30 => {
                let mut left = &*rest[..length].to_owned();
                let mut elements = Vec::new();
                while !left.is_empty() {
                    let (asn1, rest) = Asn1::parse_from_bytes(left).map_err(|e| format!("failed to parse sequence: {}", e))?;
                    elements.push(asn1);
                    left = rest;
                }
                Asn1::Sequence(elements)
            }
            _ => return Err(format!("unknown tag: {}", tag)),
        };

        Ok((asn1, &rest[length..]))
    }
}

impl TryFrom<&[u8]> for Asn1 {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (asn1, left) = Asn1::parse_from_bytes(bytes)?;

        if !left.is_empty() {
            return Err("extra bytes at the end".to_string());
        }

        Ok(asn1)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::pem::asn1::*;
    use crate::pem::PEM;

    #[test]
    fn small_example_1() {
        let bytes = hex::decode("3003020109").unwrap();
        let asn1 = Asn1::try_from(&*bytes).unwrap();
        assert_eq!(asn1, Asn1::Sequence(vec![Asn1::Integer(vec![9])]));
    }

    #[test]
    fn small_example_2() {
        let bytes = hex::decode("300b0201043006020406070809").unwrap();
        let asn1 = Asn1::try_from(&*bytes).unwrap();
        assert_eq!(
            asn1,
            Asn1::Sequence(vec![
                Asn1::Integer(vec![4]),
                Asn1::Sequence(vec![Asn1::Integer(vec![6, 7, 8, 9])])
            ])
        );
    }

    #[test]
    fn rsa_example() {
        let pem = PEM::from_str(
            "
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
            ",
        )
        .unwrap();

        let Ok(Asn1::Sequence(seq)) = Asn1::try_from(&*pem.data) else {
            panic!();
        };
        assert_eq!(seq.len(), 3);
        assert_eq!(seq[0], Asn1::Integer(vec![0]));
        assert_eq!(
            seq[1],
            Asn1::Sequence(vec![
                Asn1::ObjectIdentifier(vec![42, 134, 72, 134, 247, 13, 1, 1, 1]),
                Asn1::Null
            ]),
        );
        if let Asn1::OctetString(bytes) = &seq[2] {
            let Asn1::Sequence(seq) = Asn1::try_from(bytes.as_slice()).unwrap() else {
                panic!();
            };
            assert_eq!(seq.len(), 9);
            assert_eq!(seq[0], Asn1::Integer(vec![0]));
            assert_eq!(seq[2], Asn1::Integer(vec![1, 0, 1]));
        } else {
            panic!();
        };
    }
}
