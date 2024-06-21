use crate::HashFunction;

pub fn mgf1<const N: usize, H>(seed: &[u8], output_size: usize, hasher: H) -> Vec<u8>
where
    H: HashFunction,
    H::Output: Into<[u8; N]>,
{
    let mut output = Vec::with_capacity(output_size + N);

    let mut hash_content = Vec::with_capacity(seed.len() + 4);
    hash_content.extend_from_slice(seed);
    hash_content.extend([0, 0, 0, 0]);

    let mut counter: u32 = 0;
    while output.len() < output_size {
        hash_content[seed.len()..].copy_from_slice(&counter.to_be_bytes());
        output.extend(hasher.hash(&hash_content).into());
        counter += 1;
    }

    output.truncate(output_size);
    output
}

#[cfg(test)]
mod tests {
    use hex::ToHex;

    use crate::sha::{Sha1, Sha256};

    use super::*;

    #[test]
    fn mgf1_short_sha1() {
        assert_eq!(mgf1(b"foo", 3, Sha1).encode_hex::<String>(), "1ac907");
        assert_eq!(mgf1(b"foo", 5, Sha1).encode_hex::<String>(), "1ac9075cd4");
        assert_eq!(mgf1(b"bar", 5, Sha1).encode_hex::<String>(), "bc0c655e01");
    }

    #[test]
    fn mgf1_long_sha1() {
        assert_eq!(
            mgf1(b"bar", 50, Sha1).encode_hex::<String>(),
            "bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876",
        );
    }

    #[test]
    fn mgf1_long_sha256() {
        assert_eq!(
            mgf1(b"bar", 50, Sha256).encode_hex::<String>(),
            "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1",
        );
    }
}
