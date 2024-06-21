use crate::HashFunction;

use super::mgf::mgf1;

pub struct OaepPadding<const N: usize, H> {
    hasher: H,
}

impl<const N: usize, H> OaepPadding<N, H>
where
    H: HashFunction,
    H::Output: Into<[u8; N]>,
{
    pub fn new(hash_function: H) -> Self {
        Self { hasher: hash_function }
    }

    pub fn encode(
        &self,
        label: &[u8],
        message: &[u8],
        n_len: usize,
    ) -> Vec<u8> {
        dbg!(n_len, message.len(), N);
        let label_hash = self.hasher.hash(label).into();
        let ps_len = n_len - message.len() - 2 * N - 2;

        // data block
        let mut db = Vec::with_capacity(n_len - N - 1);
        db.extend_from_slice(&label_hash);
        db.extend(std::iter::repeat(0).take(ps_len));
        db.push(1);
        db.extend_from_slice(message);

        // TODO: generate random seed!!
        let seed: [u8; N] = [42; N];

        let db_mask = mgf1(&seed, n_len - N - 1, self.hasher.clone());
        let masked_db = xor_slices(&db, &db_mask);

        let seed_mask = mgf1(&masked_db, N, self.hasher.clone());
        let masked_seed = xor_slices(&seed, &seed_mask);

        let mut output = Vec::with_capacity(n_len);
        output.push(0);
        output.extend_from_slice(&masked_seed);
        output.extend_from_slice(&masked_db);
        output
    }

    pub fn decode(
        &self,
        label: &[u8],
        encoded_message: &[u8],
        n_len: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let label_hash = self.hasher.hash(label).into();
        let masked_seed = &encoded_message[1..(N + 1)];
        let masked_db = &encoded_message[(N + 1)..];

        let seed_mask = mgf1(masked_db, N, self.hasher.clone());
        let seed = xor_slices(masked_seed, &seed_mask);

        let db_mask = mgf1(&seed, n_len - N - 1, self.hasher.clone());
        let db = xor_slices(masked_db, &db_mask);

        if db[..N] != label_hash {
            return Err("wrong label");
        }
        let rest = &db[N..];
        let separator_idx = rest
            .iter()
            .position(|&b| b != 0)
            .ok_or("missing 1-byte before message")?;
        if rest[separator_idx] != 1 {
            return Err("separator is not a 1-byte");
        }
        if encoded_message[0] != 0 {
            return Err("first byte is not 0");
        }

        let message = &rest[(separator_idx + 1)..];

        Ok(message.to_vec())
    }
}

fn xor_slices(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    (0..a.len()).map(|i| a[i] ^ b[i]).collect::<Vec<u8>>()
}
