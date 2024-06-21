use crate::{Block, HashFunction};

use super::{
    hash::{Hash224, Hash256, Hash384, Hash512},
    pad::sha1_padding,
};

#[rustfmt::skip]
static INITIAL_HASH_224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

#[rustfmt::skip]
static INITIAL_HASH_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[rustfmt::skip]
static INITIAL_HASH_384: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

#[rustfmt::skip]
static INITIAL_HASH_512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

#[rustfmt::skip]
static ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[rustfmt::skip]
static ROUND_CONSTANTS_BIG: [u64; 80] = [
   0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
   0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
   0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
   0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
   0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
   0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
   0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
   0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
   0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
   0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
   0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
   0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
   0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
   0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
   0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone)]
pub struct Sha256;

impl HashFunction for Sha256 {
    type Output = Hash256;

    fn hash(&self, message: &[u8]) -> Self::Output {
        sha256(message)
    }
}

pub fn sha224(message: &[u8]) -> Hash224 {
    let chunks = message.chunks_exact(64);
    let remaining_bytes = chunks.remainder();
    let (last_chunk, extra_chunk) = sha2_padding(remaining_bytes, message.len() as u64);

    let mut hash = INITIAL_HASH_224;

    for chunk in chunks {
        let chunk = <[u8; 64]>::try_from(chunk).unwrap();
        process_chunk(&mut hash, chunk);
    }
    process_chunk(&mut hash, last_chunk);
    if let Some(extra_chunk) = extra_chunk {
        process_chunk(&mut hash, extra_chunk);
    }

    <[u32; 7]>::try_from(&hash[..7]).unwrap().into()
}

pub fn sha256(message: &[u8]) -> Hash256 {
    let chunks = message.chunks_exact(64);
    let remaining_bytes = chunks.remainder();
    let (last_chunk, extra_chunk) = sha2_padding(remaining_bytes, message.len() as u64);

    let mut hash = INITIAL_HASH_256;

    for chunk in chunks {
        let chunk = <[u8; 64]>::try_from(chunk).unwrap();
        process_chunk(&mut hash, chunk);
    }
    process_chunk(&mut hash, last_chunk);
    if let Some(extra_chunk) = extra_chunk {
        process_chunk(&mut hash, extra_chunk);
    }

    hash.into()
}

pub fn sha384(message: &[u8]) -> Hash384 {
    let chunks = message.chunks_exact(128);
    let remaining_bytes = chunks.remainder();
    let (last_chunk, extra_chunk) = sha2_padding_big(remaining_bytes, message.len() as u128);

    let mut hash = INITIAL_HASH_384;

    for chunk in chunks {
        let chunk = <[u8; 128]>::try_from(chunk).unwrap();
        process_big_chunk(&mut hash, chunk);
    }
    process_big_chunk(&mut hash, last_chunk);
    if let Some(extra_chunk) = extra_chunk {
        process_big_chunk(&mut hash, extra_chunk);
    }

    <[u64; 6]>::try_from(&hash[..6]).unwrap().into()
}

pub fn sha512(message: &[u8]) -> Hash512 {
    let chunks = message.chunks_exact(128);
    let remaining_bytes = chunks.remainder();
    let (last_chunk, extra_chunk) = sha2_padding_big(remaining_bytes, message.len() as u128);

    let mut hash = INITIAL_HASH_512;

    for chunk in chunks {
        let chunk = <[u8; 128]>::try_from(chunk).unwrap();
        process_big_chunk(&mut hash, chunk);
    }
    process_big_chunk(&mut hash, last_chunk);
    if let Some(extra_chunk) = extra_chunk {
        process_big_chunk(&mut hash, extra_chunk);
    }

    hash.into()
}

pub fn sha2_padding(src: &[u8], message_length: u64) -> (Block<64>, Option<Block<64>>) {
    // it's the same as for SHA-1
    sha1_padding(src, message_length)
}

pub fn sha2_padding_big(src: &[u8], message_length: u128) -> (Block<128>, Option<Block<128>>) {
    let mut last = [0; 128];
    let mut extra = [0; 128];

    last[..src.len()].copy_from_slice(src);
    last[src.len()] = 0x80;

    if src.len() < 128 - 16 {
        last[(128 - 16)..].copy_from_slice(&(message_length * 8).to_be_bytes());
        (last, None)
    } else {
        extra[(128 - 16)..].copy_from_slice(&(message_length * 8).to_be_bytes());
        (last, Some(extra))
    }
}

fn process_chunk(hash: &mut [u32; 8], chunk: [u8; 64]) {
    let k = &ROUND_CONSTANTS;

    let mut w = [0_u32; 64];
    for (i, word) in chunk.chunks_exact(4).enumerate() {
        let word = <[u8; 4]>::try_from(word).unwrap();
        w[i] = u32::from_be_bytes(word);
    }

    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash; // this will copy

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);

        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
    hash[5] = hash[5].wrapping_add(f);
    hash[6] = hash[6].wrapping_add(g);
    hash[7] = hash[7].wrapping_add(h);
}

fn process_big_chunk(hash: &mut [u64; 8], chunk: [u8; 128]) {
    let k = &ROUND_CONSTANTS_BIG;

    let mut w = [0_u64; 80];
    for (i, word) in chunk.chunks_exact(8).enumerate() {
        let word = <[u8; 8]>::try_from(word).unwrap();
        w[i] = u64::from_be_bytes(word);
    }

    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash; // this will copy

    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);

        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
    hash[5] = hash[5].wrapping_add(f);
    hash[6] = hash[6].wrapping_add(g);
    hash[7] = hash[7].wrapping_add(h);
}
