use crate::Block;

use super::{
    hash::{Hash224, Hash256},
    pad::sha1_padding,
};

pub fn sha224(message: &[u8]) -> Hash224 {
    let chunks = message.chunks_exact(64);
    let remaining_bytes = chunks.remainder();
    let (last_chunk, extra_chunk) = sha2_padding(remaining_bytes, message.len() as u64);

    let mut hash = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, //
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    ];

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

    let mut hash = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

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

pub fn sha2_padding(src: &[u8], message_length: u64) -> (Block<64>, Option<Block<64>>) {
    // it's the same as for SHA-1
    sha1_padding(src, message_length)
}

static ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, //
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, //
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, //
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, //
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, //
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, //
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, //
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, //
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, //
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, //
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, //
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, //
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, //
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, //
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, //
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, //
];

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
