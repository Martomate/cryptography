pub fn hash<'a>(data: impl IntoIterator<Item = &'a u8>) -> [u8; 16] {
    let mut hasher = Hasher::new();

    for byte in data.into_iter() {
        hasher.consume(*byte);
    }

    hasher.finish()
}

struct Hasher {
    unprocessed_bytes: Vec<u8>,
    bytes_consumed: usize,

    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl Hasher {
    fn new() -> Self {
        Self {
            unprocessed_bytes: Vec::with_capacity(64),
            bytes_consumed: 0,

            a: 0x01234567_u32.swap_bytes(),
            b: 0x89abcdef_u32.swap_bytes(),
            c: 0xfedcba98_u32.swap_bytes(),
            d: 0x76543210_u32.swap_bytes(),
        }
    }

    fn consume(&mut self, byte: u8) {
        self.bytes_consumed += 1;
        self.unprocessed_bytes.push(byte);
        if self.unprocessed_bytes.len() == 64 {
            self.process_block();
        }
    }

    fn process_block(&mut self) {
        let block = Block::from_slice(&self.unprocessed_bytes);
        self.unprocessed_bytes.clear();

        let (a, b, c, d) = block.process(self.a, self.b, self.c, self.d);

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
    }

    fn finish(mut self) -> [u8; 16] {
        let bits_consumed = (self.bytes_consumed * 8) as u64;
        let num_pad_bytes = match self.unprocessed_bytes.len() {
            56 => 64,
            a => (64 + 56 - a) % 64,
        };

        self.consume(0x80);
        for _ in 0..num_pad_bytes - 1 {
            self.consume(0);
        }
        for byte in bits_consumed.to_le_bytes() {
            self.consume(byte);
        }

        let mut out = [0; 16];
        out[0..4].copy_from_slice(&self.a.to_le_bytes());
        out[4..8].copy_from_slice(&self.b.to_le_bytes());
        out[8..12].copy_from_slice(&self.c.to_le_bytes());
        out[12..16].copy_from_slice(&self.d.to_le_bytes());
        out
    }
}

struct Block {
    x: [u32; 16]
}

impl Block {
    fn from_slice(chunk: &[u8]) -> Self {
        let mut x = [0_u32; 16];
        for (j, v) in x.iter_mut().enumerate() {
            let idx = j * 4;
            *v = u32::from_le_bytes(<[u8; 4]>::try_from(&chunk[idx..(idx + 4)]).unwrap());
        }
        Self { x }
    }

    fn ff(&self, a: u32, b: u32, c: u32, d: u32, i: usize, s: u32) -> u32 {
        a.wrapping_add(f(b, c, d)).wrapping_add(self.x[i]).rotate_left(s)
    }

    fn gg(&self, a: u32, b: u32, c: u32, d: u32, i: usize, s: u32) -> u32 {
        a.wrapping_add(g(b, c, d))
            .wrapping_add(self.x[i])
            .wrapping_add(0x5A827999)
            .rotate_left(s)
    }

    fn hh(&self, a: u32, b: u32, c: u32, d: u32, i: usize, s: u32) -> u32 {
        a.wrapping_add(h(b, c, d))
            .wrapping_add(self.x[i])
            .wrapping_add(0x6ED9EBA1)
            .rotate_left(s)
    }

    fn process(&self, mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
        a = self.ff(a, b, c, d, 0, 3);
        d = self.ff(d, a, b, c, 1, 7);
        c = self.ff(c, d, a, b, 2, 11);
        b = self.ff(b, c, d, a, 3, 19);
        a = self.ff(a, b, c, d, 4, 3);
        d = self.ff(d, a, b, c, 5, 7);
        c = self.ff(c, d, a, b, 6, 11);
        b = self.ff(b, c, d, a, 7, 19);
        a = self.ff(a, b, c, d, 8, 3);
        d = self.ff(d, a, b, c, 9, 7);
        c = self.ff(c, d, a, b, 10, 11);
        b = self.ff(b, c, d, a, 11, 19);
        a = self.ff(a, b, c, d, 12, 3);
        d = self.ff(d, a, b, c, 13, 7);
        c = self.ff(c, d, a, b, 14, 11);
        b = self.ff(b, c, d, a, 15, 19);

        a = self.gg(a, b, c, d, 0, 3);
        d = self.gg(d, a, b, c, 4, 5);
        c = self.gg(c, d, a, b, 8, 9);
        b = self.gg(b, c, d, a, 12, 13);
        a = self.gg(a, b, c, d, 1, 3);
        d = self.gg(d, a, b, c, 5, 5);
        c = self.gg(c, d, a, b, 9, 9);
        b = self.gg(b, c, d, a, 13, 13);
        a = self.gg(a, b, c, d, 2, 3);
        d = self.gg(d, a, b, c, 6, 5);
        c = self.gg(c, d, a, b, 10, 9);
        b = self.gg(b, c, d, a, 14, 13);
        a = self.gg(a, b, c, d, 3, 3);
        d = self.gg(d, a, b, c, 7, 5);
        c = self.gg(c, d, a, b, 11, 9);
        b = self.gg(b, c, d, a, 15, 13);

        a = self.hh(a, b, c, d, 0, 3);
        d = self.hh(d, a, b, c, 8, 9);
        c = self.hh(c, d, a, b, 4, 11);
        b = self.hh(b, c, d, a, 12, 15);
        a = self.hh(a, b, c, d, 2, 3);
        d = self.hh(d, a, b, c, 10, 9);
        c = self.hh(c, d, a, b, 6, 11);
        b = self.hh(b, c, d, a, 14, 15);
        a = self.hh(a, b, c, d, 1, 3);
        d = self.hh(d, a, b, c, 9, 9);
        c = self.hh(c, d, a, b, 5, 11);
        b = self.hh(b, c, d, a, 13, 15);
        a = self.hh(a, b, c, d, 3, 3);
        d = self.hh(d, a, b, c, 11, 9);
        c = self.hh(c, d, a, b, 7, 11);
        b = self.hh(b, c, d, a, 15, 15);

        (a, b, c, d)
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
