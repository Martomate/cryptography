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

    fn ff(&self, a: u32, b: u32, c: u32, d: u32, (k, s, i): (usize, u32, usize)) -> u32 {
        a.wrapping_add(f(b, c, d))
            .wrapping_add(self.x[k])
            .wrapping_add(T[i - 1])
            .rotate_left(s)
            .wrapping_add(b)
    }

    fn gg(&self, a: u32, b: u32, c: u32, d: u32, (k, s, i): (usize, u32, usize)) -> u32 {
        a.wrapping_add(g(b, c, d))
            .wrapping_add(self.x[k])
            .wrapping_add(T[i - 1])
            .rotate_left(s)
            .wrapping_add(b)
    }

    fn hh(&self, a: u32, b: u32, c: u32, d: u32, (k, s, i): (usize, u32, usize)) -> u32 {
        a.wrapping_add(h(b, c, d))
            .wrapping_add(self.x[k])
            .wrapping_add(T[i - 1])
            .rotate_left(s)
            .wrapping_add(b)
    }

    fn ii(&self, a: u32, b: u32, c: u32, d: u32, (k, s, i): (usize, u32, usize)) -> u32 {
        a.wrapping_add(_i(b, c, d))
            .wrapping_add(self.x[k])
            .wrapping_add(T[i - 1])
            .rotate_left(s)
            .wrapping_add(b)
    }

    fn process(&self, mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
        for rows in [
            [(0, 7, 1), (1, 12, 2), (2, 17, 3), (3, 22, 4)],
            [(4, 7, 5), (5, 12, 6), (6, 17, 7), (7, 22, 8)],
            [(8, 7, 9), (9, 12, 10), (10, 17, 11), (11, 22, 12)],
            [(12, 7, 13), (13, 12, 14), (14, 17, 15), (15, 22, 16)],
        ] {
            a = self.ff(a, b, c, d, rows[0]);
            d = self.ff(d, a, b, c, rows[1]);
            c = self.ff(c, d, a, b, rows[2]);
            b = self.ff(b, c, d, a, rows[3]);
        }

        for rows in [
            [(1, 5, 17), (6, 9, 18), (11, 14, 19), (0, 20, 20)],
            [(5, 5, 21), (10, 9, 22), (15, 14, 23), (4, 20, 24)],
            [(9, 5, 25), (14, 9, 26), (3, 14, 27), (8, 20, 28)],
            [(13, 5, 29), (2, 9, 30), (7, 14, 31), (12, 20, 32)],
        ] {
            a = self.gg(a, b, c, d, rows[0]);
            d = self.gg(d, a, b, c, rows[1]);
            c = self.gg(c, d, a, b, rows[2]);
            b = self.gg(b, c, d, a, rows[3]);
        }

        for rows in [
            [(5, 4, 33), (8, 11, 34), (11, 16, 35), (14, 23, 36)],
            [(1, 4, 37), (4, 11, 38), (7, 16, 39), (10, 23, 40)],
            [(13, 4, 41), (0, 11, 42), (3, 16, 43), (6, 23, 44)],
            [(9, 4, 45), (12, 11, 46), (15, 16, 47), (2, 23, 48)],
        ] {
            a = self.hh(a, b, c, d, rows[0]);
            d = self.hh(d, a, b, c, rows[1]);
            c = self.hh(c, d, a, b, rows[2]);
            b = self.hh(b, c, d, a, rows[3]);
        }

        for rows in [
            [(0, 6, 49), (7, 10, 50), (14, 15, 51), (5, 21, 52)],
            [(12, 6, 53), (3, 10, 54), (10, 15, 55), (1, 21, 56)],
            [(8, 6, 57), (15, 10, 58), (6, 15, 59), (13, 21, 60)],
            [(4, 6, 61), (11, 10, 62), (2, 15, 63), (9, 21, 64)],
        ] {
            a = self.ii(a, b, c, d, rows[0]);
            d = self.ii(d, a, b, c, rows[1]);
            c = self.ii(c, d, a, b, rows[2]);
            b = self.ii(b, c, d, a, rows[3]);
        }

        (a, b, c, d)
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
fn _i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391,
];
