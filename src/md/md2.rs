pub fn hash<'a>(data: impl IntoIterator<Item = &'a u8>) -> [u8; 16] {
    let mut hasher = Hasher::new();
    for b in data.into_iter() {
        hasher.consume(*b);
    }
    hasher.finish()
}

struct Hasher {
    chunk: Vec<u8>,
    checksum: [u8; 16],
    l: u8,
    x: [u8; 48],
}

impl Hasher {
    fn new() -> Self {
        Self {
            chunk: Vec::with_capacity(16),
            checksum: [0; 16],
            l: 0,
            x: [0; 48],
        }
    }

    fn consume(&mut self, byte: u8) {
        self.chunk.push(byte);
        if self.chunk.len() == 16 {
            self.process_chunk();
        }
    }

    fn finish(mut self) -> [u8; 16] {
        let pad = 16 - self.chunk.len() as u8;
        for _ in 0..pad {
            self.chunk.push(pad);
        }
        self.process_chunk();

        self.chunk.extend_from_slice(&self.checksum);
        self.process_chunk();

        <[u8; 16]>::try_from(&self.x[0..16]).unwrap()
    }

    fn process_chunk(&mut self) {
        let chunk = <[u8; 16]>::try_from(&self.chunk[0..16]).unwrap();
        self.chunk.clear();

        for j in 0..16 {
            let c = chunk[j];
            self.checksum[j] ^= S[(c ^ self.l) as usize];
            self.l = self.checksum[j];
        }

        for j in 0..16 {
            self.x[j + 16] = chunk[j];
            self.x[j + 32] = self.x[j + 16] ^ self.x[j];
        }

        let mut t = 0;

        // 18 rounds
        for j in 0..18 {
            for v in &mut self.x {
                *v ^= S[t as usize];
                t = *v;
            }

            t = t.wrapping_add(j);
        }
    }
}

const S: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199,
    115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47,
    238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
    154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209,
    215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
    156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
    175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205,
    244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14,
    102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20,
];
