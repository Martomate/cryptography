pub fn hash(data: &[u8]) -> [u8; 16] {
    let a = data.len() % 64;
    let num_pad_bytes = if a == 56 { 64 } else { (64 + 56 - a) % 64 };

    let mut extended_data = Vec::from_iter(data.iter().cloned());
    extended_data.push(0x80);
    extended_data.resize(extended_data.len() + num_pad_bytes - 1, 0);
    let num_bits = (data.len() * 8) as u64;
    extended_data.extend_from_slice(&num_bits.to_le_bytes());

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

    let mut aa: u32 = 0x01234567_u32.swap_bytes();
    let mut bb: u32 = 0x89abcdef_u32.swap_bytes();
    let mut cc: u32 = 0xfedcba98_u32.swap_bytes();
    let mut dd: u32 = 0x76543210_u32.swap_bytes();

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

    for i in 0..extended_data.len() / 64 {
        let mut x = [0_u32; 16];
        for (j, v) in x.iter_mut().enumerate() {
            let idx = i * 64 + j * 4;
            *v = u32::from_le_bytes(<[u8; 4]>::try_from(&extended_data[idx..(idx + 4)]).unwrap());
        }

        let mut a = aa;
        let mut b = bb;
        let mut c = cc;
        let mut d = dd;

        let ff = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize| -> u32 {
            a.wrapping_add(f(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(T[i - 1])
                .rotate_left(s)
                .wrapping_add(b)
        };
        let gg = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize| -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(T[i - 1])
                .rotate_left(s)
                .wrapping_add(b)
        };
        let hh = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize| -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(T[i - 1])
                .rotate_left(s)
                .wrapping_add(b)
        };
        let ii = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize| -> u32 {
            a.wrapping_add(_i(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(T[i - 1])
                .rotate_left(s)
                .wrapping_add(b)
        };

        for rows in [
            [(0, 7, 1), (1, 12, 2), (2, 17, 3), (3, 22, 4)],
            [(4, 7, 5), (5, 12, 6), (6, 17, 7), (7, 22, 8)],
            [(8, 7, 9), (9, 12, 10), (10, 17, 11), (11, 22, 12)],
            [(12, 7, 13), (13, 12, 14), (14, 17, 15), (15, 22, 16)],
        ] {
            let (k, s, i) = rows[0];
            a = ff(a, b, c, d, k, s, i);
            let (k, s, i) = rows[1];
            d = ff(d, a, b, c, k, s, i);
            let (k, s, i) = rows[2];
            c = ff(c, d, a, b, k, s, i);
            let (k, s, i) = rows[3];
            b = ff(b, c, d, a, k, s, i);
        }

        for rows in [
            [(1, 5, 17), (6, 9, 18), (11, 14, 19), (0, 20, 20)],
            [(5, 5, 21), (10, 9, 22), (15, 14, 23), (4, 20, 24)],
            [(9, 5, 25), (14, 9, 26), (3, 14, 27), (8, 20, 28)],
            [(13, 5, 29), (2, 9, 30), (7, 14, 31), (12, 20, 32)],
        ] {
            let (k, s, i) = rows[0];
            a = gg(a, b, c, d, k, s, i);
            let (k, s, i) = rows[1];
            d = gg(d, a, b, c, k, s, i);
            let (k, s, i) = rows[2];
            c = gg(c, d, a, b, k, s, i);
            let (k, s, i) = rows[3];
            b = gg(b, c, d, a, k, s, i);
        }

        for rows in [
            [(5, 4, 33), (8, 11, 34), (11, 16, 35), (14, 23, 36)],
            [(1, 4, 37), (4, 11, 38), (7, 16, 39), (10, 23, 40)],
            [(13, 4, 41), (0, 11, 42), (3, 16, 43), (6, 23, 44)],
            [(9, 4, 45), (12, 11, 46), (15, 16, 47), (2, 23, 48)],
        ] {
            let (k, s, i) = rows[0];
            a = hh(a, b, c, d, k, s, i);
            let (k, s, i) = rows[1];
            d = hh(d, a, b, c, k, s, i);
            let (k, s, i) = rows[2];
            c = hh(c, d, a, b, k, s, i);
            let (k, s, i) = rows[3];
            b = hh(b, c, d, a, k, s, i);
        }

        for rows in [
            [(0, 6, 49), (7, 10, 50), (14, 15, 51), (5, 21, 52)],
            [(12, 6, 53), (3, 10, 54), (10, 15, 55), (1, 21, 56)],
            [(8, 6, 57), (15, 10, 58), (6, 15, 59), (13, 21, 60)],
            [(4, 6, 61), (11, 10, 62), (2, 15, 63), (9, 21, 64)],
        ] {
            let (k, s, i) = rows[0];
            a = ii(a, b, c, d, k, s, i);
            let (k, s, i) = rows[1];
            d = ii(d, a, b, c, k, s, i);
            let (k, s, i) = rows[2];
            c = ii(c, d, a, b, k, s, i);
            let (k, s, i) = rows[3];
            b = ii(b, c, d, a, k, s, i);
        }

        aa = aa.wrapping_add(a);
        bb = bb.wrapping_add(b);
        cc = cc.wrapping_add(c);
        dd = dd.wrapping_add(d);
    }

    let mut out = [0; 16];
    out[0..4].copy_from_slice(&aa.to_le_bytes());
    out[4..8].copy_from_slice(&bb.to_le_bytes());
    out[8..12].copy_from_slice(&cc.to_le_bytes());
    out[12..16].copy_from_slice(&dd.to_le_bytes());
    out
}
