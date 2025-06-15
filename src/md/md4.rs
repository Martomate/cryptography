pub fn md4(data: &[u8]) -> [u8; 16] {
    let a = data.len() % 64;
    let num_pad_bytes = if a == 56 { 64 } else { (64 + 56 - a) % 64 };

    let mut extended_data = Vec::from_iter(data.iter().cloned());
    extended_data.push(0x80);
    extended_data.resize(extended_data.len() + num_pad_bytes - 1, 0);
    let num_bits = (data.len() * 8) as u64;
    extended_data.extend_from_slice(&num_bits.to_le_bytes());

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    let mut aa: u32 = 0x01234567_u32.swap_bytes();
    let mut bb: u32 = 0x89abcdef_u32.swap_bytes();
    let mut cc: u32 = 0xfedcba98_u32.swap_bytes();
    let mut dd: u32 = 0x76543210_u32.swap_bytes();

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

        let ff = |a: u32, b: u32, c: u32, d: u32, i: usize, s: u32| -> u32 {
            a.wrapping_add(f(b, c, d)).wrapping_add(x[i]).rotate_left(s)
        };
        let gg = |a: u32, b: u32, c: u32, d: u32, i: usize, s: u32| -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(0x5A827999)
                .rotate_left(s)
        };
        let hh = |a: u32, b: u32, c: u32, d: u32, i: usize, s: u32| -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(0x6ED9EBA1)
                .rotate_left(s)
        };

        a = ff(a, b, c, d, 0, 3);
        d = ff(d, a, b, c, 1, 7);
        c = ff(c, d, a, b, 2, 11);
        b = ff(b, c, d, a, 3, 19);
        a = ff(a, b, c, d, 4, 3);
        d = ff(d, a, b, c, 5, 7);
        c = ff(c, d, a, b, 6, 11);
        b = ff(b, c, d, a, 7, 19);
        a = ff(a, b, c, d, 8, 3);
        d = ff(d, a, b, c, 9, 7);
        c = ff(c, d, a, b, 10, 11);
        b = ff(b, c, d, a, 11, 19);
        a = ff(a, b, c, d, 12, 3);
        d = ff(d, a, b, c, 13, 7);
        c = ff(c, d, a, b, 14, 11);
        b = ff(b, c, d, a, 15, 19);

        a = gg(a, b, c, d, 0, 3);
        d = gg(d, a, b, c, 4, 5);
        c = gg(c, d, a, b, 8, 9);
        b = gg(b, c, d, a, 12, 13);
        a = gg(a, b, c, d, 1, 3);
        d = gg(d, a, b, c, 5, 5);
        c = gg(c, d, a, b, 9, 9);
        b = gg(b, c, d, a, 13, 13);
        a = gg(a, b, c, d, 2, 3);
        d = gg(d, a, b, c, 6, 5);
        c = gg(c, d, a, b, 10, 9);
        b = gg(b, c, d, a, 14, 13);
        a = gg(a, b, c, d, 3, 3);
        d = gg(d, a, b, c, 7, 5);
        c = gg(c, d, a, b, 11, 9);
        b = gg(b, c, d, a, 15, 13);

        a = hh(a, b, c, d, 0, 3);
        d = hh(d, a, b, c, 8, 9);
        c = hh(c, d, a, b, 4, 11);
        b = hh(b, c, d, a, 12, 15);
        a = hh(a, b, c, d, 2, 3);
        d = hh(d, a, b, c, 10, 9);
        c = hh(c, d, a, b, 6, 11);
        b = hh(b, c, d, a, 14, 15);
        a = hh(a, b, c, d, 1, 3);
        d = hh(d, a, b, c, 9, 9);
        c = hh(c, d, a, b, 5, 11);
        b = hh(b, c, d, a, 13, 15);
        a = hh(a, b, c, d, 3, 3);
        d = hh(d, a, b, c, 11, 9);
        c = hh(c, d, a, b, 7, 11);
        b = hh(b, c, d, a, 15, 15);

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
