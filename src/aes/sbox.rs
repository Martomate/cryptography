use super::field::AesFieldIterator;

pub const SBOX: Sbox = calculate_sbox();

pub struct Sbox {
    pub forward: [u8; 256],
    pub backward: [u8; 256],
}

const fn calculate_sbox() -> Sbox {
    let mut sbox = [0; 256];
    let mut inverse = [0; 256];

    // the field contains one cycle with all elements except 0
    sbox[0] = 0x63;
    inverse[0x63] = 0;

    // note: we do manual iteration here because iterators are not const yet
    let mut it = AesFieldIterator::start();
    while let Some(((n, inv), (np, nq))) = it.step() {
        it.p = np;
        it.q = nq;
        let s = transform_affine(inv);
        sbox[n as usize] = s;
        inverse[s as usize] = n;
    }
    
    Sbox {
        forward:sbox,
        backward:inverse,
    }
}

const fn transform_affine(b: u8) -> u8 {
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

#[cfg(test)]
mod tests {
    use super::SBOX;

    #[test]
    fn sbox_is_correct() {
        let sbox = SBOX.forward;

        // some of the first values
        assert_eq!(sbox[0x00], 0x63);
        assert_eq!(sbox[0x01], 0x7c);
        assert_eq!(sbox[0x02], 0x77);
        assert_eq!(sbox[0x03], 0x7b);

        // some other values
        assert_eq!(sbox[0x10], 0xca);
        assert_eq!(sbox[0xab], 0x62);
        assert_eq!(sbox[0xf0], 0x8c);
        assert_eq!(sbox[0xff], 0x16);
    }

    #[test]
    fn inverse_sbox_is_the_inverse() {
        let inv_sbox = SBOX.backward;

        assert_eq!(inv_sbox[0x63], 0x00);
        assert_eq!(inv_sbox[0x7c], 0x01);
        assert_eq!(inv_sbox[0x77], 0x02);
        assert_eq!(inv_sbox[0x7b], 0x03);

        assert_eq!(inv_sbox[0xca], 0x10);
        assert_eq!(inv_sbox[0x62], 0xab);
        assert_eq!(inv_sbox[0x8c], 0xf0);
        assert_eq!(inv_sbox[0x16], 0xff);
    }

    #[test]
    fn inverse_sbox_is_correct() {
        let inv_sbox = SBOX.backward;

        // some of the first values
        assert_eq!(inv_sbox[0x00], 0x52);
        assert_eq!(inv_sbox[0x01], 0x09);
        assert_eq!(inv_sbox[0x02], 0x6a);
        assert_eq!(inv_sbox[0x03], 0xd5);

        // some other values
        assert_eq!(inv_sbox[0x10], 0x7c);
        assert_eq!(inv_sbox[0xab], 0x0e);
        assert_eq!(inv_sbox[0xf0], 0x17);
        assert_eq!(inv_sbox[0xff], 0x7d);
    }
}
