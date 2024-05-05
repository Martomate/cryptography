use std::ops::Index;

use super::field::AesField;

pub struct Sbox {
    values: [u8; 256],
}

impl Sbox {
    pub fn calculate() -> Sbox {
        let mut sbox = Sbox { values: [0; 256] };

        // the field contains one cycle with all elements except 0
        sbox.values[0] = 0x63;

        for (n, inv) in AesField {
            sbox.values[n as usize] = Sbox::transform_affine(inv);
        }

        sbox
    }

    fn transform_affine(b: u8) -> u8 {
        b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
    }
}

impl Index<u8> for Sbox {
    type Output = u8;

    fn index(&self, index: u8) -> &Self::Output {
        &self.values[index as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::Sbox;

    #[test]
    fn sbox_is_correct() {
        let sbox = Sbox::calculate();

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
}
