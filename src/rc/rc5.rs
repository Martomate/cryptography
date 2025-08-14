use crate::BlockCipher;

const P32: u32 = 0xb7e15163;
const Q32: u32 = 0x9e3779b9;

pub struct RC5 {
    s: Vec<u32>, // expanded key
    r: u8, // rounds
}

impl RC5 {
    pub fn new(key: &[u8], rounds: u8) -> Self {
        assert!(key.len() < 256);

        Self { s: RC5::expand_key(key, rounds), r: rounds }
    }

    fn expand_key(key: &[u8], r: u8) -> Vec<u32> {
        let c = key.len().div_ceil(4);
        let mut l: Vec<u32> = Vec::with_capacity(c);
        for chunk in key.chunks(4) {
            let mut word = [0_u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            l.push(u32::from_le_bytes(word));
        }

        let t = 2 * (r as usize + 1);
        let mut s: Vec<u32> = Vec::with_capacity(t);

        s.push(P32);
        for i in 1..t {
            s.push(s[i-1].wrapping_add(Q32));
        }

        let mut i = 0;
        let mut j = 0;
        let mut a: u32 = 0;
        let mut b: u32 = 0;

        for _ in 0..(3 * t.max(c)) {
            let a_b = a.wrapping_add(b);
            a = s[i].wrapping_add(a_b).rotate_left(3);
            s[i] = a;
            
            let a_b = a.wrapping_add(b);
            b = l[j].wrapping_add(a_b).rotate_left(a_b);
            l[j] = b;

            i = i.wrapping_add(1) % t;
            j = j.wrapping_add(1) % c;
        }

        s
    }

    fn encrypt_32(&self, plaintext: [u32; 2]) -> [u32; 2] {
        let [mut a, mut b] = plaintext;
        
        a = a.wrapping_add(self.s[0]);
        b = b.wrapping_add(self.s[1]);
        for i in 1..=self.r as usize {
            a = (a ^ b).rotate_left(b).wrapping_add(self.s[2 * i]);
            b = (b ^ a).rotate_left(a).wrapping_add(self.s[2 * i + 1]);
        }

        [a, b]
    }
    
    fn decrypt_32(&self, ciphertext: [u32; 2]) -> [u32; 2] {
        let [mut a, mut b] = ciphertext;

        for i in (1..=self.r as usize).rev() {
            b = b.wrapping_sub(self.s[2 * i + 1]).rotate_right(a) ^ a;
            a = a.wrapping_sub(self.s[2 * i]).rotate_right(b) ^ b;
        }
        b = b.wrapping_sub(self.s[1]);
        a = a.wrapping_sub(self.s[0]);

        [a, b]
    }
}

impl BlockCipher<8> for RC5 {
    fn encrypt(&self, plaintext: crate::Block<8>) -> crate::Block<8> {
        let a = u32::from_le_bytes(<[u8; 4]>::try_from(&plaintext[..4]).unwrap());
        let b = u32::from_le_bytes(<[u8; 4]>::try_from(&plaintext[4..]).unwrap());

        let [a, b] = self.encrypt_32([a, b]);
 
        let mut res = [0_u8; 8];
        res[..4].copy_from_slice(&a.to_le_bytes());
        res[4..].copy_from_slice(&b.to_le_bytes());
        res
    }

    fn decrypt(&self, ciphertext: crate::Block<8>) -> crate::Block<8> {
        let a = u32::from_le_bytes(<[u8; 4]>::try_from(&ciphertext[..4]).unwrap());
        let b = u32::from_le_bytes(<[u8; 4]>::try_from(&ciphertext[4..]).unwrap());

        let [a, b] = self.decrypt_32([a, b]);
 
        let mut res = [0_u8; 8];
        res[..4].copy_from_slice(&a.to_le_bytes());
        res[4..].copy_from_slice(&b.to_le_bytes());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc5_examples() {
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            RC5::new(&key, 12).encrypt_32([0x00000000, 0x00000000]),
            [0xEEDBA521, 0x6D8F4B15]
        );
        
        let key = [0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9, 0xCE, 0x91];
        assert_eq!(
            RC5::new(&key, 12).encrypt_32([0xEEDBA521, 0x6D8F4B15]),
            [0xAC13C0F7, 0x52892B5B]
        );

        let key = [0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1, 0x67, 0x87];
        assert_eq!(
            RC5::new(&key, 12).encrypt_32([0xAC13C0F7, 0x52892B5B]),
            [0xB7B3422F, 0x92FC6903]
        );

        let key = [0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1, 0x2B, 0xAF];
        assert_eq!(
            RC5::new(&key, 12).encrypt_32([0xB7B3422F, 0x92FC6903]),
            [0xB278C165, 0xCC97D184]
        );

        let key = [0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15, 0x31, 0x25];
        assert_eq!(
            RC5::new(&key, 12).encrypt_32([0xB278C165, 0xCC97D184]),
            [0x15E444EB, 0x249831DA]
        );
    }
}
