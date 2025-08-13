const PITABLE: [u8; 256] = {
    let mut arr = [0_u8; 256];

    let rows = [
        0x_d978f9c419ddb5ed28e9fd794aa0d89d_u128,
        0x_c67e37832b76538e624c6488448bfba2_u128,
        0x_179a59f587b34f1361456d8d09817d32_u128,
        0x_bd8f40eb86b77b0bf09521225c6b4e82_u128,
        0x_54d66593ce60b21c7356c014a78cf1dc_u128,
        0x_1275ca1f3bbee4d1423dd430a33cb626_u128,
        0x_6fbf0eda4669075727f21d9bbc944303_u128,
        0x_f811c7f690ef3ee706c3d52fc8661ed7_u128,
        0x_08e8eade8052eef784aa72ac354d6a2a_u128,
        0x_961ad2715a1549744b9fd05e0418a4ec_u128,
        0x_c2e0416e0f51cbcc2491af50a1f47039_u128,
        0x_997c3a8523b8b47afc02365b25559731_u128,
        0x_2d5dfa98e38a92ae05df2910676cbac9_u128,
        0x_d300e6cfe19ea82c6316013f58e289a9_u128,
        0x_0d38341bab33ffb0bb480c5fb9b1cd2e_u128,
        0x_c5f3db47e5a59c770aa62068fe7fc1ad_u128,
    ];

    let mut i = 0;
    while i < 16 {
        let row = rows[i].to_be_bytes();
        let mut j = 0;
        while j < 16 {
            arr[i * 16 + j] = row[j];
            j += 1;
        }
        i += 1;
    }

    arr
};

pub struct RC2 {
    key: [u16; 64], // expanded
}

impl RC2 {
    pub fn from_key(key: &[u8], num_bits: u16) -> Self {
        Self {
            key: RC2::expand_key(key, num_bits),
        }
    }

    fn expand_key(key: &[u8], num_bits: u16) -> [u16; 64] {
        let mut L = [0; 128];
        L[..key.len()].copy_from_slice(key);

        let T = key.len();
        let T1 = num_bits;
        let T8 = T1.div_ceil(8);
        let TM = ((1 << (8 + T1 - 8 * T8)) - 1) as u8;
        let TM = 0xff_u8 >> (T1.wrapping_neg() & 7);

        for i in T..128 {
            L[i] = PITABLE[L[i - 1].wrapping_add(L[i - T]) as usize]
        }
        L[(128 - T8) as usize] = PITABLE[(L[(128 - T8) as usize] & TM) as usize];

        for i in (0..(128 - T8)).rev() {
            L[i as usize] = PITABLE[(L[(i + 1) as usize] ^ L[(i + T8) as usize]) as usize];
        }

        let mut K = [0_u16; 64];
        for i in 0..64 {
            K[i] = u16::from_le_bytes([L[i * 2], L[i * 2 + 1]]);
        }
        K
    }

    fn encrypt_block(&self, mut data: [u16; 4]) -> [u16; 4] {
        let mut keys = &self.key[..];

        for i in 0..16 {
            self.mix(&mut data, &keys[..4]);
            keys = &keys[4..];

            if i == 4 || i == 10 {
                self.mash(&mut data);
            }
        }

        data
    }

    fn decrypt_block(&self, data: [u16; 4]) -> [u16; 4] {
        todo!()
    }

    fn mix(&self, data: &mut [u16; 4], keys: &[u16]) {
        for (i, s) in [1, 2, 3, 5].into_iter().enumerate() {
            data[i] = data[i]
                .wrapping_add(keys[i])
                .wrapping_add(data[(i + 3) % 4] & data[(i + 2) % 4])
                .wrapping_add(!data[(i + 3) % 4] & data[(i + 1) % 4])
                .rotate_left(s);
        }
    }

    fn mash(&self, data: &mut [u16; 4]) {
        for i in 0..4 {
            data[i] = data[i].wrapping_add(self.key[(data[(i + 3) % 4] & 63) as usize]);
        }
    }
}

impl crate::BlockCipher<8> for RC2 {
    fn encrypt(&self, plaintext: crate::Block<8>) -> crate::Block<8> {
        let mut data = [0_u16; 4];
        for i in 0..4 {
            data[i] = <u16>::from_le_bytes([plaintext[2 * i], plaintext[2 * i + 1]]);
        }
        let res = self.encrypt_block(data);
        let mut ciphertext = [0_u8; 8];
        for i in 0..4 {
            ciphertext[2 * i..2 * i + 2].copy_from_slice(&res[i].to_le_bytes());
        }
        ciphertext
    }

    fn decrypt(&self, ciphertext: crate::Block<8>) -> crate::Block<8> {
        let mut data = [0_u16; 4];
        for i in 0..4 {
            data[i] = <u16>::from_le_bytes([ciphertext[2 * i], ciphertext[2 * i + 1]]);
        }
        let res = self.decrypt_block(data);
        let mut plaintext = [0_u8; 8];
        for i in 0..4 {
            plaintext[2 * i..2 * i + 2].copy_from_slice(&res[i].to_le_bytes());
        }
        plaintext
    }
}

#[cfg(test)]
mod tests {
    use crate::BlockCipher;

    use super::RC2 as rc2;

    #[test]
    fn rc2_examples() {
        let key = 0x0000000000000000_u64.to_be_bytes();
        assert_eq!(
            rc2::from_key(&key, 63).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0xebb773f993278eff_u64.to_be_bytes()
        );
        
        let key = 0x0000000000000000_u64.to_be_bytes();
        assert_eq!(
            rc2::from_key(&key, 128).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0x81b4ce4e4714989f_u64.to_be_bytes()
        );

        let key = 0xffffffffffffffff_u64.to_be_bytes();
        assert_eq!(
            rc2::from_key(&key, 64).encrypt(0xffffffffffffffff_u64.to_be_bytes()),
            0x278b27e42e2f0d49_u64.to_be_bytes()
        );

        let key = 0x3000000000000000_u64.to_be_bytes();
        assert_eq!(
            rc2::from_key(&key, 64).encrypt(0x1000000000000001_u64.to_be_bytes()),
            0x30649edf9be7d2c2_u64.to_be_bytes()
        );

        let key = [0x88];
        assert_eq!(
            rc2::from_key(&key, 64).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0x61a8a244adacccf0_u64.to_be_bytes()
        );

        let key = &0x88bca90e90875a00_u64.to_be_bytes()[..7];
        assert_eq!(
            rc2::from_key(key, 64).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0x6ccf4308974c267f_u64.to_be_bytes()
        );

        let key = 0x88bca90e90875a7f0f79c384627bafb2_u128.to_be_bytes();
        assert_eq!(
            rc2::from_key(&key, 64).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0x1a807d272bbe5db1_u64.to_be_bytes()
        );

        let key = 0x88bca90e90875a7f0f79c384627bafb2_u128.to_be_bytes();
        assert_eq!(
            rc2::from_key(&key, 128).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0x2269552ab0f85ca6_u64.to_be_bytes()
        );

        let mut key = [0; 33];
        key[0..16].copy_from_slice(&0x88bca90e90875a7f0f79c384627bafb2_u128.to_be_bytes());
        key[16..32].copy_from_slice(&0x16f80a6f85920584c42fceb0be255daf_u128.to_be_bytes());
        key[32] = 0x1e;
        assert_eq!(
            rc2::from_key(&key, 129).encrypt(0x0000000000000000_u64.to_be_bytes()),
            0x5b78d3a43dfff1f1_u64.to_be_bytes()
        );
    }
}
