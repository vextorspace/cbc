use crate::key::Key;
use crate::word::Word;

mod key;
mod word;

fn main() {
    let a: u16 = 5;
    let b: u16 = 44;
    println!("Hello, world {} !", a ^ b);
}


pub fn encrypt<W: Word>(pt: [W; 2], key: Key) -> [W; 2] {
    let s = key.expand_key();

    let [mut a, mut b] = pt;

    a = a.wrapping_add(&s[0]);
    b = b.wrapping_add(&s[1]);

    for i in 1..key.rounds {
        a = rsl(a ^ b, b).wrapping_add(&s[2 * i]);
        b = rsl(b ^ a, a).wrapping_add(&s[2 * i + 1]);
    }

    [a, b]
}

// Decryption
// for i in 2*r+1 down to 1:
//     B = (B - S[2*i+1])>>A xor B
//     A = (A - S[2*i])>>B xor A
// B = B - S[1]
// A = A - S[0]

pub fn decrypt<W: Word>(ct: [W; 2], key: Key) -> [W; 2] {
    let s = key.expand_key();

    let [mut a, mut b] = ct;

    for i in (1..key.rounds).rev() {
        b = rsr(b.wrapping_sub(&s[2 * i + 1]),a) ^ b;
        a = rsr(a.wrapping_sub(&s[2 * i]), b) ^ a;

    }

    a = a.wrapping_sub(&s[0]);
    b = b.wrapping_sub(&s[1]);

    [a, b]
}

fn rsl<W: Word>(operand: W, shift: W) -> W {
    let bits: W = W::from_usize(W::BYTES*8);
    let bits_not_rolled = (bits - W::ONE) & shift;
    if bits_not_rolled == W::ZERO || bits_not_rolled == bits {
        operand
    } else {
        (operand << bits_not_rolled) | (operand >> (bits - bits_not_rolled))
    }
}

fn rsr<W: Word>(operand: W, shift: W) -> W {
    let bits: W = W::from_usize(W::BYTES*8);
    let bits_not_rolled = (bits - W::ONE) & shift;
    if bits_not_rolled == W::ZERO || bits_not_rolled == bits {
        operand
    } else {
        (operand >> bits_not_rolled) | (operand << (bits - bits_not_rolled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rivest_1() {
        let key = Key::new(vec![0; 16], 12);
        let pt = [0x00u32, 0x00];

        let ct = encrypt(pt, key);
        println!("ct = {:2x?}", ct);
    }

    #[test]
    fn test_rotate_shift_left() {
        let a: u8 = 0x75; // 0111 0101
        assert_eq!(rsl(a,1u8), 0xEA); // 1110 1010
        assert_eq!(rsl(a,2u8), 0xD5); // 1101 0101
        assert_eq!(rsl(a,3u8), 0xAB); // 1010 1011
        assert_eq!(rsl(a, 4u8), 0x57); // 0101 0111
        assert_eq!(rsl(a, 5u8), 0xAE); // 1010 1110
        assert_eq!(rsl(a, 8u8), a); // 0111 0101
        assert_eq!(rsl(a, 9u8), rsl(a, 1u8)); // 1110 1010
        assert_eq!(rsl(a, 17u8), rsl(a, 1u8)); // 1110 1010

    }

    #[test]
    fn test_rotate_shift_right() {
        let a: u8 = 0xBB; // 1011 1011

        assert_eq!(rsr(a,1u8), 0xDD); // 1101 1101
        assert_eq!(rsr(a,2u8), 0xEE);  // 1110 1110
        assert_eq!(rsr(a,3u8), 0x77);  // 0111 0111
        assert_eq!(rsr(a, 8u8), a);
        assert_eq!(rsr(a, 9u8), rsr(a, 1u8));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let pt : [u8; 2] = [5, 44];
        let key = Key::new(vec![0; 16], 10);
        let ct = encrypt(pt, key.clone());
        let pt2 = decrypt(ct, key);
        assert_eq!(pt, pt2);
    }

    #[test]
    fn test_overflow() {
        assert_eq!(255u8.wrapping_add(1u8), 0u8);
        assert_eq!(0u8.wrapping_sub(1u8), 255u8);
    }
}