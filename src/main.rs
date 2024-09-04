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
        a = word::rsl(a ^ b, b).wrapping_add(&s[2 * i]);
        b = word::rsl(b ^ a, a).wrapping_add(&s[2 * i + 1]);
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
        b = word::rsr(b.wrapping_sub(&s[2 * i + 1]), a) ^ b;
        a = word::rsr(a.wrapping_sub(&s[2 * i]), b) ^ a;

    }

    a = a.wrapping_sub(&s[0]);
    b = b.wrapping_sub(&s[1]);

    [a, b]
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