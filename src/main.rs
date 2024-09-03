fn main() {
    let a: u16 = 5;
    let b: u16 = 44;
    println!("Hello, world {} !", a ^ b);
}


pub trait Word:
Clone
+ Copy
+ PartialEq
+ std::ops::AddAssign
+ std::ops::SubAssign
+ std::ops::Add<Output=Self>
+ std::ops::Sub<Output=Self>
+ std::ops::BitXor<Output=Self>
+ std::ops::BitOr<Output=Self>
+ std::ops::BitAnd<Output=Self>
+ std::ops::Shl<Output=Self>
+ std::ops::Shr<Output=Self> {
    const ZERO: Self;
    const ONE: Self;
    const BYTES: usize;
    const P: Self;
    const Q: Self;

    fn from_u8(byte: u8) -> Self;
    fn from_usize(byte: usize) -> Self;
}
// Encryption
// A = A + S[0]
// B = B + S[1]
// for i in 1 to 2*r+1:
//     A = (A xor B)<<B + S[2*i]
//     B = (B xor A)<<A + S[2*i+1]

impl Word for u8 {
    const ZERO: u8 = 0;
    const ONE: u8 = 1;
    const BYTES: usize = 1;
    const P: u8 = 0;
    const Q: u8 = 0;

    fn from_u8(byte: u8) -> u8 {
        byte
    }

    fn from_usize(word: usize) -> Self {
        word as u8
    }

}
pub fn encrypt<W: Word>(pt: [W; 2], key: Vec<u8>, rounds: usize) -> [W; 2] {
    let t = 2 * rounds + 1;
    let s = vec![W::ZERO; t];

    let [mut a, mut b] = pt;

    a += s[0];
    b += s[1];

    for i in 1..t {
        a = (a ^ b) << b + s[2 * i];
        b = (b ^ a) << a + s[2 * i + 1];
    }

    [a, b]
}

// Decryption
// for i in 2*r+1 down to 1:
//     B = (B - S[2*i+1])>>A xor B
//     A = (A - S[2*i])>>B xor A
// B = B - S[1]
// A = A - S[0]

pub fn decrypt<W: Word>(ct: [W; 2], key: Vec<u8>, rounds: usize) -> [W; 2] {
    let t = 2 * rounds + 1;
    let s = vec![W::ZERO; t];

    let [mut a, mut b] = ct;

    for i in (t-1)..0 {
        b = ((b - s[2 * i + 1]) >> a) ^ b;
        a = ((a - s[2 * i]) >> b) ^ a;

    }

    a -= s[0];
    b -= s[1];

    [a, b]
}

pub fn expand_key<W: Word>(key: Vec<u8>, rounds: usize) -> Vec<W> {
    let b = key.len();
    let w = W::BYTES;
    let temp = (8*b + (w - 1)) / w;
    let c = std::cmp::max(1,temp);
    let t = 2 * rounds + 1;

    let mut key_l = vec![W::ZERO; c];
    for i in (0..(b-1)).rev() {
        let ix = i / w;
        key_l[ix] = key_l[ix] << W::from_u8(8u8) + W::from_u8(key[i]);
    }

    let mut key_s = vec![W::ZERO; t];
    key_s[0] = W::P;
    for i in 1..t {
        key_s[i] = key_s[i-1] + W::Q;
    }

    let mut i = 0;
    let mut j = 0;
    let mut a = W::ZERO;
    let mut b = W::ZERO;

    let iters = 3*std::cmp::max(c,t);
    for _ in 0..iters {
        key_s[i] = (key_s[i] + a + b) << W::from_u8(3u8);
        a = key_s[i];
        key_l[j] = (key_l[j] + a + b) << (a + b);
        b = key_l[j];
        i = (i + j) % t;
        j = (j + i) % c;
    }
    key_s
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
    fn test_rotate_shift_left() {
        let a: u8 = 0x75; // 0111 0101
        println!("a = {:2x?}", a);
        println!("a rsl 1 = {:2x?}", rsl(a,1u8)); // 1110 1010
        println!("a rsl 2 = {:2x?}", rsl(a,2u8)); // 1101 0101
        println!("a rsl 3 = {:2x?}", rsl(a,3u8)); // 1010 1011
        println!("a rsl 5 = {:2x?}", rsl(a,5u8)); // 1010 1110

        assert_eq!(rsl(a,1u8), 0xEA); // 1110 1010
        assert_eq!(rsl(a,2u8), 0xD5); // 1101 0101
        assert_eq!(rsl(a,3u8), 0xAB); // 1010 1011
        assert_eq!(rsl(a, 4u8), 0x57); // 0101 0111
        assert_eq!(rsl(a, 5u8), 0xAE); // 1010 1110
        assert_eq!(rsl(a, 8u8), a); // 0111 0101
        assert_eq!(rsl(a, 9u8), rsl(a, 1u8)); // 1110 1010
    }

    #[test]
    fn test_rotate_shift_right() {
        let a: u8 = 0xBB; // 1011 1011
        println!("a = {:2x?}", a);
        println!("a rsr 1 = {:2x?}", rsr(a,1u8));
        println!("a rsr 2 = {:2x?}", rsr(a,2u8));
        println!("a rsr 3 = {:2x?}", rsr(a,3u8));

        assert_eq!(rsr(a,1u8), 0xDD); // 1101 1101
        assert_eq!(rsr(a,2u8), 0xEE);  // 1110 1110
        assert_eq!(rsr(a,3u8), 0x77);  // 0111 0111
        assert_eq!(rsr(a, 8u8), a);
        assert_eq!(rsr(a, 9u8), rsr(a, 1u8));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let pt : [u8; 2] = [5, 44];
        let rounds = 10;
        let key = vec![0; 16];
        let ct = encrypt(pt, key.clone(), rounds);
        let pt2 = decrypt(ct, key, rounds);
        assert_eq!(pt, pt2);
    }

    #[test]
    fn test_expand_key() {
        let key: Vec<u8> = vec![0; 16];

        let rounds = 10;
        let s : Vec<u8> = expand_key(key, rounds);
        assert_eq!(s.len(), 2 * rounds + 1);
    }
}