fn main() {
    let a: u16 = 5;
    let b: u16 = 44;
    println!("Hello, world {} !", a ^ b);
}


pub trait Word:
Clone
+ Copy
+ std::ops::AddAssign
+ std::ops::SubAssign
+ std::ops::Add<Output=Self>
+ std::ops::Sub<Output=Self>
+ std::ops::BitXor<Output=Self>
+ std::ops::Shl<Output=Self>
+ std::ops::Shr<Output=Self> {
    const ZERO: Self;
    const BYTES: usize;
    const P: Self;
    const Q: Self;

    fn from_u8(byte: u8) -> Self;
}
// Encryption
// A = A + S[0]
// B = B + S[1]
// for i in 1 to 2*r+1:
//     A = (A xor B)<<B + S[2*i]
//     B = (B xor A)<<A + S[2*i+1]

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

#[cfg(test)]
mod tests {
    #[test]
    fn test_rotate_left_shift() {
        let a: u8 = 0x77; // 0111 0111
        println!("a = {:2x?}", a);
        
        assert_eq!(rsl(a,1), 0xEE); // 1110 1110
        assert!(rsl(a,2) == 0xDD); // 1101 1101
        assert!(rsl(a,3) == 0xBB); // 1011 1011
    }

    fn rsl(operand: u8, shift: i32) -> u8 {
        operand << shift | operand >> (8 - shift)
    }

    #[test]
    fn test_encrypt_decrypt() {
        /*
        let pt : [dyn Word; 2] = [5, 44];
        let rounds = 10;
        let key = vec![0; 16];
        let ct = encrypt(pt, key, rounds);
        let pt2 = decrypt(ct, key, rounds);
        assert_eq!(pt, pt2);
         */
    }

    #[test]
    fn test_expand_key() {
        /*
        let key = vec![0; 16];

        let rounds = 10;
        let s = expand_key(key, rounds);
        assert_eq!(s.len(), 2 * rounds + 1);
        */
    }
}