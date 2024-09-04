
pub trait Word:
Clone
+ Copy
+ num::traits::WrappingAdd
+ num::traits::WrappingSub
+ std::fmt::Debug
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
    const P: u8 = 0xB8u8;
    const Q: u8 = 0x9Eu8;

    fn from_u8(byte: u8) -> u8 {
        byte
    }
    fn from_usize(word: usize) -> Self {
        word as u8
    }
}

impl Word for u32 {
    const ZERO: u32 = 0;
    const ONE: u32 = 1;
    const BYTES: usize = 4;
    const P: u32 = 0xB7E15163u32;
    const Q: u32 = 0x9E3779B9u32;

    fn from_u8(byte: u8) -> u32 {
        byte as u32
    }
    fn from_usize(word: usize) -> Self {
        word as u32
    }
}
