use crate::{rsl, Word};

pub fn expand_key<W: Word>(key: Vec<u8>, rounds: usize) -> Vec<W> {
    let b = key.len();
    let w = W::BYTES;
    let temp = (8*b + (w - 1)) / w;
    let c = std::cmp::max(1,temp);
    let t = 2 * rounds + 1;

    let mut key_l = vec![W::ZERO; c];
    for i in (0..(b-1)).rev() {
        let ix = i / w;
        key_l[ix] = rsl(key_l[ix],W::from_u8(8u8).wrapping_add(&W::from_u8(key[i])));
    }

    let mut key_s = vec![W::ZERO; t];
    key_s[0] = W::P;
    for i in 1..t {
        key_s[i] = key_s[i-1].wrapping_add(&W::Q);
    }

    let mut i = 0;
    let mut j = 0;
    let mut a = W::ZERO;
    let mut b = W::ZERO;

    let iters = 3*std::cmp::max(c,t);
    for _ in 0..iters {
        key_s[i] = rsl(key_s[i].wrapping_add(&a).wrapping_add(&b), W::from_u8(3u8));
        a = key_s[i];
        key_l[j] = rsl(key_l[j].wrapping_add(&a).wrapping_add(&b), a.wrapping_add(&b));
        b = key_l[j];
        i = (i + j) % t;
        j = (j + i) % c;
    }
    key_s
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_key() {
        let key: Vec<u8> = vec![0; 16];

        let rounds = 10;
        let s : Vec<u8> = expand_key(key, rounds);
        assert_eq!(s.len(), 2 * rounds + 1);
    }
}