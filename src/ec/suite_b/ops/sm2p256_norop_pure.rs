// Copyright 2020 Yao Pengfei.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#![allow(dead_code)]

use crate::limb::{Limb, LIMB_LENGTH};
use crate::ec::suite_b::ops::sm2p256_norop::CURVE_PARAMS;
use crate::ec::suite_b::ops::norop_pure::{norop_mul_pure, norop_add_pure, norop_limbs_less_than, norop_sub_pure};

// r.len() = a.len() = b.len() = SM2P256_LIMB_LEN
pub(crate) fn mont_pro_sm2p256_pure(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let mut c0: Limb = 0;
    let mut c = [0; LIMB_LENGTH + 2];
    let mut c_mock = [0; LIMB_LENGTH + 2];
    let b0 = b[0];
    let mut carry = false;
    for i in 0..a.len() {
        let q = c0.overflowing_add(a[i].overflowing_mul(b0).0).0;
        let mut lam1 = [0; LIMB_LENGTH + 1];
        norop_mul_pure(&mut lam1, &[a[i]], b);
        let mut lam2 = [0; LIMB_LENGTH + 1];
        norop_mul_pure(&mut lam2, &[q], &CURVE_PARAMS.p);
        let mut lam3 = [0; LIMB_LENGTH + 2];
        carry = norop_add_pure(&mut lam3, &lam1, &lam2);
        lam3[5] = Limb::from(carry);

        if i % 2 == 0 {
            let _ = norop_add_pure(&mut c, &c_mock[1..], &lam3);
            c0 = c[1];
        } else {
            let _ = norop_add_pure(&mut c_mock, &c[1..], &lam3);
            c0 = c_mock[1];
        }

    }

    if carry || norop_limbs_less_than(&c_mock[1..], &CURVE_PARAMS.p) == 0 {
        let _ = norop_sub_pure(&mut c, &c_mock[1..], &CURVE_PARAMS.p);
        r.copy_from_slice(&c[0..LIMB_LENGTH]);
    } else {
        r.copy_from_slice(&c_mock[1..LIMB_LENGTH + 1]);
    }

    r
}


#[cfg(test)]
mod sm2p256_norop_pure_test {
    use crate::ec::suite_b::ops::sm2p256_norop_pure::*;
    use crate::limb::Limb;

    #[test]
    fn mont_pro_sm2p256_pure_test() {
        let a: &[Limb; 4] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        let mut r = mont_pro_sm2p256_pure(a, a);
        r.reverse();
        println!("mont_pro_sm2p256_pure 1: {:x?}", r);

        // 0100000000000000000000000000000000ffffffff0000000000000001 1 * r modsm2p256
        let b: &[Limb; 4] = &[0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0100000000];
        let mut r = mont_pro_sm2p256_pure(a, b);
        r.reverse();
        println!("mont_pro_sm2p256_pure 2: {:x?}", r);
    }
}

#[cfg(feature = "internal_benches")]
mod bigint_benches {
    use crate::ec::suite_b::ops::sm2p256_norop_pure::*;
    use crate::limb::Limb;

    extern crate test;

    #[bench]
    fn mont_pro_sm2p256_pure_bench(bench: &mut test::Bencher) {
        let a: &[Limb; 4] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        bench.iter(||
            {
                let _ = mont_pro_sm2p256_pure(a, a);
            });
    }

    #[bench]
    fn norop_mul_pure_bench(bench: &mut test::Bencher) {
        let mut r = [0;8];
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let b = [0xacf005cd78843090, 0xd89cdf6229c4bddf, 0xdc30061d04874834, 0xe5a220abf7212ed6];

        bench.iter(||
            {
                for _ in 0..100 {
                    norop_mul_pure(&mut r, &a, &b);
                }
            });
    }

    #[bench]
    fn norop_add_pure_bench(bench: &mut test::Bencher) {
        let mut r = [0;6];
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834, 0xdc30061d04874834];
        let b = [0xacf005cd78843090, 0xd89cdf6229c4bddf, 0xdc30061d04874834, 0xe5a220abf7212ed6, 0xdc30061d04874834];

        bench.iter(||
            {
                for _ in 0..100 {
                    let _ = norop_add_pure(&mut r, &a, &b);
                }
            });
    }

    #[bench]
    fn norop_sub_pure_bench(bench: &mut test::Bencher) {
        let mut r = [0;4];
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let b = [0xacf005cd78843090, 0xd89cdf6229c4bddf, 0xdc30061d04874834, 0xe5a220abf7212ed6];

        bench.iter(||
            {
                for _ in 0..100 {
                    let _ = norop_sub_pure(&mut r, &b, &a);
                }
            });
    }
}