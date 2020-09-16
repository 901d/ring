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

use super::{
    elem::{binary_op, binary_op_assign},
    elem_sqr_mul, elem_sqr_mul_acc, Modulus, *,
};
use core::marker::PhantomData;

macro_rules! p256_limbs {
    [ $($limb:expr),+ ] => {
        limbs![$($limb),+, 0, 0, 0, 0]
    };
}

pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: 256 / LIMB_BITS,

    q: Modulus {
        p: p256_limbs![
            0xffffffff, 0xffffffff, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xfffffffe
        ],
        rr: p256_limbs![
            0x00000003, 0x00000002, 0xffffffff, 0x00000002, 0x00000001, 0x00000001, 0x00000002,
            0x00000004
        ],
    },

    n: Elem {
        limbs: p256_limbs![
            0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b, 0xffffffff, 0xffffffff, 0xffffffff,
            0xfffffffe
        ],
        m: PhantomData,
        encoding: PhantomData, // Unencoded
    },

    a: Elem {
        limbs: p256_limbs![
            0xfffffffc, 0xffffffff, 0x00000003, 0xfffffffc, 0xffffffff, 0xffffffff, 0xffffffff,
            0xfffffffb
        ],
        m: PhantomData,
        encoding: PhantomData, // R
    },
    b: Elem {
        limbs: p256_limbs![
            0x2bc0dd42, 0x90d23063, 0xe9b537ab, 0x71cf379a, 0x5ea51c3c, 0x52798150, 0xba20e2c8,
            0x240fe188
        ],
        m: PhantomData,
        encoding: PhantomData, // R
    },

    elem_add_impl: sm2p256_norop::Norop_sm2p256_add,
    elem_mul_mont: sm2p256_norop::Norop_sm2p256_mul_mont,
    elem_sqr_mont: sm2p256_norop::Norop_sm2p256_sqr_mont,

    point_add_jacobian_impl: sm2p256_norop::Norop_sm2p256_point_add,
};

pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: sm2p256_elem_inv_squared,
    point_mul_base_impl: sm2p256_point_mul_base_impl,
    point_mul_impl: sm2p256_norop::Norop_sm2p256_point_mul,
};

fn sm2p256_elem_inv_squared(a: &Elem<R>) -> Elem<R> {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc

    #[inline]
    fn sqr_mul(a: &Elem<R>, squarings: usize, b: &Elem<R>) -> Elem<R> {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b)
    }

    #[inline]
    fn sqr_mul_acc(a: &mut Elem<R>, squarings: usize, b: &Elem<R>) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b)
    }

    let b_1 = &a;
    let b_11 = sqr_mul(b_1, 1, b_1);
    let b_111 = sqr_mul(&b_11, 1, b_1);
    let f_11 = sqr_mul(&b_111, 3, &b_111);
    let fff = sqr_mul(&f_11, 6, &f_11);
    let fff_111 = sqr_mul(&fff, 3, &b_111);
    let fffffff_11 = sqr_mul(&fff_111, 15, &fff_111);
    let ffffffff = sqr_mul(&fffffff_11, 2, &b_11);

    // fffffff_111
    let mut acc = sqr_mul(&fffffff_11, 1, &b_1);

    // fffffffe
    COMMON_OPS.elem_square(&mut acc);

    // fffffffeffffffff
    sqr_mul_acc(&mut acc, 32, &ffffffff);

    // fffffffeffffffffffffffff
    sqr_mul_acc(&mut acc, 32, &ffffffff);

    // fffffffeffffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 32, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 32, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff00000000ffffffff
    sqr_mul_acc(&mut acc, 64, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffff_11
    sqr_mul_acc(&mut acc, 30, &fffffff_11);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
    COMMON_OPS.elem_square(&mut acc);
    COMMON_OPS.elem_square(&mut acc);

    acc
}

fn sm2p256_point_mul_base_impl(g_scalar: &Scalar) -> Point {
    let mut r = Point::new_at_infinity();

    static GENERATOR: (Elem<R>, Elem<R>) = (
        Elem {
            limbs: p256_limbs![
            0xf418029e, 0x61328990, 0xdca6c050, 0x3e7981ed, 0xac24c3c3, 0xd6a1ed99,
            0xe1c13b05, 0x91167a5e
        ],
            m: PhantomData,
            encoding: PhantomData,
        },
        Elem {
            limbs: p256_limbs![
            0x3c2d0ddd, 0xc1354e59, 0x8d3295fa, 0xc1f5e578, 0x6e2a48f8, 0x8d4cfb06,
            0x81d735bd, 0x63cd65d4
        ],
            m: PhantomData,
            encoding: PhantomData,
        },
    );

    sm2p256_norop::Norop_sm2p256_point_mul(
        r.xyz.as_mut_ptr(),
        g_scalar.limbs.as_ptr(),
        GENERATOR.0.limbs.as_ptr(),
        GENERATOR.1.limbs.as_ptr(),
    );

    r
}

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_inv_to_mont_impl: sm2p256_scalar_inv_to_mont,
    scalar_mul_mont: sm2p256_norop::Norop_sm2p256_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,
    private_key_ops: &PRIVATE_KEY_OPS,

    q_minus_n: Elem {
        limbs: p256_limbs![0xc62abedc, 0xac440bf6, 0xde39fad5, 0x8dfc2093, 0, 0, 0, 0],
        m: PhantomData,
        encoding: PhantomData, // Unencoded
    },
};

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,

    oneRR_mod_n: Scalar {
        limbs: p256_limbs![
            0x7c114f20, 0x901192af, 0xde6fa2fa, 0x3464504a, 0x3affe0d4, 0x620fc84c, 0xa22b3d3b,
            0x1eb5e412
        ],
        m: PhantomData,
        encoding: PhantomData, // R
    },
};

fn sm2p256_scalar_inv_to_mont(a: &Scalar<Unencoded>) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121

    #[inline]
    fn mul(a: &Scalar<R>, b: &Scalar<R>) -> Scalar<R> {
        binary_op(sm2p256_norop::Norop_sm2p256_scalar_mul_mont, a, b)
    }

    #[inline]
    fn sqr(a: &Scalar<R>) -> Scalar<R> {
        unary_op(sm2p256_norop::Norop_sm2p256_scalar_sqr_mont, a)
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &Scalar<R>, squarings: Limb, b: &Scalar<R>) -> Scalar<R> {
        debug_assert!(squarings >= 1);
        let mut tmp = Scalar::zero();
        sm2p256_norop::Norop_sm2p256_scalar_sqr_rep_mont(tmp.limbs.as_mut_ptr(), a.limbs.as_ptr(), squarings);
        mul(&tmp, b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut Scalar<R>, squarings: Limb, b: &Scalar<R>) {
        debug_assert!(squarings >= 1);
        sm2p256_norop::Norop_sm2p256_scalar_sqr_rep_mont(acc.limbs.as_mut_ptr(), acc.limbs.as_ptr(), squarings);
        binary_op_assign(sm2p256_norop::Norop_sm2p256_scalar_mul_mont, acc, b);
    }

    fn to_mont(a: &Scalar) -> Scalar<R> {
        static N_RR: Scalar<Unencoded> = Scalar {
            limbs: p256_limbs![
                0x7c114f20, 0x901192af, 0xde6fa2fa, 0x3464504a, 0x3affe0d4, 0x620fc84c, 0xa22b3d3b,
                0x1eb5e412
            ],
            m: PhantomData,
            encoding: PhantomData,
        };
        binary_op(sm2p256_norop::Norop_sm2p256_scalar_mul_mont, a, &N_RR)
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_10: usize = 1;
    const B_11: usize = 2;
    const B_101: usize = 3;
    const B_111: usize = 4;
    const B_1111: usize = 5;
    const B_10101: usize = 6;
    const B_101111: usize = 7;
    const DIGIT_COUNT: usize = 8;

    let mut d = [Scalar::zero(); DIGIT_COUNT];

    d[B_1] = to_mont(a);
    d[B_10] = sqr(&d[B_1]);
    d[B_11] = mul(&d[B_10], &d[B_1]);
    d[B_101] = mul(&d[B_10], &d[B_11]);
    d[B_111] = mul(&d[B_101], &d[B_10]);
    let b_1010 = sqr(&d[B_101]);
    d[B_1111] = mul(&b_1010, &d[B_101]);
    d[B_10101] = sqr_mul(&b_1010, 0 + 1, &d[B_1]);
    let b_101010 = sqr(&d[B_10101]);
    d[B_101111] = mul(&b_101010, &d[B_101]);
    let b_111111 = mul(&b_101010, &d[B_10101]);
    let b_1111111 = sqr_mul(&b_111111, 0 + 1, &d[B_1]);

    let ff = sqr_mul(&b_111111, 0 + 2, &d[B_11]);
    let ffff = sqr_mul(&ff, 0 + 8, &ff);
    let ffffffff = sqr_mul(&ffff, 0 + 16, &ffff);

    // ffffff
    let mut acc = sqr_mul(&ffff, 0 + 8, &ff);

    // fffffff_111
    sqr_mul_acc(&mut acc, 0 + 7, &b_1111111);

    // fffffffe
    acc = sqr(&mut acc);

    // fffffffeffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);

    // fffffffeffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);

    // fffffffeffffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);

    // The rest of the exponent, in binary, is:
    //
    //    0111,001,00000001111,01111,101,10101,1,001,0000111,00011,000000101,0010101,1
    //    111,1,00111,0111,00111,0010101,1,0000101111,11,00011,00011,001,0010101,001111

    //    0111,001,00000001111,01111,101,10101,1,001,0000111,00011,000000101,0010101,
    //    10101,00111,0111,01111,11,01,0000001,001,00111,00111,010101,01,000001,001,00001

    static REMAINING_WINDOWS: [(u8, u8); 27] = [
        (1 + 3, B_111 as u8),
        (2 + 1, B_1 as u8),
        (7 + 4, B_1111 as u8),
        (1 + 4, B_1111 as u8),
        (0 + 3, B_101 as u8),
        (0 + 5, B_10101 as u8),
        (0 + 1, B_1 as u8),
        (2 + 1, B_1 as u8),
        (4 + 3, B_111 as u8),
        (3 + 2, B_11 as u8),
        (6 + 3, B_101 as u8),
        (2 + 5, B_10101 as u8),
        (0 + 5, B_10101 as u8),
        (2 + 3, B_111 as u8),
        (1 + 3, B_111 as u8),
        (1 + 4, B_1111 as u8),
        (0 + 2, B_11 as u8),
        (1 + 1, B_1 as u8),
        (6 + 1, B_1 as u8),
        (2 + 1, B_1 as u8),
        (2 + 3, B_111 as u8),
        (2 + 3, B_111 as u8),
        (1 + 5, B_10101 as u8),
        (1 + 1, B_1 as u8),
        (5 + 1, B_1 as u8),
        (2 + 1, B_1 as u8),
        (4 + 1, B_1 as u8),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS {
        sqr_mul_acc(&mut acc, Limb::from(squarings), &d[usize::from(digit)]);
    }

    acc
}

#[cfg(feature = "internal_benches")]
mod internal_benches {
    use super::{super::internal_benches::*, *};

    bench_curve!(&[
        Scalar {
            limbs: LIMBS_1,
            m: PhantomData,
            encoding: PhantomData,
        },
        Scalar {
            limbs: LIMBS_ALTERNATING_10,
            m: PhantomData,
            encoding: PhantomData,
        },
        Scalar {
            // n - 1
            limbs: p256_limbs![
                0x39d54123 - 1,
                0x53bbf409,
                0x21c6052b,
                0x7203df6b,
                0xffffffff,
                0xffffffff,
                0xffffffff,
                0xfffffffe
            ],
            m: PhantomData,
            encoding: PhantomData,
        },
    ]);
}
