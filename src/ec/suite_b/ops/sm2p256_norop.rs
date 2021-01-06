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

use crate::ec::suite_b::ops::norop256::{norop256_limbs_sub_mod, norop256_limbs_add_mod};
use crate::limb::{Limb, LimbMask, LIMB_FALSE, LIMB_LENGTH};
use crate::c;
use crate::arithmetic::bigint::N0;
use std::slice;
use crate::ec::suite_b::ops::sm2p256_table::SM2P256_PRECOMPUTED;
use crate::ec::suite_b::ops::norop_pure::{norop_mul_pure, norop_add_pure, norop_limbs_less_than, norop_sub_pure, norop_mul_pure_upper};

extern "C" {
    fn LIMBS_shl_mod(r: *mut Limb, a: *const Limb, m: *const Limb, num_limbs: c::size_t);
    fn LIMBS_equal(a: *const Limb, b: *const Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_equal_limb(a: *const Limb, b: Limb, num_limbs: c::size_t) -> LimbMask;
}

pub static CURVE_PARAMS: curve_params = curve_params {
    a: [0; 4],
    b: [0; 4],
    p: [0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff],
    n: [0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff],
    p_inv_r_neg: [0x0000000000000001, 0xffffffff00000001, 0xfffffffe00000000, 0xfffffffc00000001],
    r_p: [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x100000000],
    rr_p: [0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0400000002],
    n_inv_r_neg: [0x327f9e8872350975, 0xdf1e8d34fc8319a5, 0x2b0068d3b08941d4, 0x6f39132f82e4c7bc],
    rr_n: [0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b],
    n0: N0([0x0000000000000001, 0xffffffff00000001]),
    nn0: N0([0x327f9e8872350975, 0xdf1e8d34fc8319a5]),
};

pub struct curve_params {
    pub a: [u64; 4],
    pub b: [u64; 4],
    pub p: [u64; 4],
    pub n: [u64; 4],
    pub p_inv_r_neg: [u64; 4],
    pub r_p: [u64; 4],
    pub rr_p: [u64; 4],
    pub n_inv_r_neg: [u64; 4],
    pub rr_n: [u64; 4],
    pub n0: N0,
    pub nn0: N0,
}

pub(super) extern "C" fn Norop_sm2p256_add(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    add_sm2p256(r, a, b);
}

pub(super) extern "C" fn Norop_sm2p256_mul_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    mont_pro_sm2p256(r, a, b)
}

pub(super) extern "C" fn Norop_sm2p256_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    mont_pro_sm2p256(r, a, a);
}

// rem = a + b
pub(super) extern "C" fn Norop_sm2p256_point_add(
    r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
    a: *const Limb, // [3][COMMON_OPS.num_limbs]
    b: *const Limb, // [3][COMMON_OPS.num_limbs]
) {
    let r_arr = unsafe {[r, r.offset(4), r.offset(8)]};
    let a_arr = unsafe {[a, a.offset(4), a.offset(8)]};
    let b_arr = unsafe {[b, b.offset(4), b.offset(8)]};
    norop_point_add_sm2p256(r_arr, a_arr, b_arr);
}

// double and add
pub(super) extern "C" fn Norop_sm2p256_point_mul(
    r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
    p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
    p_x: *const Limb,      // [COMMON_OPS.num_limbs]
    p_y: *const Limb,      // [COMMON_OPS.num_limbs]
) {
    let r_arr = unsafe {[r, r.offset(4), r.offset(8)]};
    norop_point_mul_sm2p256(r_arr, norop_to_jacobi_sm2p256([p_x, p_y]), p_scalar);
}

pub(super) extern "C" fn Norop_sm2p256_point_mul_base(
    r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
    p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let r_arr = unsafe {[r, r.offset(4), r.offset(8)]};
    norop_point_mul_base_sm2p256(r_arr, p_scalar);
}

// rem = a * b * r^-1 modn
pub(super) extern "C" fn Norop_sm2p256_scalar_mul_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    norop_scalar_mont_pro_sm2p256(r, a, b)
}

pub(super) extern "C" fn Norop_sm2p256_scalar_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    norop_scalar_mont_pro_sm2p256(r, a, a)
}

pub(super) extern "C" fn Norop_sm2p256_scalar_sqr_rep_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    rep: Limb,
) {
    norop_scalar_mul_rep_sm2p256(r, a, rep);
}

pub(crate) fn mont_pro_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    extern "C" {
        // `r` and/or 'a' and/or 'b' may alias.
        fn GFp_bn_mul_mont(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            n: *const Limb,
            n0: &N0,
            num_limbs: c::size_t,
        );
    }
    unsafe {
        GFp_bn_mul_mont(
            r,
            a,
            b,
            CURVE_PARAMS.p.as_ptr(),
            &CURVE_PARAMS.n0,
            CURVE_PARAMS.p.len(),
        )
    }
}

fn add_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    unsafe {
        norop256_limbs_add_mod(
            slice::from_raw_parts_mut(r, 4),
            slice::from_raw_parts(a, 4),
            slice::from_raw_parts(b, 4),
            &CURVE_PARAMS.p,
            CURVE_PARAMS.p.len()
        )
    }
}

fn neg_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    sub_sm2p256(r, CURVE_PARAMS.p.as_ptr(), a);
}

fn sub_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    unsafe {
        norop256_limbs_sub_mod(
            slice::from_raw_parts_mut(r, 4),
            slice::from_raw_parts(a, 4),
            slice::from_raw_parts(b, 4),
            &CURVE_PARAMS.p,
            CURVE_PARAMS.p.len()
        )
    }
}

// a << b
fn shl_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    shift: usize
) {
    unsafe {
        core::ptr::copy(a, r ,4);
        for _i in 0..shift {
            LIMBS_shl_mod(r, r, CURVE_PARAMS.p.as_ptr(),CURVE_PARAMS.p.len());
        }
    }
}

// fn mod_sm2p256(
//     a: &BigUint,
// ) -> BigUint {
//     let mut rem = a.clone();
//     let mut rem_len = rem.bits();
//     while rem_len > 256 {
//         let left_rem = &rem >> 256;
//         rem -= (&left_rem + (&left_rem >> 32) + (&left_rem >> 160) - (&left_rem >> 192)) * &SM2P256_CTX.p;
//         rem_len = rem.bits();
//     }
//     if rem >= SM2P256_CTX.p {
//         rem -= &SM2P256_CTX.p;
//     }
//     rem
// }

// todo change algorithm
fn norop_to_mont_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    mont_pro_sm2p256(r, a, CURVE_PARAMS.rr_p.as_ptr())
}

fn norop_point_add_sm2p256(
    r: [*mut Limb; 3],
    a: [*const Limb; 3],
    b: [*const Limb; 3]
) {
    let r_x = r[0];
    let r_y = r[1];
    let r_z = r[2];
    let a_x = a[0];
    let a_y = a[1];
    let a_z = a[2];
    let b_x = b[0];
    let b_y = b[1];
    let b_z = b[2];

    unsafe {
        if LIMBS_equal_limb(a_z, 0 , 4) == LimbMask::True {
            core::ptr::copy(b_x, r_x, 4);
            core::ptr::copy(b_y, r_y, 4);
            core::ptr::copy(b_z, r_z, 4);
            return;
        } else if LIMBS_equal_limb(b_z, 0 , 4) == LimbMask::True {
            core::ptr::copy(a_x, r_x, 4);
            core::ptr::copy(a_y, r_y, 4);
            core::ptr::copy(a_z, r_z, 4);
            return;
        } else if LIMBS_equal(a_x, b_x, 4) == LimbMask::True
            && LIMBS_equal(a_y, b_y, 4) == LimbMask::True
            && LIMBS_equal(a_z, b_z, 4) == LimbMask::True  {
            norop_point_double_sm2p256(r, a);
            return;
        }
    }

    let mut a_z_sqr: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(a_z_sqr.as_mut_ptr(), a_z, a_z);
    let mut b_z_sqr: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(b_z_sqr.as_mut_ptr(), b_z, b_z);
    let mut u1: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(u1.as_mut_ptr(), a_x, b_z_sqr.as_ptr());
    let mut u2: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(u2.as_mut_ptr(), b_x, a_z_sqr.as_ptr());
    let mut a_z_cub: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(a_z_cub.as_mut_ptr(), a_z_sqr.as_ptr(), a_z);
    let mut b_z_cub: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(b_z_cub.as_mut_ptr(), b_z_sqr.as_ptr(), b_z);
    let mut s1: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(s1.as_mut_ptr(), a_y, b_z_cub.as_ptr());
    let mut s2: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(s2.as_mut_ptr(), b_y, a_z_cub.as_ptr());
    let mut h: [Limb; 4] = [0; 4];
    sub_sm2p256(h.as_mut_ptr(), u2.as_ptr(), u1.as_ptr());
    let mut r2: [Limb; 4] = [0; 4];
    sub_sm2p256(r2.as_mut_ptr(), s2.as_ptr(), s1.as_ptr());
    let mut r2_sqr: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(r2_sqr.as_mut_ptr(), r2.as_ptr(), r2.as_ptr());
    let mut h_sqr: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(h_sqr.as_mut_ptr(), h.as_ptr(), h.as_ptr());
    let mut h_cub: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(h_cub.as_mut_ptr(), h_sqr.as_ptr(), h.as_ptr());

    let mut v: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(v.as_mut_ptr(), u1.as_ptr(), h_sqr.as_ptr()); // u1*hh
    let mut lam1: [Limb; 4] = [0; 4];
    sub_sm2p256(lam1.as_mut_ptr(), r2_sqr.as_ptr(), h_cub.as_ptr()); // rr-hhh
    let mut lam2: [Limb; 4] = [0; 4];
    shl_sm2p256(lam2.as_mut_ptr(), v.as_ptr(), 1); // 2*v
    sub_sm2p256(r_x, lam1.as_ptr(), lam2.as_ptr()); // x3=rr-hhh-2*v

    let mut lam3: [Limb; 4] = [0; 4];
    sub_sm2p256(lam3.as_mut_ptr(), v.as_ptr(), r_x); // v-x3
    let mut lam4: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam4.as_mut_ptr(), r2.as_ptr(), lam3.as_ptr()); // r*(v-x3)
    let mut lam5: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam5.as_mut_ptr(), s1.as_ptr(), h_cub.as_ptr()); // s1*hhh
    sub_sm2p256(r_y, lam4.as_ptr(), lam5.as_ptr()); // y3=r*(v-x3)-s1*hhh

    let mut lam6: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam6.as_mut_ptr(), a_z, b_z);
    mont_pro_sm2p256(r_z, lam6.as_ptr(), h.as_ptr());
}

fn norop_point_double_sm2p256(
    r: [*mut Limb; 3],
    a: [*const Limb; 3],
) {
    let r_x = r[0];
    let r_y = r[1];
    let r_z = r[2];
    let a_x = a[0];
    let a_y = a[1];
    let a_z = a[2];
    let mut delta: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(delta.as_mut_ptr(), a_z, a_z);
    let mut gamma: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(gamma.as_mut_ptr(), a_y, a_y);
    let mut beta: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(beta.as_mut_ptr(), a_x, gamma.as_ptr());
    let mut lam1: [Limb; 4] = [0; 4];
    sub_sm2p256(lam1.as_mut_ptr(), a_x, delta.as_ptr()); // x1-delta
    let mut lam2: [Limb; 4] = [0; 4];
    add_sm2p256(lam2.as_mut_ptr(), a_x, delta.as_ptr()); // x1+delta
    let mut lam3: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam3.as_mut_ptr(), lam1.as_ptr(), lam2.as_ptr()); // (x1-delta)*(x1+delta)
    let mut lam4: [Limb; 4] = [0; 4];
    shl_sm2p256(lam4.as_mut_ptr(), lam3.as_ptr(), 1); // 2(x1-delta)*(x1+delta)
    let mut alpha: [Limb; 4] = [0; 4];
    add_sm2p256(alpha.as_mut_ptr(), lam3.as_ptr(), lam4.as_ptr()); // 3(x1-delta)*(x1+delta)
    let mut lam5: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam5.as_mut_ptr(), alpha.as_ptr(), alpha.as_ptr()); // alpha^2
    let mut lam6: [Limb; 4] = [0; 4];
    shl_sm2p256(lam6.as_mut_ptr(), beta.as_ptr(), 3); // 8beta
    sub_sm2p256(r_x, lam5.as_ptr(), lam6.as_ptr()); // x3=alpha^2-8beta
    let mut lam7: [Limb; 4] = [0; 4];
    add_sm2p256(lam7.as_mut_ptr(), a_y, a_z);
    let mut lam8: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam8.as_mut_ptr(), lam7.as_ptr(), lam7.as_ptr()); // (y1+z1)^2
    let mut lam9: [Limb; 4] = [0; 4];
    sub_sm2p256(lam9.as_mut_ptr(), lam8.as_ptr(), gamma.as_ptr()); // (y1+z1)^2-gamma
    sub_sm2p256(r_z, lam9.as_ptr(), delta.as_ptr());
    let mut lam10: [Limb; 4] = [0; 4];
    shl_sm2p256(lam10.as_mut_ptr(), beta.as_ptr(), 2); // 4beta
    let mut lam11: [Limb; 4] = [0; 4];
    sub_sm2p256(lam11.as_mut_ptr(), lam10.as_ptr(), r_x); // 4beat-x3
    let mut lam12: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(lam12.as_mut_ptr(), alpha.as_ptr(), lam11.as_ptr()); // alpha*(4*beta-x3)
    let mut gamma_sqr: [Limb; 4] = [0; 4];
    mont_pro_sm2p256(gamma_sqr.as_mut_ptr(), gamma.as_ptr(), gamma.as_ptr());
    let mut lam13: [Limb; 4] = [0; 4];
    shl_sm2p256(lam13.as_mut_ptr(), gamma_sqr.as_ptr(), 3); // 8gamma^2
    sub_sm2p256(r_y, lam12.as_ptr(), lam13.as_ptr());
}

fn norop_point_mul_sm2p256(
    r: [*mut Limb; 3],
    a: [*const Limb; 3],
    p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let scalar_ptr = p_scalar as *const u8;
    let scalar_bz = unsafe { slice::from_raw_parts(scalar_ptr, 32) };

    let lam: [Limb; 4] = [0, 0, 0, 0];
    let a_order: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
    unsafe {
        core::ptr::copy(a[0], a_order[0], 4);
        core::ptr::copy(a[1], a_order[1], 4);
        core::ptr::copy(a[2], a_order[2], 4);
    }

    for scalar_byte in scalar_bz {
        let mut bit: usize = 0;
        while bit < 8 {
            let r_const: [*const Limb; 3] = [r[0], r[1], r[2]];
            let a_order_const: [*const Limb; 3] = [a_order[0], a_order[1], a_order[2]];
            if (scalar_byte >> bit) & 0x01 != 0 {
                norop_point_add_sm2p256(r, r_const, a_order_const);
            }
            norop_point_double_sm2p256(a_order, a_order_const);
            bit += 1;
        }
    }
}

fn norop_point_mul_base_sm2p256(
    r: [*mut Limb; 3],
    p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
) {
    let scalar_ptr = p_scalar as *const u8;
    let scalar_bz = unsafe { slice::from_raw_parts(scalar_ptr, 32) };

    for (index, scalar_byte) in scalar_bz.iter().enumerate() {
        let raw_index = (scalar_byte & 0x7f) as usize;
        if raw_index != 0 {
            let r_const: [*const Limb; 3] = [r[0], r[1], r[2]];
            let a_order_const: [*const Limb; 3] = norop_to_jacobi_sm2p256([SM2P256_PRECOMPUTED[index][raw_index*2-2].as_ptr(), SM2P256_PRECOMPUTED[index][raw_index*2-1].as_ptr()]);
            norop_point_add_sm2p256(r, r_const, a_order_const);
        }
        if scalar_byte & 0x80 != 0 {
            let r_const: [*const Limb; 3] = [r[0], r[1], r[2]];
            let a_order_const: [*const Limb; 3] = norop_to_jacobi_sm2p256([SM2P256_PRECOMPUTED[index][254].as_ptr(), SM2P256_PRECOMPUTED[index][255].as_ptr()]);
            norop_point_add_sm2p256(r, r_const, a_order_const);
        }
    }

    // let mut start = 0;
    // for index in 0..37 {
    //     let be = index * 7 / 8;
    //     let mut scalar_byte =  scalar_bz[be] << start;
    //     if start > 1 {
    //         start -= 1;
    //         scalar_byte += scalar_bz[be-1] >> (7 - start)
    //     } else {
    //         start = (start + 7) % 8;
    //     }
    //     scalar_byte &= 0x7f;
    // }
}

// (`a` squared `squarings` times) * b
#[inline]
fn norop_sqr_mul_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
    squarings: usize,
) {
    mont_pro_sm2p256(r, a, a);
    for _ in 1..squarings {
        mont_pro_sm2p256(r, r, r);
    }
    mont_pro_sm2p256(r, r, b)
}

fn norop_to_jacobi_sm2p256(
    a: [*const Limb; 2],
) -> [*const Limb; 3] {
    // 1 * r modsm2p256
    [a[0], a[1], [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0100000000].as_ptr()]
}

fn norop_scalar_mont_pro_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    b: *const Limb, // [COMMON_OPS.num_limbs]
) {
    extern "C" {
        // `r` and/or 'a' and/or 'b' may alias.
        fn GFp_bn_mul_mont(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            n: *const Limb,
            n0: &N0,
            num_limbs: c::size_t,
        );
    }
    unsafe {
        GFp_bn_mul_mont(
            r,
            a,
            b,
            CURVE_PARAMS.n.as_ptr(),
            &CURVE_PARAMS.nn0,
            CURVE_PARAMS.n.len(),
        )
    }
}

// `a` squared `squarings` times
fn norop_scalar_mul_rep_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
    rep: Limb,
) {
    norop_scalar_mont_pro_sm2p256(r, a, a);
    for _ in 1..rep {
        norop_scalar_mont_pro_sm2p256(r, r, r);
    }
}

#[allow(dead_code)]
fn norop_scalar_to_mont_sm2p256(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    norop_scalar_mont_pro_sm2p256(r, a, CURVE_PARAMS.rr_n.as_ptr())
}

pub(crate) fn mont_pro_sm2p256_next(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let mut t = [0; LIMB_LENGTH * 2];
    norop_mul_pure(&mut t, a, b);
    norop_mul_pure_upper(&mut r, &t[0..LIMB_LENGTH], &CURVE_PARAMS.p_inv_r_neg, 4);
    let mut lam2 = [0; LIMB_LENGTH * 2];
    norop_mul_pure(&mut lam2, &r, &CURVE_PARAMS.p);
    let mut lam3 = [0; LIMB_LENGTH * 2];
    let carry = norop_add_pure(&mut lam3, &t, &lam2);

    if carry || norop_limbs_less_than(&lam3[LIMB_LENGTH..], &CURVE_PARAMS.p) == LIMB_FALSE {
        let _ = norop_sub_pure(&mut r, &lam3[LIMB_LENGTH..], &CURVE_PARAMS.p);
        return r;
    }

    r.copy_from_slice(&mut lam3[LIMB_LENGTH..]);
    r
}

#[cfg(test)]
mod sm2p256_norop_test {
    use crate::limb::Limb;
    use crate::ec::suite_b::ops::sm2p256_norop::*;
    use crate::ec::suite_b::private_key::affine_from_jacobian;
    use crate::ec::suite_b::ops::{sm2p256, Point};
    use crate::{rand, signature};
    use crate::signature::{ECDSA_SM2P256_SM3_ASN1, VerificationAlgorithm};

    #[test]
    fn norop_sqr_mul_sm2p256_test() {
        let r: &mut [Limb] = &mut [0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        let b: &[Limb] = &[0x16553623adc0a99a, 0xd3f55c3f46cdfd75, 0x7bdb6926ab664658, 0x52ab139ac09ec830];
        norop_sqr_mul_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 4);
        r.reverse();
        println!("norop_sqr_mul_sm2p256_test: {:x?}", r);
    }

    #[test]
    fn sm2p256_elem_mul_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        mont_pro_sm2p256(r.as_mut_ptr(), a.as_ptr(), a.as_ptr());
        r.reverse();
        println!("sm2p256_elem_mul_test 1: {:x?}", r);

        // 0100000000000000000000000000000000ffffffff0000000000000001 1 * r modsm2p256
        let b: &[Limb] = &[0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0100000000];
        mont_pro_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr());
        r.reverse();
        println!("sm2p256_elem_mul_test 2: {:x?}", r);
    }

    #[test]
    fn sm2p256_to_mont_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        norop_to_mont_sm2p256(r.as_mut_ptr(), a.as_ptr());
        r.reverse();
        println!("sm2p256_to_mont_test: {:x?}", r);
    }

    #[test]
    fn sm2p256_neg_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[0xffffffffffffffff, 0xffffffff00000001, 0xffffffffffffffff, 0xfffffffeffffffff];
        neg_sm2p256(r.as_mut_ptr(), a.as_ptr());
        r.reverse();
        println!("sm2p256_neg_test: {:x?}", r);
    }

    #[test]
    fn sm2p256_sub_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        let b: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        sub_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr());
        r.reverse();
        println!("sm2p256_sub_test 1: {:x?}", r);

        let a: &[Limb] = &[0x0000000000000001, 0x0000000100000000, 0x0000000000000000, 0x0100000000];
        let b: &[Limb] = &[0xffffffffffffffff, 0xffffffff00000001, 0xffffffffffffffff, 0xfffffffeffffffff];
        sub_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr());
        r.reverse();
        println!("sm2p256_sub_test 2: {:x?}", r);
    }

    #[test]
    fn shl_sm2p256_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        shl_sm2p256(r.as_mut_ptr(), a.as_ptr(), 7);
        r.reverse();
        println!("shl_sm2p256_test 2: {:x?}", r);
    }

    #[test]
    fn sm2p256_point_double_test() {
        let ori_point_g_x: &[Limb] = &[0x715a4589334c74c7, 0x8fe30bbff2660be1, 0x5f9904466a39c994, 0x32c4ae2c1f198119];
        let ori_point_g_y: &[Limb] = &[0x02df32e52139f0a0, 0xd0a9877cc62a4740, 0x59bdcee36b692153, 0xbc3736a2f4f6779c];
        let mont_ori_point_g_x: &mut [Limb] = &mut [0, 0, 0, 0];
        norop_to_mont_sm2p256(mont_ori_point_g_x.as_mut_ptr(), ori_point_g_x.as_ptr());
        let mont_ori_point_g_y: &mut [Limb] = &mut [0, 0, 0, 0];
        norop_to_mont_sm2p256(mont_ori_point_g_y.as_mut_ptr(), ori_point_g_y.as_ptr());
        let projective_mont_point_g = norop_to_jacobi_sm2p256([mont_ori_point_g_x.as_ptr(), mont_ori_point_g_y.as_ptr()]);
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let double_projective_mont_point_g: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
        norop_point_double_sm2p256(double_projective_mont_point_g, projective_mont_point_g);
        unsafe {
            let r_x: &mut [Limb] = &mut [0, 0, 0, 0];
            let r_y: &mut [Limb] = &mut [0, 0, 0, 0];
            r_x.copy_from_slice(slice::from_raw_parts(double_projective_mont_point_g[0], 4));
            r_y.copy_from_slice(slice::from_raw_parts(double_projective_mont_point_g[1], 4));
            r_x.reverse();
            r_y.reverse();
            println!("sm2p256_point_double_test: x: {:x?}, y: {:x?}", r_x, r_y);
        }
    }

    #[test]
    fn sm2p256_point_add_test() {
        let g_2_x: &[Limb] = &[0x0af037bfbc3be46a, 0x83bdc9ba2d8fa938, 0x5349d94b5788cd24, 0x0d7e9c18caa5736a];
        let g_2_y: &[Limb] = &[0x6a7e1a1d69db9ac1, 0xccbd8d37c4a8e82b, 0xc7b145169b7157ac, 0x947e74656c21bdf5];
        let g_4_x: &[Limb] = &[0x393f7c5a98615060, 0x487ea27fe9016209, 0x8a86bcb4a09f9020, 0x50dc8e3ac899dbe1];
        let g_4_y: &[Limb] = &[0xfc099043fd619998, 0x1de135ea7c7383bd, 0x4d0bd55632cf70ed, 0x6ffc31c525bce9e3];
        let pro_g_2 = norop_to_jacobi_sm2p256([g_2_x.as_ptr(), g_2_y.as_ptr()]);
        let pro_g_4 = norop_to_jacobi_sm2p256([g_4_x.as_ptr(), g_4_y.as_ptr()]);
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let pro_g_6: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
        norop_point_add_sm2p256(pro_g_6, pro_g_2, pro_g_4);
        unsafe {
            let r_x: &mut [Limb] = &mut [0, 0, 0, 0];
            let r_y: &mut [Limb] = &mut [0, 0, 0, 0];
            r_x.copy_from_slice(slice::from_raw_parts(pro_g_6[0], 4));
            r_y.copy_from_slice(slice::from_raw_parts(pro_g_6[1], 4));
            r_x.reverse();
            r_y.reverse();
            println!("sm2p256_point_add_test: x: {:x?}, y: {:x?}", r_x, r_y);
        }
    }

    #[test]
    fn sm2p256_point_mul_test() {
        let ori_point_g_x: &[Limb] = &[0x715a4589334c74c7, 0x8fe30bbff2660be1, 0x5f9904466a39c994, 0x32c4ae2c1f198119];
        let ori_point_g_y: &[Limb] = &[0x02df32e52139f0a0, 0xd0a9877cc62a4740, 0x59bdcee36b692153, 0xbc3736a2f4f6779c];
        let mont_ori_point_g_x: &mut [Limb] = &mut [0; 4];
        norop_to_mont_sm2p256(mont_ori_point_g_x.as_mut_ptr(), ori_point_g_x.as_ptr());
        let mont_ori_point_g_y: &mut [Limb] = &mut [0; 4];
        norop_to_mont_sm2p256(mont_ori_point_g_y.as_mut_ptr(), ori_point_g_y.as_ptr());
        let projective_mont_point_g = norop_to_jacobi_sm2p256([mont_ori_point_g_x.as_ptr(), mont_ori_point_g_y.as_ptr()]);
        let scalar: &[Limb] = &[31 << 7, 0, 0, 0];
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let pro_point: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
        norop_point_mul_sm2p256(pro_point, projective_mont_point_g, scalar.as_ptr());
        unsafe {
            let r_x: &mut [Limb] = &mut [0, 0, 0, 0];
            let r_y: &mut [Limb] = &mut [0, 0, 0, 0];
            r_x.copy_from_slice(slice::from_raw_parts(pro_point[0], 4));
            r_y.copy_from_slice(slice::from_raw_parts(pro_point[1], 4));
            r_x.reverse();
            r_y.reverse();
            println!("sm2p256_point_mul_test: x: {:x?}, y: {:x?}", r_x, r_y);
        }
    }

    #[test]
    fn sm2p256_point_mul_base_test() {
        let scalar: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let pro_point: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
        norop_point_mul_base_sm2p256(pro_point, scalar.as_ptr());

        let mut nor_point = Point::new_at_infinity();
        unsafe {
            nor_point.xyz[0..4].copy_from_slice(slice::from_raw_parts(pro_point[0], 4));
            nor_point.xyz[4..8].copy_from_slice(slice::from_raw_parts(pro_point[1], 4));
            nor_point.xyz[8..12].copy_from_slice(slice::from_raw_parts(pro_point[2], 4));
        }
        let mut aff_point = affine_from_jacobian(&sm2p256::PRIVATE_KEY_OPS, &nor_point).unwrap();
        aff_point.0.limbs.reverse();
        aff_point.1.limbs.reverse();
        println!("sm2p256_point_mul_base_test: x: {:x?}, y: {:x?}", aff_point.0.limbs, aff_point.1.limbs);
    }

    #[test]
    fn sm2p256_scalar_mul_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[1, 0, 0, 0];
        let b: &[Limb] = &[0x53bbf40939d54122, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff];
        norop_scalar_mont_pro_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr());
        r.reverse();
        println!("sm2p256_scalar_mul_test: {:x?}", r);
    }

    #[test]
    fn sm2p256_calar_mul_rep_test() {
        let r: &mut [Limb] = &mut [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        norop_scalar_mul_rep_sm2p256(r.as_mut_ptr(), a.as_ptr(), 5);
        r.reverse();
        println!("sm2p256_calar_mul_rep_test: {:x?}", r);
    }

    #[test]
    fn sm2p256_signing_test() {
        let rng = rand::SystemRandom::new();
        let msg = b"hello world";

        let prik = hex::decode("b8aa2a5bd9a9cf448984a247e63cb3878859d02b886e1bc63cd5c6dd46a744ab").unwrap();
        let pubk = hex::decode("0479fff92a3df175895778dc9dcc825d95e8bb816c356d6c7390332294b3a20189bb24feac1a4a08ff614a4c514b985755948c0a4e49c0042e84078d4a23df6f7e").unwrap();

        let signing_alg = &signature::ECDSA_SM2P256_SM3_ASN1_SIGNING;

        let private_key =
            signature::EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &prik, &pubk)
                .unwrap();
        let sig = private_key.sign(&rng, msg).unwrap();

        let verify_alg = &ECDSA_SM2P256_SM3_ASN1;

        let _ = verify_alg.verify(
            untrusted::Input::from(private_key.public_key()),
            untrusted::Input::from(msg),
            untrusted::Input::from(sig.as_ref())
        );
    }
}

#[cfg(feature = "internal_benches")]
mod bigint_benches {
    use crate::limb::Limb;
    use crate::ec::suite_b::ops::sm2p256_norop::*;
    use crate::arithmetic::bigint::N0;
    use crate::c;
    use crate::ec::suite_b::ops::sm2p256_norop_pure::mont_pro_sm2p256_pure;

    extern crate test;

    #[bench]
    fn GFp_nistz256_mul_mont_bench(bench: &mut test::Bencher) {
        extern "C" {
            fn GFp_nistz256_mul_mont(
                r: *mut Limb,   // [COMMON_OPS.num_limbs]
                a: *const Limb, // [COMMON_OPS.num_limbs]
                b: *const Limb, // [COMMON_OPS.num_limbs]
            );
        }
        let mut r: [Limb; 4] = [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        bench.iter(||
            {
                unsafe {
                    GFp_nistz256_mul_mont(
                        r.as_mut_ptr(),
                        a.as_ptr(),
                        a.as_ptr(),
                    )
                }
            });
    }

    #[bench]
    fn GFp_bn_mul_mont_bench(bench: &mut test::Bencher) {
        extern "C" {
            // `r` and/or 'a' and/or 'b' may alias.
            fn GFp_bn_mul_mont(
                r: *mut Limb,
                a: *const Limb,
                b: *const Limb,
                n: *const Limb,
                n0: &N0,
                num_limbs: c::size_t,
            );
        }
        let mut r: [Limb; 4] = [0, 0, 0, 0];
        let a: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        bench.iter(||
            {
                unsafe {
                    GFp_bn_mul_mont(
                        r.as_mut_ptr(),
                        a.as_ptr(),
                        a.as_ptr(),
                        CURVE_PARAMS.p.as_ptr(),
                        &CURVE_PARAMS.n0,
                        CURVE_PARAMS.p.len(),
                    )
                }
            });
    }

    #[bench]
    fn mont_pro_sm2p256_next_bench(bench: &mut test::Bencher) {
        let a = [0xffffff8a00000051, 0xffffffdc00000054, 0xffffffba00000031, 0xffffffc400000063];
        // let b = [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x100000000];
        bench.iter(|| {
            let _ = mont_pro_sm2p256_next(&a, &a);
        });
    }

    #[bench]
    fn mont_pro_sm2p256_pure_bench(bench: &mut test::Bencher) {
        let a: &[Limb; 4] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        bench.iter(||
            {
                let _ = mont_pro_sm2p256_pure(a, a);
            });
    }

    #[bench]
    fn sub_sm2p256_bench(bench: &mut test::Bencher) {
        let mut r: [Limb; 4] = [0, 0, 0, 0];
        let a: &[Limb] = &[0x0af037bfbc3be46a, 0x83bdc9ba2d8fa938, 0x5349d94b5788cd24, 0x0d7e9c18caa5736a];
        let b: &[Limb] = &[0x6a7e1a1d69db9ac1, 0xccbd8d37c4a8e82b, 0xc7b145169b7157ac, 0x947e74656c21bdf5];
        bench.iter(||
            {
                sub_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr());
            });
    }

    #[bench]
    fn add_sm2p256_bench(bench: &mut test::Bencher) {
        let mut r: [Limb; 4] = [0, 0, 0, 0];
        let a = [0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        let b = [0x16553623adc0a99a, 0xd3f55c3f46cdfd75, 0x7bdb6926ab664658, 0x52ab139ac09ec830];
        bench.iter(|| {
            add_sm2p256(r.as_mut_ptr(), a.as_ptr(), b.as_ptr());
        })
    }

    #[bench]
    fn LIMBS_shl_mod_bench(bench: &mut test::Bencher) {
        extern "C" {
            fn LIMBS_shl_mod(
                r: *mut Limb,
                a: *const Limb,
                m: *const Limb,
                num_limbs: c::size_t
            );
        }
        let mut r: [Limb; 4] = [0, 0, 0, 0];
        let a: &[Limb] = &[0xfaf037bfbc3be46a, 0x83bdc9ba2d8fa938, 0x5349d94b5788cd24, 0x0d7e9c18caa5736a];
        bench.iter(||
            {
                for _ in 0..7 {
                    unsafe {
                        LIMBS_shl_mod(
                            r.as_mut_ptr(),
                            a.as_ptr(),
                            CURVE_PARAMS.p.as_ptr(),
                            CURVE_PARAMS.p.len(),
                        )
                    }
                }
            });
    }

    #[bench]
    fn norop_point_add_sm2p256_bench(bench: &mut test::Bencher) {
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let r: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
        let g_2_x: &[Limb] = &[0x0af037bfbc3be46a, 0x83bdc9ba2d8fa938, 0x5349d94b5788cd24, 0x0d7e9c18caa5736a];
        let g_2_y: &[Limb] = &[0x6a7e1a1d69db9ac1, 0xccbd8d37c4a8e82b, 0xc7b145169b7157ac, 0x947e74656c21bdf5];
        let pro_g_2 = norop_to_jacobi_sm2p256([g_2_x.as_ptr(), g_2_y.as_ptr()]);
        bench.iter(||
            {
                norop_point_add_sm2p256(r, pro_g_2, pro_g_2);
            });
    }

    #[bench]
    fn norop_point_double_sm2p256_bench(bench: &mut test::Bencher) {
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let r: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
        let g_2_x: &[Limb] = &[0x0af037bfbc3be46a, 0x83bdc9ba2d8fa938, 0x5349d94b5788cd24, 0x0d7e9c18caa5736a];
        let g_2_y: &[Limb] = &[0x6a7e1a1d69db9ac1, 0xccbd8d37c4a8e82b, 0xc7b145169b7157ac, 0x947e74656c21bdf5];
        let pro_g_2 = norop_to_jacobi_sm2p256([g_2_x.as_ptr(), g_2_y.as_ptr()]);
        bench.iter(||
            {
                norop_point_double_sm2p256(r, pro_g_2);
            });
    }

    #[bench]
    fn norop_point_mul_sm2p256_bench(bench: &mut test::Bencher) {
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let g_2_x: &[Limb] = &[0x0af037bfbc3be46a, 0x83bdc9ba2d8fa938, 0x5349d94b5788cd24, 0x0d7e9c18caa5736a];
        let g_2_y: &[Limb] = &[0x6a7e1a1d69db9ac1, 0xccbd8d37c4a8e82b, 0xc7b145169b7157ac, 0x947e74656c21bdf5];
        let pro_g_2 = norop_to_jacobi_sm2p256([g_2_x.as_ptr(), g_2_y.as_ptr()]);
        let scalar: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        bench.iter(||
            {
                let r: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
                norop_point_mul_sm2p256(r, pro_g_2, scalar.as_ptr());
            });
    }

    #[bench]
    fn norop_point_mul_base_sm2p256_bench(bench: &mut test::Bencher) {
        let lam: [Limb; 4] = [0, 0, 0, 0];
        let scalar: &[Limb] = &[0xfffff8950000053b, 0xfffffdc600000543, 0xfffffb8c00000324, 0xfffffc4d0000064e];
        bench.iter(||
            {
                let r: [*mut Limb; 3] = [lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr(), lam.clone().as_mut_ptr()];
                norop_point_mul_base_sm2p256(r, scalar.as_ptr());
            });
    }
}
