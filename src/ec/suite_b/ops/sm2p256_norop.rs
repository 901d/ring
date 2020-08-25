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

use crate::ec::suite_b::ops::norop256::{norop256_mul_u128, norop256_mul_u512_u128, norop256_add_u512_u128};

pub static CURVE_PARAMS: curve_params = curve_params {
    a: [0; 4],
    b: [0; 4],
    p: [0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff],
    n: [0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff],
    p_inv_r_neg: [0x0000000000000001, 0xffffffff00000001, 0xfffffffe00000000, 0xfffffffc00000001],
    rr_p: [0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0400000002],
    n_inv_r_neg: [0x327f9e8872350975, 0xdf1e8d34fc8319a5, 0x2b0068d3b08941d4, 0x6f39132f82e4c7bc],
    rr_n: [0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b],
};

pub struct curve_params {
    a: [u64; 4],
    b: [u64; 4],
    p: [u64; 4],
    n: [u64; 4],
    p_inv_r_neg: [u64; 4],
    rr_p: [u64; 4],
    n_inv_r_neg: [u64; 4],
    rr_n: [u64; 4],
}

pub(crate) fn mont_pro_sm2p256_next(
    a: &[u64; 4],
    b: &[u64; 4],
) -> [u64; 4] {
    let t = norop256_mul_u128(a, b);
    let mut m = [0; 4];
    unsafe {
        core::ptr::copy(norop256_mul_u512_u128(&t, &CURVE_PARAMS.p_inv_r_neg)[8..].as_ptr(), m.as_mut_ptr(), 4);
    }
    let m_mul_p = norop256_mul_u128(&m, &CURVE_PARAMS.p);
    let mut r =  [0; 4];
    unsafe {
        core::ptr::copy(norop256_add_u512_u128(&t, &m_mul_p)[4..8].as_ptr(), r.as_mut_ptr(), 4);
    }
    r
}

