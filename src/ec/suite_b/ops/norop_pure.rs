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

use crate::limb::{Limb, DoubleLimb, LIMB_BITS, LIMB_FULL};
use std::num::Wrapping;

struct DoubleLimbPair(DoubleLimb, DoubleLimb);

impl DoubleLimbPair {
    #[inline]
    fn new(a: DoubleLimb, b: DoubleLimb) -> Self {
        DoubleLimbPair(a, b)
    }

    #[inline]
    fn limb_mul(a: Limb, b: Limb) -> Self {
        let mut u = DoubleLimb::from(a) * DoubleLimb::from(b);
        let v = u >> LIMB_BITS;
        u &= LIMB_FULL as DoubleLimb;
        DoubleLimbPair(u, v)
    }

    #[inline]
    fn pair_add(self, add_pair: Self) -> Self {
        let mut local = self.0 + add_pair.0;
        let mut carry = self.1 + add_pair.1;
        carry += local >> LIMB_BITS;
        local &= LIMB_FULL as DoubleLimb;
        DoubleLimbPair(local, carry)
    }

    #[inline]
    fn add_limb(self, a: Limb) -> Self {
        let mut local = self.0 + a as DoubleLimb;
        let carry = self.1 + local >> LIMB_BITS;
        local &= LIMB_FULL as DoubleLimb;
        DoubleLimbPair(local, carry)
    }
}

/// r.len() >= a.len() + b.len()
#[inline]
pub(crate) fn norop_mul_pure(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb]
) {
    let la = a.len();
    let lb = b.len();
    assert!(r.len() >= (la + lb));
    let mut res_pair = DoubleLimbPair::new(0, 0);
    for index in 0..(la + lb - 1) {
        let min = if lb > index + 1 {
            0
        } else {
            index + 1 - lb
        };
        let mut mid_pair = DoubleLimbPair::new(0, 0);
        for i in min..=(la - 1).min(index) {
            mid_pair = mid_pair.pair_add(DoubleLimbPair::limb_mul(a[i], b[index-i]));
        }
        res_pair = DoubleLimbPair::new(res_pair.1, 0).pair_add(mid_pair);
        r[index] = res_pair.0 as Limb;
    }
    r[la + lb - 1] = res_pair.1 as Limb;
}

/// r.len() >= a.len() + b.len()
#[inline]
pub(crate) fn norop_mul_pure_upper(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    max: usize
) {
    let la = a.len();
    let lb = b.len();
    assert!(r.len() >= (la + lb) || (max != 0 && r.len() >= max));
    let mut res_pair = DoubleLimbPair::new(0, 0);
    for index in 0..(la + lb - 1) {
        let min = if lb > index + 1 {
            0
        } else {
            index + 1 - lb
        };
        let mut mid_pair = DoubleLimbPair::new(0, 0);
        for i in min..=(la - 1).min(index) {
            mid_pair = mid_pair.pair_add(DoubleLimbPair::limb_mul(a[i], b[index-i]));
        }
        res_pair = DoubleLimbPair::new(res_pair.1, 0).pair_add(mid_pair);
        r[index] = res_pair.0 as Limb;
        if index + 1 == max {
            return;
        }
    }
    r[la + lb - 1] = res_pair.1 as Limb;
}

/// r.len() >= a.len() + b.len()
#[inline]
pub(crate) fn norop_mul_pure_lower(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    min: usize
) {
    let la = a.len();
    let lb = b.len();
    assert!(r.len() >= (la + lb - min));
    let mut res_pair = DoubleLimbPair::new(0, 0);
    for index in 0..(la + lb - 1) {
        if min > index {
            continue;
        }
        let lv = if lb > index + 1 {
            0
        } else {
            index + 1 - lb
        };
        let mut mid_pair = DoubleLimbPair::new(0, 0);
        for i in lv..=(la - 1).min(index) {
            mid_pair = mid_pair.pair_add(DoubleLimbPair::limb_mul(a[i], b[index-i]));
        }
        res_pair = DoubleLimbPair::new(res_pair.1, 0).pair_add(mid_pair);
        r[index - min] = res_pair.0 as Limb;
    }
    r[la + lb - 1 - min] = res_pair.1 as Limb;
}

/// r.len() >= max(a.len(), b.len()) + 1
#[inline]
pub(crate) fn norop_add_pure(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
) -> bool {
    let la = a.len();
    let lb = b.len();
    assert!(r.len() >= la.max(lb));
    let mut carry = false;
    for index in 0..la.max(lb) {
        let lhs = if la > index {
            a[index]
        } else {
            0
        };
        let rhs = if lb > index {
            b[index]
        } else {
            0
        };
        let (tmp, c) = limb_add(lhs, rhs, carry);
        r[index] = tmp;
        carry = c;
    }
    carry
}

/// r.len() >= a.len() && a > b
#[inline]
pub(crate) fn norop_sub_pure(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
) -> bool {
    let la = a.len();
    let lb = b.len();
    assert!(la > 0 && lb > 0);
    assert!(r.len() >= la);
    let mut borrow = false;
    for i in 0..la {
        let mut other = 0;
        if lb > i {
            other = b[i];
        }
        let (tmp, need_borrow) = limb_sub(a[i], other, borrow);
        borrow = need_borrow;
        r[i] = tmp;
    }
    borrow
}

/// r.len() = b.len()
#[inline]
pub(crate) fn norop_limb_copy(
    r: &mut [Limb],
    a: &[Limb],
) {
    assert_eq!(r.len(), a.len());
    for i in 0..a.len() {
        r[i] = a[i]
    }
}

#[inline]
fn limb_add(a: Limb, b: Limb, carry: bool) -> (Limb, bool) {
    let (m, c1) = a.overflowing_add(b);
    let (r, c2) = m.overflowing_add(carry as Limb);
    (r, c1 || c2)
}

#[inline]
fn limb_sub(a: Limb, b: Limb, borrow: bool) -> (Limb, bool) {
    if borrow {
        if a > b {
            return (a - b - 1, false);
        }
        return (LIMB_FULL - b + a, true);
    }
    if a < b {
        return (LIMB_FULL - b + a + 1, true);
    }
    (a - b, false)
}

#[inline]
pub(crate) fn norop_limbs_less_than(a: &[Limb], b: &[Limb]) -> Limb {
    let la = a.len();
    let lb = b.len();

    if lb > la {
        for i in 0..lb - la {
            if b[la + i] != 0 { return constant_time_is_zero_w(0); }
        }
    }

    for i in 0..la {
        if la - i > lb  && a[ la - i - 1 ] != 0 { return constant_time_is_nonzero_w(0); }
        else if lb >= la - i {
            if b[la - i - 1] > a[la - i - 1] {
                return constant_time_is_zero_w(0);
            } else if a[la - i - 1] > b[la - i - 1] {
                return constant_time_is_nonzero_w(0);
            }
        }
    }

    return constant_time_is_nonzero_w(0);
}

#[inline]
pub(crate) fn norop_limbs_more_than(a: &[Limb], b: &[Limb]) -> Limb {
    let la = a.len();
    let lb = b.len();

    if la > lb {
        for i in 0..la - lb {
            if a[lb + i] != 0 { return constant_time_is_zero_w(0); }
        }
    }

    for i in 0..lb {
        if lb - i > la  && b[ lb - i - 1 ] != 0 { return constant_time_is_nonzero_w(0); }
        else if la >= lb - i {
            if a[lb - i - 1] > b[lb - i - 1]
            {
                return constant_time_is_zero_w(0);
            } else if b[lb - i - 1] > a[lb - i - 1] {
                return constant_time_is_nonzero_w(0);
            }
        }
    }

    return constant_time_is_nonzero_w(0);
}

#[inline]
pub(crate) fn norop_limbs_equal_with(a: &[Limb], b: &[Limb]) -> Limb {
    let la = a.len();
    let lb = b.len();

    if la > lb {
        for i in 0..la - lb {
            if a[lb + i] != 0 { return constant_time_is_nonzero_w(0); }
        }
    }

    for i in 0..lb {
        if lb - i > la  && b[ lb - i - 1 ] != 0 { return constant_time_is_nonzero_w(0); }
        else if la >= lb - i && a[lb - i - 1] != b[lb - i - 1] {
            return constant_time_is_nonzero_w(0);
        }
    }

    return constant_time_is_zero_w(0);
}

#[inline]
fn constant_time_is_zero_w(a: Limb) -> Limb {
    constant_time_msb_w(!a & (Wrapping(a) - Wrapping(1)).0)
}

#[inline]
fn constant_time_is_nonzero_w(a: Limb) -> Limb {
    !constant_time_msb_w(!a & (Wrapping(a) - Wrapping(1)).0)
}

#[inline]
fn constant_time_msb_w(a: Limb) -> Limb {
    (Wrapping(0) - Wrapping(a >> (std::mem::size_of::<Limb>() * 8 - 1))).0
}

#[cfg(test)]
mod test {
    use crate::limb::{LIMB_TRUE, LIMB_FALSE};
    use crate::ec::suite_b::ops::norop_pure::*;

    #[test]
    fn norop_mul_pure_test() {
        let mut r = [0;8];
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let b = [0xacf005cd78843090, 0xd89cdf6229c4bddf, 0xdc30061d04874834, 0xe5a220abf7212ed6];
        norop_mul_pure(&mut r, &a, &b);
        r.reverse();
        println!("norop_mul_pure_test: {:x?}", r);
    }

    #[test]
    fn norop_add_pure_test() {
        let mut r = [0;4];
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let b = [0xacf005cd78843090, 0xd89cdf6229c4bddf, 0xdc30061d04874834, 0xe5a220abf7212ed6];
        let _ = norop_add_pure(&mut r, &a, &b);
        r.reverse();
        println!("norop_add_pure_test: {:x?}", r);
    }

    #[test]
    fn norop_sub_pure_test() {
        let mut r = [0;4];
        let a = [0xacf005cd78843090, 0xd89cdf6229c4bddf, 0xdc30061d04874834, 0xe5a220abf7212ed6];
        let b = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let _ = norop_sub_pure(&mut r, &a, &b);
        r.reverse();
        println!("norop_sub_pure_test: {:x?}", r);
    }

    #[test]
    fn norop_limbs_less_than_test() {
        let a = [0x12345, 0x23456, 0x34567, 0x45678, 0, 0, 0];
        let b = [0x12345, 0x23456, 0x34567, 0x45678, 0x1, 0];
        assert_eq!(norop_limbs_less_than(&a, &b), LIMB_TRUE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12345, 0x23456, 0x34567, 0, 0, 0];
        assert_eq!(norop_limbs_less_than(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12344, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_less_than(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12346, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_less_than(&a, &b), LIMB_TRUE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12345, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_less_than(&a, &b), LIMB_FALSE);
    }

    #[test]
    fn norop_limbs_more_than_test() {
        let a = [0x12345, 0x23456, 0x34567, 0x45678,0,0,0];
        let b = [0x12345, 0x23456, 0x34567, 0x45678, 0x1,0];
        assert_eq!(norop_limbs_more_than(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12345, 0x23456, 0x34567, 0, 0, 0];
        assert_eq!(norop_limbs_more_than(&a, &b), LIMB_TRUE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12344, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_more_than(&a, &b), LIMB_TRUE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12346, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_more_than(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12345, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_more_than(&a, &b), LIMB_FALSE);
    }

    #[test]
    fn norop_limbs_equal_with_test() {
        let a = [0x12345, 0x23456, 0x34567, 0x45678,0,0,0];
        let b = [0x12345, 0x23456, 0x34567, 0x45678, 0x1,0];
        assert_eq!(norop_limbs_equal_with(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12345, 0x23456, 0x34567];
        assert_eq!(norop_limbs_equal_with(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12344, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_equal_with(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12346, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_equal_with(&a, &b), LIMB_FALSE);

        let a = [0x12345, 0x23456, 0x34567, 0x45678];
        let b = [0x12345, 0x23456, 0x34567, 0x45678];
        assert_eq!(norop_limbs_equal_with(&a, &b), LIMB_TRUE);
    }
}
