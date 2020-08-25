// Copyright 2016 Brian Smith.
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

//! Elliptic curve operations on P-256 & P-384.

use self::ops::*;
use crate::{arithmetic::montgomery::*, cpu, ec, error, io::der, limb::LimbMask, pkcs8};
use untrusted;
use std::marker::PhantomData;

// NIST SP 800-56A Step 3: "If q is an odd prime p, verify that
// yQ**2 = xQ**3 + axQ + b in GF(p), where the arithmetic is performed modulo
// p."
//
// That is, verify that (x, y) is on the curve, which is true iif:
//
//     y**2 == x**3 + a*x + b (mod q)
//
// Or, equivalently, but more efficiently:
//
//     y**2 == (x**2 + a)*x + b  (mod q)
//
fn verify_affine_point_is_on_the_curve(
    ops: &CommonOps,
    (x, y): (&Elem<R>, &Elem<R>),
) -> Result<(), error::Unspecified> {
    verify_affine_point_is_on_the_curve_scaled(ops, (x, y), &ops.a, &ops.b)
}

// Use `verify_affine_point_is_on_the_curve` instead of this function whenever
// the affine coordinates are available or will become available. This function
// should only be used then the affine coordinates are never calculated. See
// the notes for `verify_affine_point_is_on_the_curve_scaled`.
//
// The value `z**2` is returned on success because it is useful for ECDSA
// verification.
//
// This function also verifies that the point is not at infinity.
fn verify_jacobian_point_is_on_the_curve(
    ops: &CommonOps,
    p: &Point,
) -> Result<Elem<R>, error::Unspecified> {
    let z = ops.point_z(p);

    // Verify that the point is not at infinity.
    ops.elem_verify_is_not_zero(&z)?;

    let x = ops.point_x(p);
    let y = ops.point_y(p);

    // We are given Jacobian coordinates (x, y, z). So, we have:
    //
    //    (x/z**2, y/z**3) == (x', y'),
    //
    // where (x', y') are the affine coordinates. The curve equation is:
    //
    //     y'**2  ==  x'**3 + a*x' + b  ==  (x'**2 + a)*x' + b
    //
    // Substituting our Jacobian coordinates, we get:
    //
    //    /   y  \**2       /  /   x  \**2       \   /   x  \
    //    | ---- |      ==  |  | ---- |    +  a  | * | ---- |  +  b
    //    \ z**3 /          \  \ z**2 /          /   \ z**2 /
    //
    // Simplify:
    //
    //            y**2      / x**2       \     x
    //            ----  ==  | ----  +  a | * ----  +  b
    //            z**6      \ z**4       /   z**2
    //
    // Multiply both sides by z**6:
    //
    //     z**6             / x**2       \   z**6
    //     ---- * y**2  ==  | ----  +  a | * ---- * x  +  (z**6) * b
    //     z**6             \ z**4       /   z**2
    //
    // Simplify:
    //
    //                      / x**2       \
    //            y**2  ==  | ----  +  a | * z**4 * x  +  (z**6) * b
    //                      \ z**4       /
    //
    // Distribute z**4:
    //
    //                      / z**4                     \
    //            y**2  ==  | ---- * x**2  +  z**4 * a | * x  +  (z**6) * b
    //                      \ z**4                     /
    //
    // Simplify:
    //
    //            y**2  ==  (x**2  +  z**4 * a) * x  +  (z**6) * b
    //
    let z2 = ops.elem_squared(&z);
    let z4 = ops.elem_squared(&z2);
    let z4_a = ops.elem_product(&z4, &ops.a);
    let z6 = ops.elem_product(&z4, &z2);
    let z6_b = ops.elem_product(&z6, &ops.b);
    verify_affine_point_is_on_the_curve_scaled(ops, (&x, &y), &z4_a, &z6_b)?;
    Ok(z2)
}

// Handles the common logic of point-is-on-the-curve checks for both affine and
// Jacobian cases.
//
// When doing the check that the point is on the curve after a computation,
// to avoid fault attacks or mitigate potential bugs, it is better for security
// to use `verify_affine_point_is_on_the_curve` on the affine coordinates,
// because it provides some protection against faults that occur in the
// computation of the inverse of `z`. See the paper and presentation "Fault
// Attacks on Projective-to-Affine Coordinates Conversion" by Diana Maimuţ,
// Cédric Murdica, David Naccache, Mehdi Tibouchi. That presentation concluded
// simply "Check the validity of the result after conversion to affine
// coordinates." (It seems like a good idea to verify that
// z_inv * z == 1 mod q too).
//
// In the case of affine coordinates (x, y), `a_scaled` and `b_scaled` are
// `a` and `b`, respectively. In the case of Jacobian coordinates (x, y, z),
// the computation and comparison is the same, except `a_scaled` and `b_scaled`
// are (z**4 * a) and (z**6 * b), respectively. Thus, performance is another
// reason to prefer doing the check on the affine coordinates, as Jacobian
// computation requires 3 extra multiplications and 2 extra squarings.
//
// An example of a fault attack that isn't mitigated by a point-on-the-curve
// check after multiplication is given in "Sign Change Fault Attacks On
// Elliptic Curve Cryptosystems" by Johannes Blömer, Martin Otto, and
// Jean-Pierre Seifert.
fn verify_affine_point_is_on_the_curve_scaled(
    ops: &CommonOps,
    (x, y): (&Elem<R>, &Elem<R>),
    a_scaled: &Elem<R>,
    b_scaled: &Elem<R>,
) -> Result<(), error::Unspecified> {
    let lhs = ops.elem_squared(y);

    let mut rhs = ops.elem_squared(x);
    ops.elem_add(&mut rhs, a_scaled);
    ops.elem_mul(&mut rhs, x);
    ops.elem_add(&mut rhs, b_scaled);

    if ops.elems_are_equal(&lhs, &rhs) != LimbMask::True {
        return Err(error::Unspecified);
    }

    Ok(())
}

pub(crate) fn key_pair_from_pkcs8(
    curve: &'static ec::Curve,
    template: &pkcs8::Template,
    input: untrusted::Input,
    cpu_features: cpu::Features,
) -> Result<ec::KeyPair, error::KeyRejected> {
    let (ec_private_key, _) = pkcs8::unwrap_key(template, pkcs8::Version::V1Only, input)?;
    let (private_key, public_key) =
        ec_private_key.read_all(error::KeyRejected::invalid_encoding(), |input| {
            // https://tools.ietf.org/html/rfc5915#section-3
            der::nested(
                input,
                der::Tag::Sequence,
                error::KeyRejected::invalid_encoding(),
                |input| key_pair_from_pkcs8_(template, input),
            )
        })?;
    key_pair_from_bytes(curve, private_key, public_key, cpu_features)
}

fn key_pair_from_pkcs8_<'a>(
    template: &pkcs8::Template,
    input: &mut untrusted::Reader<'a>,
) -> Result<(untrusted::Input<'a>, untrusted::Input<'a>), error::KeyRejected> {
    let version = der::small_nonnegative_integer(input)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
    if version != 1 {
        return Err(error::KeyRejected::version_not_supported());
    }

    let private_key = der::expect_tag_and_get_value(input, der::Tag::OctetString)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

    // [0] parameters (optional).
    if input.peek(u8::from(der::Tag::ContextSpecificConstructed0)) {
        let actual_alg_id =
            der::expect_tag_and_get_value(input, der::Tag::ContextSpecificConstructed0)
                .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
        if actual_alg_id != template.curve_oid() {
            return Err(error::KeyRejected::wrong_algorithm());
        }
    }

    // [1] publicKey. The RFC says it is optional, but we require it
    // to be present.
    let public_key = der::nested(
        input,
        der::Tag::ContextSpecificConstructed1,
        error::Unspecified,
        der::bit_string_with_no_unused_bits,
    )
    .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

    Ok((private_key, public_key))
}

pub(crate) fn key_pair_from_bytes(
    curve: &'static ec::Curve,
    private_key_bytes: untrusted::Input,
    public_key_bytes: untrusted::Input,
    cpu_features: cpu::Features,
) -> Result<ec::KeyPair, error::KeyRejected> {
    let seed = ec::Seed::from_bytes(curve, private_key_bytes, cpu_features)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_component())?;

    let r = ec::KeyPair::derive(seed)
        .map_err(|error::Unspecified| error::KeyRejected::unexpected_error())?;
    if public_key_bytes != *r.public_key().as_ref() {
        return Err(error::KeyRejected::inconsistent_components());
    }

    Ok(r)
}

pub mod curve;
pub mod ecdh;
pub mod ecdsa;

mod ops;

mod private_key;
mod public_key;

macro_rules! p256_limbs {
    [ $($limb:expr),+ ] => {
        limbs![$($limb),+, 0, 0, 0, 0]
    };
}

#[test]
fn verify_affine_point_is_on_the_curve_scaled_test() {
    let g: (Elem<R>, Elem<R>) = (
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

    assert!(verify_affine_point_is_on_the_curve_scaled(&sm2p256::COMMON_OPS, (&g.0, &g.1), &sm2p256::COMMON_OPS.a, &sm2p256::COMMON_OPS.b).is_ok());
}

#[test]
fn sm2p256_point_mul_test() {
    let scalar = Scalar {
        limbs: p256_limbs![
            0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b, 0xffffffff, 0xffffffff, 0xffffffff,
            0xfffffeee
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let p = sm2p256::PRIVATE_KEY_OPS.point_mul_base(&scalar);
    assert!(verify_jacobian_point_is_on_the_curve(&sm2p256::COMMON_OPS, &p).is_ok());
}

#[test]
fn sm2p256_point_add_test() {
    let scalar1 = Scalar {
        limbs: p256_limbs![
            10, 0, 0, 0, 0, 0, 0, 0
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let p1 = sm2p256::PRIVATE_KEY_OPS.point_mul_base(&scalar1);
    let scalar2 = Scalar {
        limbs: p256_limbs![
            15, 0, 0, 0, 0, 0, 0, 0
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let p2 = sm2p256::PRIVATE_KEY_OPS.point_mul_base(&scalar2);
    let p = sm2p256::COMMON_OPS.point_sum(&p1, &p2);
    assert!(verify_jacobian_point_is_on_the_curve(&sm2p256::COMMON_OPS, &p).is_ok());
}

#[test]
fn sm2p256_elem_inv_squared_test() {
    let elem = Elem {
        limbs: p256_limbs![
            0xa88a09af, 0x7eedf6ee, 0xff6feeeb, 0x381cfa4a, 0x117f899f, 0x289e5602,
            0xe73f380b, 0xa69b63a2
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let expect_elem = Elem {
        limbs: p256_limbs![
            0x80f59e24, 0xf30353a5, 0x1a42cc6c, 0xaf397c87, 0x1dfd4054, 0xf6a573b6,
            0x2c3b4a49, 0x22bee6f8
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let inv_sqr_elem = sm2p256::PRIVATE_KEY_OPS.elem_inverse_squared(&elem);
    assert_eq!(sm2p256::PRIVATE_KEY_OPS.common.elems_are_equal(&inv_sqr_elem, &expect_elem), LimbMask::True)

}

#[test]
fn sm2p256_scalar_inv_to_mont_test() {
    let elem = Scalar {
        limbs: p256_limbs![
            0xadc0a99a, 0x16553623, 0x46cdfd75, 0xd3f55c3f, 0xab664658, 0x7bdb6926,
            0xc09ec830, 0x52ab139a
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let expect_elem = Elem {
        limbs: p256_limbs![
            0x07351abb, 0xd73bee1a, 0x64611057, 0x8a7ab60c, 0x80bffdae, 0x41941fa8,
            0x1523b2b9, 0x8b27cc69
        ],
        m: PhantomData,
        encoding: PhantomData,
    };
    let inv_sqr_scalar = sm2p256::SCALAR_OPS.scalar_inv_to_mont(&elem);
    let inv_sqr_elem = Elem {
        limbs: inv_sqr_scalar.limbs,
        m: PhantomData,
        encoding: PhantomData,
    };
    assert_eq!(sm2p256::SCALAR_OPS.common.elems_are_equal(&inv_sqr_elem, &expect_elem), LimbMask::True);
}
