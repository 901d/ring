// Copyright 2015-2017 Brian Smith.
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

use crate::{ec, error, rand};
// use libsm::sm2;
// use num_bigint::BigUint;

/// A key agreement algorithm.
macro_rules! suite_b_curve {
    ( $NAME:ident, $bits:expr, $private_key_ops:expr, $id:expr,
      $check_private_key_bytes:ident, $generate_private_key:ident,
      $public_from_private:ident) => {
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in
        /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]. Public keys are
        /// validated during key agreement according to
        /// [NIST Special Publication 800-56A, revision 2] and Appendix B.3 of
        /// the NSA's [Suite B Implementer's Guide to NIST SP 800-56A].
        ///
        /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
        ///     http://www.secg.org/sec1-v2.pdf
        /// [NIST Special Publication 800-56A, revision 2]:
        ///     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
        /// [Suite B Implementer's Guide to NIST SP 800-56A]:
        ///     https://github.com/briansmith/ring/blob/master/doc/ecdh.pdf
        pub static $NAME: ec::Curve = ec::Curve {
            public_key_len: 1 + (2 * (($bits + 7) / 8)),
            elem_scalar_seed_len: ($bits + 7) / 8,
            id: $id,
            check_private_key_bytes: $check_private_key_bytes,
            generate_private_key: $generate_private_key,
            public_from_private: $public_from_private,
        };

        fn $check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
            debug_assert_eq!(bytes.len(), $bits / 8);
            ec::suite_b::private_key::check_scalar_big_endian_bytes($private_key_ops, bytes)
        }

        fn $generate_private_key(
            rng: &dyn rand::SecureRandom,
            out: &mut [u8],
        ) -> Result<(), error::Unspecified> {
            ec::suite_b::private_key::generate_private_scalar_bytes($private_key_ops, rng, out)
        }

        fn $public_from_private(
            public_out: &mut [u8],
            private_key: &ec::Seed,
        ) -> Result<(), error::Unspecified> {
            ec::suite_b::private_key::public_from_private($private_key_ops, public_out, private_key)
        }
    };
}

suite_b_curve!(
    P256,
    256,
    &ec::suite_b::ops::p256::PRIVATE_KEY_OPS,
    ec::CurveID::P256,
    p256_check_private_key_bytes,
    p256_generate_private_key,
    p256_public_from_private
);

suite_b_curve!(
    P384,
    384,
    &ec::suite_b::ops::p384::PRIVATE_KEY_OPS,
    ec::CurveID::P384,
    p384_check_private_key_bytes,
    p384_generate_private_key,
    p384_public_from_private
);

suite_b_curve!(
    SM2P256,
    256,
    &ec::suite_b::ops::sm2p256::PRIVATE_KEY_OPS,
    ec::CurveID::SM2P256,
    sm2p256_check_private_key_bytes,
    sm2p256_generate_private_key,
    sm2p256_public_from_private
);

// pub static SM2P256: ec::Curve = ec::Curve {
//     public_key_len: 65,
//     elem_scalar_seed_len: 32,
//     id: ec::CurveID::SM2P256,
//     check_private_key_bytes: sm2p256_check_private_key_bytes,
//     generate_private_key: sm2p256_generate_private_key,
//     public_from_private: sm2p256_public_from_private,
// };
//
// fn sm2p256_check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
//     ec::suite_b::private_key::check_scalar_big_endian_bytes(&ec::suite_b::ops::sm2p256::PRIVATE_KEY_OPS, bytes)
// }
//
// fn sm2p256_generate_private_key(_rng: &dyn rand::SecureRandom, out: &mut [u8]) -> Result<(), error::Unspecified> {
//     let ctx = sm2::signature::SigCtx::new();
//     let (_pk, sk) = ctx.new_keypair();
//     out.copy_from_slice(&sk.to_bytes_be());
//     Ok(())
// }
//
// fn sm2p256_public_from_private(public_out: &mut [u8], private_key: &ec::Seed) -> Result<(), error::Unspecified> {
//     debug_assert_eq!(public_out.len(), 65);
//     let sk = BigUint::from_bytes_be(private_key.bytes_less_safe());
//     let ctx = sm2::signature::SigCtx::new();
//     let ecctx = sm2::ecc::EccCtx::new();
//     let pk_raw_point = ctx.pk_from_sk(&sk);
//     public_out.copy_from_slice(&ecctx.point_to_bytes(&pk_raw_point, false));
//     Ok(())
// }
