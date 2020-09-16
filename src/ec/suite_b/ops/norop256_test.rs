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

use crate::{rand, signature};

mod test {
    use crate::ec::suite_b::ops::{norop256, p256, Elem};
    use crate::ec::suite_b::ops::sm2p256_norop::mont_pro_sm2p256_next;
    use crate::arithmetic::montgomery::R;

    #[test]
    fn norop256_mul_test() {
        let a = [0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab, 0x04874834,
                0xdc30061d];
        let b = norop256::norop256_mul(&a, &a);
        let (_prefix, shorts, _suffix) = unsafe { b.align_to::<u8>() };
        println!("{}", hex::encode(shorts));
    }

    #[test]
    fn norop256_mul_u128_test() {
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let b = norop256::norop256_mul_u128(&a, &a);
        let (_prefix, shorts, _suffix) = unsafe { b.align_to::<u8>() };
        println!("{}", hex::encode(shorts));
    }

    #[test]
    fn norop256_mul_u128_next_test() {
        let a = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
        let b = norop256::norop256_mul_u128_next(&a, &a);
        let (_prefix, shorts, _suffix) = unsafe { b.align_to::<u8>() };
        println!("{}", hex::encode(shorts));
    }

    #[test]
    fn mont_pro_sm2p256_next_test() {
        let a = [0xffffff8a00000051, 0xffffffdc00000054, 0xffffffba00000031, 0xffffffc400000063];
        let b = [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x100000000];
        let r = mont_pro_sm2p256_next(&a, &b);
        let (_prefix, shorts, _suffix) = unsafe { r.align_to::<u8>() };
        println!("mont_pro_sm2p256_next_test: {}", hex::encode(shorts));
    }

    #[test]
    fn elem_product_bench() {
        // This benchmark assumes that the multiplication is constant-time
        // so 0 * 0 is as good of a choice as anything.
        let a: Elem<R> = Elem::zero();
        let b: Elem<R> = Elem::zero();
        let _ = p256::COMMON_OPS.elem_product(&a, &b);
    }
}

#[cfg(feature = "internal_benches")]
mod internal_benches {
    use num_bigint::BigUint;
    use crate::ec::suite_b::ops::norop256::{norop256_mul, norop256_mul_u128, norop256_mul_u128_next};
    use crate::ec::suite_b::ops::sm2p256_norop::mont_pro_sm2p256_next;
    use crate::{signature, rand};

    extern crate test;

    #[bench]
    fn norop256_mul_bench(bench: &mut test::Bencher) {
        let a = [0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab, 0x04874834,
                0xdc30061d];
        bench.iter(|| {
            let _ = norop256_mul(&a, &a);
        });
    }

    #[bench]
    fn norop256_mul_biguint_bench(bench: &mut test::Bencher) {
        let a = BigUint::from_bytes_be(&hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122").unwrap());
        bench.iter(|| {
            let _ = &a * &a;
        });
    }

    #[bench]
    fn norop256_mul_u128_bench(bench: &mut test::Bencher) {
        let a = [0x29c4bddfd89cdf62, 0x78843090acf005cd, 0xf7212ed65a220ab, 0x04874834dc30061d];
        bench.iter(|| {
            let _ = norop256_mul_u128(&a, &a);
        });
    }

    #[bench]
    fn norop256_mul_u128_next_bench(bench: &mut test::Bencher) {
        let a = [0x29c4bddfd89cdf62, 0x78843090acf005cd, 0xf7212ed65a220ab, 0x04874834dc30061d];
        bench.iter(|| {
            let _ = norop256_mul_u128_next(&a, &a);
        });
    }

    #[bench]
    fn mont_pro_sm2p256_next_bench(bench: &mut test::Bencher) {
        let a = [0xffffff8a00000051, 0xffffffdc00000054, 0xffffffba00000031, 0xffffffc400000063];
        let b = [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x100000000];
        bench.iter(|| {
            let _ = mont_pro_sm2p256_next(&a, &b);
        });
    }

    #[bench]
    fn sm2p256_signing_bench(bench: &mut test::Bencher) {
        let rng = rand::SystemRandom::new();
        let msg = hex::decode("5905238877c774").unwrap();

        let prik = hex::decode("b8aa2a5bd9a9cf448984a247e63cb3878859d02b886e1bc63cd5c6dd46a744ab").unwrap();
        let pubk = hex::decode("0479fff92a3df175895778dc9dcc825d95e8bb816c356d6c7390332294b3a20189bb24feac1a4a08ff614a4c514b985755948c0a4e49c0042e84078d4a23df6f7e").unwrap();

        let signing_alg = &signature::ECDSA_SM2P256_SM3_ASN1_SIGNING;

        let private_key =
            signature::EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &prik, &pubk)
                .unwrap();

        bench.iter(|| {
            let _ = private_key.sign(&rng, &msg).unwrap();
        });
    }

    #[bench]
    fn p256_signing_bench(bench: &mut test::Bencher) {
        let rng = rand::SystemRandom::new();
        let msg = hex::decode("5905238877c774").unwrap();

        let prik = hex::decode("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").unwrap();
        let pubk = hex::decode("041ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9").unwrap();

        let signing_alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;

        let private_key =
            signature::EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &prik, &pubk)
                .unwrap();

        bench.iter(|| {
            let _ = private_key.sign(&rng, &msg).unwrap();
        });
    }
}

#[test]
fn sm2p256_signing_test() {
    let rng = rand::SystemRandom::new();
    let msg = hex::decode("5905238877c774").unwrap();

    let prik = hex::decode("b8aa2a5bd9a9cf448984a247e63cb3878859d02b886e1bc63cd5c6dd46a744ab").unwrap();
    let pubk = hex::decode("0479fff92a3df175895778dc9dcc825d95e8bb816c356d6c7390332294b3a20189bb24feac1a4a08ff614a4c514b985755948c0a4e49c0042e84078d4a23df6f7e").unwrap();

    let signing_alg = &signature::ECDSA_SM2P256_SM3_ASN1_SIGNING;

    let private_key =
        signature::EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &prik, &pubk)
            .unwrap();

    let _ = private_key.sign(&rng, &msg).unwrap();
}