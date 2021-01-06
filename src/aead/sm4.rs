use crate::{aead, cpu, error};
use crate::aead::{KeyInner, Nonce, Aad, Tag, Direction};
use crate::aead::nonce::Counter;
use libsm::sm4::cipher_mode::{SM4CipherMode, CipherMode};
use crate::endian::BigEndian;

const KEY_LEN: usize = 16;

/// SM4 with cfb mod
pub static SM4_CBC: aead::Algorithm = aead::Algorithm {
    key_len: 16,
    init: init_key,
    seal: sm4_cbc_seal,
    open: sm4_cbc_open,
    id: aead::AlgorithmID::SM4_CBC,
    max_input_len: super::max_input_len(16, 2),
};

pub struct Key([u8; KEY_LEN]);

impl Key {
    fn from(value: &[u8]) -> Self {
        let mut ret = Key([0; KEY_LEN]);
        ret.0.copy_from_slice(value);
        ret
    }

    fn value(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn init_key(key: &[u8], _cpu_features: cpu::Features) -> Result<KeyInner, error::Unspecified> {
    Ok(KeyInner::SM4CBC(Key::from(key)))
}

fn sm4_cbc_seal(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Tag {
    aead(key, nonce, aad, in_out, Direction::Sealing, cpu_features)
}

fn sm4_cbc_open(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_prefix_len: usize,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Tag {
    aead(key, nonce, aad, in_out, Direction::Opening {in_prefix_len}, cpu_features)
}

#[inline(always)] // Statically eliminate branches on `direction`.
fn aead(
    key: &KeyInner,
    nonce: Nonce,
    Aad(_aad): Aad<&[u8]>,
    in_out: &mut [u8],
    direction: Direction,
    _todo: cpu::Features,
) -> Tag {
    let sm4_key = match key {
        KeyInner::SM4CBC(key) => key,
        _ => unreachable!(),
    };

    let mut counter: Counter<BigEndian<u32>> = Counter::one(nonce);
    let tag_iv = counter.increment();
    let sm4cm = SM4CipherMode::new(sm4_key.value(), CipherMode::Cbc);

    if let Direction::Opening {..} = direction {
        in_out.copy_from_slice(&sm4cm.encrypt(in_out, counter.increment().into_block_less_safe().as_ref()));
    } else {
        in_out.copy_from_slice(&sm4cm.decrypt(in_out, counter.increment().into_block_less_safe().as_ref()));
    }
    let block = tag_iv.into_block_less_safe();
    Tag(block)
}
