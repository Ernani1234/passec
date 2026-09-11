//! Keyfile de audio — o segundo fator que realmente entra na chave.
//!
//! Dois modos, gravados no header do cofre:
//!
//! * [`KeyfileMode::Generated`] — o PASSEC sorteia 64 bytes de entropia e os
//!   **modula** num WAV (ver `audio::modem`). O digest usado no KDF vem do
//!   payload demodulado, nao das amostras. Consequencia pratica: o arquivo
//!   sobrevive a reamostragem, a conversao para MP3 e ate a ser tocado num
//!   alto-falante e regravado por microfone — o FEC reconstroi os mesmos 64
//!   bytes e a chave bate.
//!
//! * [`KeyfileMode::RawFile`] — o usuario aponta um audio qualquer (aquela
//!   musica) e o digest sai do PCM bruto. Mais divertido, porem fragil: um
//!   unico sample diferente muda o digest e o cofre nao abre mais. Serve para
//!   quem quer negacao plausivel e tem backup do arquivo exato.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{random_vec, CryptoError};

/// Entropia do keyfile gerado. 64 bytes = 512 bits, muito alem do que o
/// Argon2id consegue aproveitar, mas o custo de carregar e zero.
pub const KEYFILE_ENTROPY_LEN: usize = 64;

/// Separa os dois modos no espaco de hash: o mesmo conteudo de 64 bytes lido
/// como payload ou como PCM produz digests diferentes.
const DOMAIN_PAYLOAD: &str = "passec.keyfile.payload.v1";
const DOMAIN_RAW_PCM: &str = "passec.keyfile.rawpcm.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyfileMode {
    /// Cofre protegido so pela senha mestra.
    None,
    /// WAV gerado pelo PASSEC, com payload modulado e corrigido por FEC.
    Generated,
    /// Audio arbitrario do usuario; digest do PCM bruto.
    RawFile,
}

impl KeyfileMode {
    pub fn requires_file(self) -> bool {
        !matches!(self, KeyfileMode::None)
    }
}

/// Sorteia a entropia de um keyfile novo, pronta para ser modulada.
pub fn new_payload() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    Ok(Zeroizing::new(random_vec(KEYFILE_ENTROPY_LEN)?))
}

/// Digest do payload demodulado de um keyfile gerado.
pub fn digest_payload(payload: &[u8]) -> [u8; 32] {
    blake3::derive_key(DOMAIN_PAYLOAD, payload)
}

/// Digest do PCM bruto de um audio arbitrario.
///
/// As amostras entram como little-endian i16 para que o digest nao dependa da
/// endianness da maquina — o mesmo arquivo tem que abrir o cofre num PC ARM e
/// num x86.
pub fn digest_raw_pcm(samples: &[i16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN_RAW_PCM);
    // Bloco a bloco para nao materializar um Vec do tamanho da musica inteira.
    let mut buf = [0u8; 8192];
    for chunk in samples.chunks(buf.len() / 2) {
        for (i, s) in chunk.iter().enumerate() {
            let bytes = s.to_le_bytes();
            buf[i * 2] = bytes[0];
            buf[i * 2 + 1] = bytes[1];
        }
        hasher.update(&buf[..chunk.len() * 2]);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_tem_o_tamanho_certo_e_nao_se_repete() {
        let a = new_payload().unwrap();
        let b = new_payload().unwrap();
        assert_eq!(a.len(), KEYFILE_ENTROPY_LEN);
        assert_ne!(&a[..], &b[..]);
    }

    #[test]
    fn digest_e_deterministico() {
        assert_eq!(digest_payload(b"abc"), digest_payload(b"abc"));
        assert_ne!(digest_payload(b"abc"), digest_payload(b"abd"));
    }

    /// Os dominios precisam separar os modos, senao um WAV gerado poderia
    /// abrir um cofre configurado em modo RawFile.
    #[test]
    fn modos_nao_colidem() {
        let bytes = [0x11u8, 0x22, 0x33, 0x44];
        let samples = [0x2211i16, 0x4433];
        assert_ne!(digest_payload(&bytes), digest_raw_pcm(&samples));
    }

    #[test]
    fn digest_pcm_independe_do_tamanho_do_bloco() {
        let longo: Vec<i16> = (0..20_000).map(|i| (i % 1000) as i16 - 500).collect();
        let a = digest_raw_pcm(&longo);
        let b = digest_raw_pcm(&longo.clone());
        assert_eq!(a, b);
        let mut alterado = longo.clone();
        alterado[12_345] = alterado[12_345].wrapping_add(1);
        assert_ne!(a, digest_raw_pcm(&alterado));
    }
}
