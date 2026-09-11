//! Criptografia autenticada com XChaCha20-Poly1305.
//!
//! XChaCha20 (nonce de 192 bits) em vez de ChaCha20 ou AES-GCM (96 bits)
//! porque com 192 bits um nonce **aleatorio** e seguro na pratica: a chance de
//! colisao so deixa de ser desprezivel perto de 2^80 mensagens. Com 96 bits
//! seria preciso manter um contador persistente em disco, e um contador que
//! regride — restauracao de backup, copia do cofre para outra maquina —
//! reusa nonce e quebra a confidencialidade por inteiro.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use super::{random_array, CryptoError, SecretKey};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Cifra `plaintext` e devolve `nonce (24B) || ciphertext || tag (16B)`.
///
/// `aad` e autenticado mas nao cifrado: viaja em claro e qualquer alteracao
/// nele faz `open` falhar.
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::Encrypt)?;

    let nonce_bytes = random_array::<NONCE_LEN>()?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Verifica a tag e decifra um blob produzido por [`seal`].
///
/// O retorno e `Zeroizing`: o plaintext some da RAM quando o chamador o larga.
pub fn open(
    key: &SecretKey,
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);

    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::Decrypt)?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        // Poly1305 ja rejeitou; qualquer causa vira o mesmo erro opaco para
        // nao virar oraculo.
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::from_bytes([9u8; 32])
    }

    #[test]
    fn ida_e_volta() {
        let k = key();
        let sealed = seal(&k, b"senha-do-banco", b"header").unwrap();
        let opened = open(&k, &sealed, b"header").unwrap();
        assert_eq!(&opened[..], b"senha-do-banco");
    }

    #[test]
    fn aad_diferente_falha() {
        let k = key();
        let sealed = seal(&k, b"segredo", b"header-v1").unwrap();
        // Exatamente o cenario de downgrade: header adulterado, tag invalida.
        assert!(open(&k, &sealed, b"header-v2").is_err());
    }

    #[test]
    fn chave_errada_falha() {
        let sealed = seal(&key(), b"segredo", b"").unwrap();
        assert!(open(&SecretKey::from_bytes([1u8; 32]), &sealed, b"").is_err());
    }

    #[test]
    fn ciphertext_adulterado_falha() {
        let k = key();
        let mut sealed = seal(&k, b"segredo", b"").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&k, &sealed, b"").is_err());
    }

    #[test]
    fn nonce_nunca_se_repete_entre_chamadas() {
        let k = key();
        let a = seal(&k, b"x", b"").unwrap();
        let b = seal(&k, b"x", b"").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        // Mesmo plaintext e mesma chave produzem ciphertext distinto.
        assert_ne!(a, b);
    }

    #[test]
    fn blob_truncado_falha_sem_panico() {
        let k = key();
        let sealed = seal(&k, b"segredo", b"").unwrap();
        for corte in [0usize, 1, NONCE_LEN, NONCE_LEN + 1, sealed.len() - 1] {
            assert!(open(&k, &sealed[..corte], b"").is_err());
        }
    }
}
