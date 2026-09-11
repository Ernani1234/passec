//! Nucleo criptografico do PASSEC.
//!
//! Modelo de chaves (envelope em duas camadas):
//!
//! ```text
//!   senha mestra ─┐
//!                 ├─► Argon2id(salt, m=256MiB, t=3, p=4) ──► KEK (32B, efemera)
//!   keyfile .wav ─┘        (BLAKE3 do PCM, opcional)
//!
//!   KEK ──XChaCha20-Poly1305(AAD = header)──► desembrulha VaultKey (32B)
//!
//!   VaultKey ──BLAKE3::derive_key(dominio)──► subchaves por finalidade
//!                                             ├─ corpo do cofre
//!                                             ├─ exportacao em audio
//!                                             └─ segredo TOTP
//! ```
//!
//! A VaultKey e sorteada uma unica vez na criacao do cofre e nunca muda:
//! trocar a senha mestra apenas re-embrulha os mesmos 32 bytes, entao a
//! operacao e instantanea e nao reescreve o corpo cifrado.
//!
//! O header viaja como AAD (dado associado autenticado) em *ambas* as
//! camadas. Isso amarra os parametros do KDF ao ciphertext: um atacante que
//! edite o arquivo para baixar o custo do Argon2id de 256MiB para 8KiB
//! invalida a tag Poly1305 e a abertura falha, em vez de ficar barata.

pub mod aead;
pub mod kdf;
pub mod keyfile;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Todas as chaves simetricas do sistema tem 256 bits.
pub const KEY_LEN: usize = 32;

/// Chave simetrica que se apaga da RAM ao sair de escopo.
///
/// Nao implementa `Debug` nem `Display` de proposito: material de chave nunca
/// deve escorregar para um log, um `dbg!` ou uma mensagem de panico.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Sorteia uma chave nova do CSPRNG do sistema.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random_array::<KEY_LEN>()?))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Deriva uma subchave ligada a um dominio textual.
    ///
    /// Dominios distintos produzem chaves independentes, entao o ciphertext de
    /// um export em audio nunca e decifravel com a chave do corpo do cofre.
    pub fn derive(&self, domain: &str) -> Self {
        Self(blake3::derive_key(domain, &self.0))
    }
}

/// Dominios de derivacao. Constantes para que um erro de digitacao vire erro
/// de compilacao em vez de duas chaves silenciosamente diferentes.
pub mod domain {
    pub const VAULT_BODY: &str = "passec.vault.body.v1";
    pub const AUDIO_EXPORT: &str = "passec.audio.export.v1";
    pub const AUDIO_ENTRY: &str = "passec.audio.entry.v1";
    pub const TOTP_SECRET: &str = "passec.totp.secret.v1";
    pub const HELLO_WRAP: &str = "passec.hello.wrap.v1";
}

/// Sorteia `N` bytes do CSPRNG do sistema (BCryptGenRandom no Windows).
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

/// Sorteia `n` bytes do CSPRNG do sistema.
pub fn random_vec(n: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("falha ao obter entropia do sistema")]
    Rng,

    #[error("derivacao de chave falhou: {0}")]
    Kdf(String),

    /// Mensagem deliberadamente vaga: distinguir "senha errada" de "arquivo
    /// corrompido" entrega ao atacante um oraculo sobre o material de chave.
    #[error("nao foi possivel abrir o cofre — senha mestra, keyfile ou arquivo invalido")]
    Decrypt,

    #[error("falha ao cifrar")]
    Encrypt,

    #[error("parametros de KDF fora da faixa aceita")]
    BadKdfParams,
}
