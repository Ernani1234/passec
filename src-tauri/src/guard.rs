//! Modo "em guarda" e a combinacao de teclas que sai dele.
//!
//! # O que e
//!
//! Um estado intermediario entre aberto e trancado, para a pausa curta: o
//! cafe, a ida ao banheiro, alguem que chega na mesa. A interface fecha na
//! hora, mas as chaves continuam na RAM, entao voltar custa uma combinacao de
//! teclas em vez de um Argon2id de 256 MiB.
//!
//! # Ate onde protege — e por que nao pode ser mais que isso
//!
//! Seja explicito: **em guarda nao e criptografia**. As chaves seguem vivas no
//! processo, entao quem tiver acesso tecnico a maquina (um depurador, um dump
//! de memoria, outro processo com privilegio) alcanca o cofre sem passar por
//! aqui. O que este modo barra e a pessoa que senta na sua cadeira.
//!
//! Isso nao e uma limitacao que da para consertar: o caminho seguro seria
//! descartar as chaves — e aí sair do modo exigiria **derivar a chave de
//! novo**, o que a combinacao de teclas nao consegue fazer. Uma sequencia de
//! seis teclas tem cerca de 2 bilhoes de possibilidades; o Argon2id existe
//! justamente porque isso cai em segundos num ataque offline. Derivar a chave
//! do cofre a partir dela seria trocar a senha mestra por um PIN e chamar de
//! seguranca.
//!
//! Por isso o modo tem prazo: passado [`GUARD_TO_LOCK_SECS`] sem ninguem
//! voltar, ele vira bloqueio de verdade e as chaves somem. A pausa curta e
//! conveniencia; a pausa longa vira a coisa segura sozinha.

use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

/// Quanto tempo em guarda antes de virar bloqueio de verdade.
pub const GUARD_TO_LOCK_SECS: u64 = 180;

/// Tentativas erradas da combinacao antes de trancar de vez.
///
/// Baixo de proposito: a combinacao e curta, e quem esta chutando nao e o
/// dono. Trancar devolve o problema para o Argon2id, que e onde ele deve
/// morar.
pub const MAX_PATTERN_ATTEMPTS: u32 = 5;

pub const MIN_PATTERN_LEN: usize = 3;
pub const MAX_PATTERN_LEN: usize = 16;

/// Dominio de derivacao do resumo da combinacao.
const PATTERN_DOMAIN: &str = "passec.guard.pattern.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardState {
    /// Cofre aberto e utilizavel.
    Open,
    /// Interface trancada, chaves ainda vivas.
    OnGuard,
}

/// Estado do modo em guarda dentro da sessao.
pub struct Guard {
    state: GuardState,
    since: Option<Instant>,
    attempts: u32,
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            state: GuardState::Open,
            since: None,
            attempts: 0,
        }
    }
}

impl Guard {
    pub fn state(&self) -> GuardState {
        self.state
    }

    pub fn is_on_guard(&self) -> bool {
        self.state == GuardState::OnGuard
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn enter(&mut self) {
        self.state = GuardState::OnGuard;
        self.since = Some(Instant::now());
        self.attempts = 0;
    }

    pub fn leave(&mut self) {
        self.state = GuardState::Open;
        self.since = None;
        self.attempts = 0;
    }

    /// Segundos restantes ate o modo virar bloqueio de verdade.
    pub fn seconds_until_lock(&self) -> Option<u64> {
        let since = self.since?;
        Some(
            Duration::from_secs(GUARD_TO_LOCK_SECS)
                .saturating_sub(since.elapsed())
                .as_secs(),
        )
    }

    pub fn expired(&self) -> bool {
        match self.since {
            Some(t) => t.elapsed() >= Duration::from_secs(GUARD_TO_LOCK_SECS),
            None => false,
        }
    }

    /// Registra um erro. Devolve `true` quando o limite estourou e a sessao
    /// deve ser trancada de verdade.
    pub fn record_failure(&mut self) -> bool {
        self.attempts += 1;
        self.attempts >= MAX_PATTERN_ATTEMPTS
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("a combinacao precisa ter entre {MIN_PATTERN_LEN} e {MAX_PATTERN_LEN} teclas")]
    BadLength,
    #[error("nenhuma combinacao foi definida para este cofre")]
    NotSet,
}

/// Resumo da combinacao, guardado dentro do cofre cifrado.
///
/// O resumo e derivado da VaultKey, nao de um hash puro: assim ele so faz
/// sentido dentro deste cofre, e copiar o campo para outro arquivo nao leva a
/// nada. Nao usamos Argon2id aqui de proposito — ele protegeria contra quem le
/// o cofre, e quem le o cofre ja tem todas as senhas. Gastar um segundo por
/// tentativa so tornaria a pausa curta irritante.
pub fn digest(vault_key: &[u8; 32], pattern: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PATTERN_DOMAIN);
    hasher.update(vault_key);
    hasher.update(pattern.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn validate_len(pattern: &str) -> Result<(), PatternError> {
    let n = pattern.chars().count();
    if (MIN_PATTERN_LEN..=MAX_PATTERN_LEN).contains(&n) {
        Ok(())
    } else {
        Err(PatternError::BadLength)
    }
}

/// Confere a combinacao em tempo constante.
///
/// Comparar com `==` sairia no primeiro byte diferente e vazaria, pelo tempo,
/// quantas teclas iniciais estavam certas — o que transformaria a busca de
/// exponencial em linear.
pub fn verify(vault_key: &[u8; 32], stored: &[u8; 32], attempt: &str) -> bool {
    digest(vault_key, attempt).ct_eq(stored).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn comeca_aberto() {
        let g = Guard::default();
        assert_eq!(g.state(), GuardState::Open);
        assert!(!g.is_on_guard());
        assert!(g.seconds_until_lock().is_none());
        assert!(!g.expired());
    }

    #[test]
    fn entra_e_sai() {
        let mut g = Guard::default();
        g.enter();
        assert!(g.is_on_guard());
        assert!(g.seconds_until_lock().unwrap() <= GUARD_TO_LOCK_SECS);

        g.leave();
        assert_eq!(g.state(), GuardState::Open);
        assert_eq!(g.attempts(), 0);
    }

    #[test]
    fn erros_acumulam_ate_o_limite() {
        let mut g = Guard::default();
        g.enter();
        for _ in 0..MAX_PATTERN_ATTEMPTS - 1 {
            assert!(!g.record_failure(), "trancou cedo demais");
        }
        assert!(g.record_failure(), "deveria trancar no limite");
    }

    /// Sair do modo zera o contador: um acerto legitimo nao pode deixar o
    /// usuario a uma tentativa de ser trancado na proxima pausa.
    #[test]
    fn sair_zera_as_tentativas() {
        let mut g = Guard::default();
        g.enter();
        g.record_failure();
        g.record_failure();
        g.leave();
        g.enter();
        assert_eq!(g.attempts(), 0);
    }

    #[test]
    fn combinacao_certa_confere() {
        let d = digest(&KEY, "asdf");
        assert!(verify(&KEY, &d, "asdf"));
        assert!(!verify(&KEY, &d, "asdg"));
        assert!(!verify(&KEY, &d, "asd"));
        assert!(!verify(&KEY, &d, ""));
    }

    /// O resumo e amarrado ao cofre: copiar o campo para outro arquivo nao
    /// deve destravar nada.
    #[test]
    fn resumo_depende_da_chave_do_cofre() {
        let d = digest(&KEY, "asdf");
        let outra = [9u8; 32];
        assert!(!verify(&outra, &d, "asdf"));
        assert_ne!(digest(&KEY, "asdf"), digest(&outra, "asdf"));
    }

    #[test]
    fn comprimento_e_validado() {
        assert!(validate_len("ab").is_err());
        assert!(validate_len("abc").is_ok());
        assert!(validate_len(&"a".repeat(MAX_PATTERN_LEN)).is_ok());
        assert!(validate_len(&"a".repeat(MAX_PATTERN_LEN + 1)).is_err());
    }

    /// A combinacao pode usar teclas nao-ASCII; o comprimento conta
    /// caracteres, nao bytes.
    #[test]
    fn conta_caracteres_e_nao_bytes() {
        assert!(validate_len("áéí").is_ok());
        let d = digest(&KEY, "áéí");
        assert!(verify(&KEY, &d, "áéí"));
    }
}
