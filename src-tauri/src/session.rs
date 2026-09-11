//! Estado vivo da aplicacao: o cofre destrancado, o relogio de inatividade e o
//! freio contra tentativas repetidas.
//!
//! O cofre aberto existe **so aqui**, atras de um `Mutex`, e some da RAM
//! assim que e trancado — `UnlockedVault` carrega chaves que se apagam no
//! drop. A interface nunca recebe a VaultKey nem a senha; recebe apenas os
//! campos que pediu, item a item.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::guard::{Guard, GuardState};
use crate::vault::UnlockedVault;

/// Inatividade tolerada antes do cofre trancar sozinho.
pub const DEFAULT_AUTOLOCK_SECS: u64 = 300;
pub const MIN_AUTOLOCK_SECS: u64 = 30;
pub const MAX_AUTOLOCK_SECS: u64 = 3600;

/// Tentativas livres antes do atraso comecar a crescer.
const FREE_ATTEMPTS: u32 = 3;
/// Teto do atraso, para que o freio nunca vire um bloqueio permanente do
/// proprio dono.
const MAX_PENALTY: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("o cofre esta trancado")]
    Locked,

    #[error("o cofre esta em guarda")]
    OnGuard,
    #[error("aguarde {0} segundos antes de tentar de novo")]
    Throttled(u64),
    #[error("nenhum cofre foi aberto nesta sessao")]
    NoVaultPath,

    #[error("nenhuma combinacao de teclas foi definida; use a senha mestra")]
    NoPattern,
}

/// Conteudo protegido pelo mutex.
struct Inner {
    vault: Option<UnlockedVault>,
    path: Option<PathBuf>,
    last_activity: Instant,
    autolock: Duration,
    /// Passo TOTP ja consumido, para recusar reuso do mesmo codigo.
    last_totp_step: Option<u64>,
    failed_attempts: u32,
    /// Instante antes do qual novas tentativas sao recusadas.
    penalty_until: Option<Instant>,
    /// Estado do modo em guarda (interface trancada, chaves vivas).
    guard: Guard,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            vault: None,
            path: None,
            last_activity: Instant::now(),
            autolock: Duration::from_secs(DEFAULT_AUTOLOCK_SECS),
            last_totp_step: None,
            failed_attempts: 0,
            penalty_until: None,
            guard: Guard::default(),
        }
    }
}

#[derive(Default)]
pub struct AppState {
    inner: Mutex<Inner>,
}

impl AppState {
    /// Um mutex envenenado significa que outra thread entrou em panico
    /// segurando o cofre. Preferimos seguir com o estado recuperado a derrubar
    /// o aplicativo e perder alteracoes nao salvas.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    // --- freio contra forca bruta -----------------------------------------

    /// Verifica se ainda ha penalidade pendente.
    ///
    /// O atraso cresce exponencialmente a partir da quarta falha: 1 s, 2 s,
    /// 4 s... ate 5 minutos. Isso nao impede um ataque offline (quem tem o
    /// arquivo ignora este processo), mas torna tedioso tentar senhas na
    /// interface de uma maquina destravada.
    pub fn check_throttle(&self) -> Result<(), SessionError> {
        let inner = self.lock_inner();
        if let Some(until) = inner.penalty_until {
            let agora = Instant::now();
            if until > agora {
                return Err(SessionError::Throttled(
                    (until - agora).as_secs().max(1),
                ));
            }
        }
        Ok(())
    }

    pub fn record_failure(&self) {
        let mut inner = self.lock_inner();
        inner.failed_attempts += 1;
        if inner.failed_attempts > FREE_ATTEMPTS {
            let exceso = inner.failed_attempts - FREE_ATTEMPTS;
            // `saturating_sub` e o teto evitam estouro quando o expoente cresce.
            let secs = 1u64.checked_shl(exceso.saturating_sub(1)).unwrap_or(u64::MAX);
            let penalty = Duration::from_secs(secs).min(MAX_PENALTY);
            inner.penalty_until = Some(Instant::now() + penalty);
        }
    }

    pub fn record_success(&self) {
        let mut inner = self.lock_inner();
        inner.failed_attempts = 0;
        inner.penalty_until = None;
    }

    pub fn failed_attempts(&self) -> u32 {
        self.lock_inner().failed_attempts
    }

    // --- ciclo do cofre ----------------------------------------------------

    pub fn set_vault(&self, vault: UnlockedVault, path: PathBuf) {
        let mut inner = self.lock_inner();
        inner.vault = Some(vault);
        inner.path = Some(path);
        inner.last_activity = Instant::now();
        inner.last_totp_step = None;
    }

    /// Tranca o cofre, largando as chaves. Devolve `true` se algo foi trancado.
    pub fn lock(&self) -> bool {
        let mut inner = self.lock_inner();
        inner.last_totp_step = None;
        inner.guard.leave();
        // O `drop` de UnlockedVault zera KEK e VaultKey.
        inner.vault.take().is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_inner().vault.is_some()
    }

    pub fn vault_path(&self) -> Option<PathBuf> {
        self.lock_inner().path.clone()
    }

    pub fn set_vault_path(&self, path: PathBuf) {
        self.lock_inner().path = Some(path);
    }

    /// Empresta o cofre destrancado para uma operacao, renovando o relogio de
    /// inatividade.
    pub fn with_vault<T, F>(&self, f: F) -> Result<T, SessionError>
    where
        F: FnOnce(&mut UnlockedVault) -> T,
    {
        let mut inner = self.lock_inner();
        // Expirou enquanto a interface estava parada: tranca agora, antes de
        // deixar qualquer leitura passar.
        if inner.vault.is_some() && inner.last_activity.elapsed() >= inner.autolock {
            inner.vault = None;
            inner.last_totp_step = None;
            return Err(SessionError::Locked);
        }
        // Em guarda, nenhuma leitura do cofre passa. Sem esta barreira o modo
        // seria so uma cortina visual: a interface continuaria podendo pedir
        // qualquer item pelo IPC.
        if inner.guard.is_on_guard() {
            return Err(SessionError::OnGuard);
        }

        let vault = inner.vault.as_mut().ok_or(SessionError::Locked)?;
        let out = f(vault);
        inner.last_activity = Instant::now();
        Ok(out)
    }

    /// Empresta o cofre **sem** verificar o modo em guarda.
    ///
    /// Existe para um unico proposito: conferir a combinacao de teclas, que
    /// precisa da VaultKey justamente enquanto o modo esta ativo. Nao use para
    /// mais nada — e o furo que o modo existe para tapar.
    fn with_vault_bypassing_guard<T, F>(&self, f: F) -> Result<T, SessionError>
    where
        F: FnOnce(&mut UnlockedVault) -> T,
    {
        let mut inner = self.lock_inner();
        let vault = inner.vault.as_mut().ok_or(SessionError::Locked)?;
        Ok(f(vault))
    }

    // --- modo em guarda ----------------------------------------------------

    pub fn guard_state(&self) -> GuardState {
        self.lock_inner().guard.state()
    }

    pub fn guard_seconds_until_lock(&self) -> Option<u64> {
        self.lock_inner().guard.seconds_until_lock()
    }

    pub fn guard_attempts(&self) -> u32 {
        self.lock_inner().guard.attempts()
    }

    /// Ha combinacao configurada neste cofre.
    ///
    /// Consultado em guarda — e justamente nesse estado que a interface precisa
    /// saber se deve pedir a combinacao ou mandar direto para a senha mestra.
    /// Devolve apenas um booleano; o resumo em si nao sai daqui.
    pub fn has_guard_pattern(&self) -> bool {
        self.with_vault_bypassing_guard(|v| v.body.guard_pattern.is_some())
            .unwrap_or(false)
    }

    /// Entra em guarda. Devolve `false` se nao havia cofre aberto.
    pub fn enter_guard(&self) -> bool {
        let mut inner = self.lock_inner();
        if inner.vault.is_none() {
            return false;
        }
        inner.guard.enter();
        true
    }

    /// Confere a combinacao e sai do modo em caso de acerto.
    ///
    /// Erra demais e a sessao e trancada de verdade: a combinacao e curta, e
    /// devolver o problema para o Argon2id e a resposta certa a quem esta
    /// chutando.
    pub fn try_leave_guard(&self, attempt: &str) -> Result<bool, SessionError> {
        let armazenado = self.with_vault_bypassing_guard(|v| {
            v.body
                .guard_pattern
                .as_ref()
                .and_then(|hex| crate::util::from_hex(hex))
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .map(|d| (d, *v.vault_key_copy().expose()))
        })?;

        let Some((digest, chave)) = armazenado else {
            return Err(SessionError::NoPattern);
        };

        if crate::guard::verify(&chave, &digest, attempt) {
            let mut inner = self.lock_inner();
            inner.guard.leave();
            inner.last_activity = Instant::now();
            return Ok(true);
        }

        let estourou = {
            let mut inner = self.lock_inner();
            inner.guard.record_failure()
        };
        if estourou {
            self.lock();
        }
        Ok(false)
    }

    // --- inatividade -------------------------------------------------------

    /// Renova o relogio de inatividade.
    ///
    /// Em guarda a renovacao e ignorada: se o mouse for esbarrado na mesa, ou
    /// se alguem mexer na maquina, isso nao pode adiar o bloqueio de verdade.
    pub fn touch(&self) {
        let mut inner = self.lock_inner();
        if !inner.guard.is_on_guard() {
            inner.last_activity = Instant::now();
        }
    }

    pub fn autolock_secs(&self) -> u64 {
        self.lock_inner().autolock.as_secs()
    }

    pub fn set_autolock_secs(&self, secs: u64) {
        let secs = secs.clamp(MIN_AUTOLOCK_SECS, MAX_AUTOLOCK_SECS);
        self.lock_inner().autolock = Duration::from_secs(secs);
    }

    /// Segundos restantes ate o auto-lock, para a contagem na interface.
    pub fn seconds_until_lock(&self) -> Option<u64> {
        let inner = self.lock_inner();
        inner.vault.as_ref()?;
        Some(
            inner
                .autolock
                .saturating_sub(inner.last_activity.elapsed())
                .as_secs(),
        )
    }

    /// Tranca se a inatividade estourou. Chamado pelo vigia de fundo.
    pub fn lock_if_expired(&self) -> bool {
        let mut inner = self.lock_inner();
        if inner.vault.is_none() {
            return false;
        }

        // Duas contagens correm em paralelo: a inatividade normal e o prazo do
        // modo em guarda, que e mais curto. A primeira que vencer tranca.
        let inativo = inner.last_activity.elapsed() >= inner.autolock;
        let guarda_expirou = inner.guard.expired();

        if inativo || guarda_expirou {
            inner.vault = None;
            inner.last_totp_step = None;
            inner.guard.leave();
            return true;
        }
        false
    }

    // --- TOTP --------------------------------------------------------------

    /// Marca um passo TOTP como gasto; devolve `false` se ja tinha sido usado.
    ///
    /// Sem isso, um codigo visto por cima do ombro continuaria valido pelo
    /// resto da janela de 30 segundos.
    pub fn consume_totp_step(&self, step: u64) -> bool {
        let mut inner = self.lock_inner();
        if inner.last_totp_step == Some(step) {
            return false;
        }
        inner.last_totp_step = Some(step);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    /// Cria um cofre barato para os testes que precisam de sessao aberta.
    fn cofre_de_teste() -> UnlockedVault {
        use crate::crypto::kdf::{KdfParams, UnlockFactors};
        use crate::crypto::keyfile::KeyfileMode;
        UnlockedVault::create(
            &UnlockFactors {
                password: "uma-senha-mestra-bem-comprida",
                keyfile_digest: None,
            },
            KeyfileMode::None,
            KdfParams {
                memory_kib: 16 * 1024,
                iterations: 2,
                parallelism: 1,
            },
        )
        .unwrap()
    }

    fn sessao_aberta() -> AppState {
        let s = AppState::default();
        s.set_vault(cofre_de_teste(), PathBuf::from("teste.vault"));
        s
    }

    /// A garantia central do modo: em guarda, nada le o cofre pelo IPC.
    ///
    /// Sem esta barreira o modo seria apenas uma cortina visual — a interface
    /// continuaria podendo pedir qualquer senha.
    #[test]
    fn em_guarda_nenhuma_leitura_passa() {
        let s = sessao_aberta();
        assert!(s.with_vault(|_| ()).is_ok());

        assert!(s.enter_guard());
        assert!(matches!(s.with_vault(|_| ()), Err(SessionError::OnGuard)));

        // E o cofre continua aberto: em guarda nao e trancar.
        assert!(s.is_unlocked());
    }

    #[test]
    fn combinacao_certa_devolve_o_acesso() {
        let s = sessao_aberta();
        s.with_vault(|v| {
            let chave = *v.vault_key_copy().expose();
            let d = crate::guard::digest(&chave, "asdf");
            v.body.guard_pattern = Some(crate::util::to_hex(&d));
        })
        .unwrap();

        s.enter_guard();
        assert!(!s.try_leave_guard("errada").unwrap());
        assert!(s.with_vault(|_| ()).is_err(), "errar nao pode liberar");

        assert!(s.try_leave_guard("asdf").unwrap());
        assert!(s.with_vault(|_| ()).is_ok());
    }

    /// Chutar demais devolve o problema para o Argon2id.
    #[test]
    fn erros_demais_trancam_de_verdade() {
        let s = sessao_aberta();
        s.with_vault(|v| {
            let chave = *v.vault_key_copy().expose();
            let d = crate::guard::digest(&chave, "asdf");
            v.body.guard_pattern = Some(crate::util::to_hex(&d));
        })
        .unwrap();

        s.enter_guard();
        for _ in 0..crate::guard::MAX_PATTERN_ATTEMPTS {
            let _ = s.try_leave_guard("nao-e-essa");
        }

        assert!(!s.is_unlocked(), "deveria ter trancado de verdade");
        assert!(matches!(s.with_vault(|_| ()), Err(SessionError::Locked)));
    }

    #[test]
    fn sem_combinacao_o_erro_manda_usar_a_senha() {
        let s = sessao_aberta();
        s.enter_guard();
        assert!(matches!(
            s.try_leave_guard("qualquer"),
            Err(SessionError::NoPattern)
        ));
    }

    /// Mexer no mouse durante a pausa nao pode adiar o bloqueio de verdade.
    #[test]
    fn em_guarda_o_relogio_nao_e_renovado() {
        let s = sessao_aberta();
        s.enter_guard();
        let antes = s.seconds_until_lock();
        s.touch();
        s.touch();
        assert_eq!(s.seconds_until_lock(), antes);
    }

    #[test]
    fn trancar_limpa_o_modo_em_guarda() {
        let s = sessao_aberta();
        s.enter_guard();
        assert!(s.lock());
        assert_eq!(s.guard_state(), GuardState::Open);
    }

    #[test]
    fn nao_entra_em_guarda_sem_cofre_aberto() {
        let s = AppState::default();
        assert!(!s.enter_guard());
    }

    #[test]
    fn comeca_trancado() {
        let s = AppState::default();
        assert!(!s.is_unlocked());
        assert!(matches!(s.with_vault(|_| ()), Err(SessionError::Locked)));
        assert!(s.seconds_until_lock().is_none());
    }

    #[test]
    fn freio_so_aparece_depois_das_tentativas_livres() {
        let s = AppState::default();
        for _ in 0..FREE_ATTEMPTS {
            s.record_failure();
            assert!(s.check_throttle().is_ok());
        }
        s.record_failure();
        assert!(matches!(s.check_throttle(), Err(SessionError::Throttled(_))));
    }

    #[test]
    fn acerto_limpa_o_freio() {
        let s = AppState::default();
        for _ in 0..10 {
            s.record_failure();
        }
        assert!(s.check_throttle().is_err());
        s.record_success();
        assert!(s.check_throttle().is_ok());
        assert_eq!(s.failed_attempts(), 0);
    }

    /// Muitas falhas nao podem estourar o expoente nem travar para sempre.
    #[test]
    fn penalidade_tem_teto() {
        let s = AppState::default();
        for _ in 0..200 {
            s.record_failure();
        }
        match s.check_throttle() {
            Err(SessionError::Throttled(secs)) => {
                assert!(secs <= MAX_PENALTY.as_secs(), "penalidade de {secs}s");
            }
            other => panic!("esperava freio, veio {other:?}"),
        }
    }

    #[test]
    fn autolock_respeita_os_limites() {
        let s = AppState::default();
        s.set_autolock_secs(1);
        assert_eq!(s.autolock_secs(), MIN_AUTOLOCK_SECS);
        s.set_autolock_secs(99_999);
        assert_eq!(s.autolock_secs(), MAX_AUTOLOCK_SECS);
        s.set_autolock_secs(600);
        assert_eq!(s.autolock_secs(), 600);
    }

    #[test]
    fn codigo_totp_nao_pode_ser_reusado() {
        let s = AppState::default();
        assert!(s.consume_totp_step(42));
        assert!(!s.consume_totp_step(42));
        assert!(s.consume_totp_step(43));
    }

    #[test]
    fn trancar_sem_cofre_aberto_nao_mente() {
        let s = AppState::default();
        assert!(!s.lock());
    }
}
