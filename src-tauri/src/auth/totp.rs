//! TOTP (RFC 6238) — segundo fator para destrancar o PASSEC.
//!
//! # Ate onde isto protege
//!
//! Seja honesto sobre o alcance: o TOTP e um portao *da aplicacao*, nao da
//! criptografia. Ele nao entra no KDF porque nao pode — um codigo de 6 digitos
//! tem 10^6 possibilidades, e um atacante que tivesse o arquivo do cofre
//! testaria todas em milissegundos, sem nem tocar no Argon2id.
//!
//! Na pratica isso significa: quem rouba o *arquivo* do cofre e sabe a senha
//! mestra abre o conteudo com qualquer implementacao, ignorando este modulo.
//! O que o TOTP barra e o acesso oportunista a uma sessao ja instalada — o
//! colega que senta na maquina e sabe a senha. Para um segundo fator que
//! realmente entra na chave, o mecanismo e o keyfile de audio.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

/// Janela de tempo padrao do RFC.
pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
/// Passos aceitos para cada lado do atual, cobrindo relogios dessincronizados.
const DRIFT_STEPS: i64 = 1;
/// 160 bits, o tamanho recomendado pelo RFC 4226 para HMAC-SHA1.
const SECRET_BYTES: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("segredo TOTP invalido (Base32 malformado)")]
    BadSecret,
    #[error("falha ao gerar QR code: {0}")]
    Qr(String),
    #[error("falha ao obter entropia")]
    Rng,
}

fn alphabet() -> base32::Alphabet {
    base32::Alphabet::Rfc4648 { padding: false }
}

/// Sorteia um segredo novo em Base32, pronto para o app autenticador.
pub fn generate_secret() -> Result<String, TotpError> {
    let bytes = crate::crypto::random_array::<SECRET_BYTES>().map_err(|_| TotpError::Rng)?;
    Ok(base32::encode(alphabet(), &bytes))
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, TotpError> {
    // Autenticadores costumam exibir o segredo em grupos separados por espaco,
    // e o usuario cola exatamente como viu.
    let limpo: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    let bytes = base32::decode(alphabet(), &limpo).ok_or(TotpError::BadSecret)?;
    if bytes.is_empty() {
        return Err(TotpError::BadSecret);
    }
    Ok(bytes)
}

/// Calcula o codigo de um passo especifico.
fn code_for_step(secret: &[u8], step: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC aceita chave de qualquer tamanho");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Truncamento dinamico do RFC 4226: os 4 bits finais escolhem de onde
    // extrair os 31 bits que viram o codigo.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    let modulo = 10u32.pow(DIGITS);
    format!("{:0width$}", binary % modulo, width = DIGITS as usize)
}

/// Codigo corrente para um dado instante.
pub fn code_at(secret: &str, unix_secs: u64) -> Result<String, TotpError> {
    let bytes = decode_secret(secret)?;
    Ok(code_for_step(&bytes, unix_secs / STEP_SECS))
}

/// Segundos restantes ate o codigo mudar — a interface usa para a barra de
/// progresso.
pub fn seconds_remaining(unix_secs: u64) -> u64 {
    STEP_SECS - (unix_secs % STEP_SECS)
}

/// Confere um codigo digitado, aceitando um passo de folga para cada lado.
///
/// Devolve o passo que casou, para o chamador registrar e recusar reuso: sem
/// isso, um codigo espiado continua valido pelos 30 segundos seguintes.
pub fn verify(secret: &str, code: &str, unix_secs: u64) -> Result<Option<u64>, TotpError> {
    let bytes = decode_secret(secret)?;
    let digitado: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if digitado.len() != DIGITS as usize {
        return Ok(None);
    }

    let current = (unix_secs / STEP_SECS) as i64;
    for delta in -DRIFT_STEPS..=DRIFT_STEPS {
        let step = (current + delta).max(0) as u64;
        let esperado = code_for_step(&bytes, step);
        // Comparacao em tempo constante: comparar strings com `==` sai mais
        // cedo no primeiro digito diferente e vaza, pelo tempo, quantos
        // digitos iniciais estavam certos.
        if esperado.as_bytes().ct_eq(digitado.as_bytes()).into() {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

/// Monta a URI `otpauth://` que o app autenticador le no QR.
pub fn provisioning_uri(secret: &str, account: &str) -> String {
    let enc = |s: &str| {
        s.chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                ' ' => "%20".to_string(),
                other => other
                    .to_string()
                    .bytes()
                    .map(|b| format!("%{b:02X}"))
                    .collect(),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/PASSEC:{}?secret={}&issuer=PASSEC&algorithm=SHA1&digits={}&period={}",
        enc(account),
        secret,
        DIGITS,
        STEP_SECS
    )
}

/// Renderiza a URI como SVG, para a interface exibir sem depender de
/// biblioteca de QR no frontend.
pub fn qr_svg(uri: &str) -> Result<String, TotpError> {
    use qrcode::render::svg;
    use qrcode::QrCode;

    let code = QrCode::new(uri.as_bytes()).map_err(|e| TotpError::Qr(e.to_string()))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#0b1a0e"))
        .light_color(svg::Color("#8dff6a"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vetor de teste do RFC 6238 (apendice B), com o segredo ASCII
    /// "12345678901234567890" em Base32.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn bate_com_os_vetores_do_rfc_6238() {
        // (instante, codigo esperado) — SHA1, 6 digitos, passo de 30 s.
        for (t, esperado) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(code_at(RFC_SECRET, t).unwrap(), esperado, "instante {t}");
        }
    }

    #[test]
    fn aceita_o_codigo_do_momento() {
        let t = 1_700_000_000u64;
        let code = code_at(RFC_SECRET, t).unwrap();
        assert!(verify(RFC_SECRET, &code, t).unwrap().is_some());
    }

    #[test]
    fn tolera_relogio_atrasado_ou_adiantado() {
        let t = 1_700_000_000u64;
        let anterior = code_at(RFC_SECRET, t - STEP_SECS).unwrap();
        let seguinte = code_at(RFC_SECRET, t + STEP_SECS).unwrap();
        assert!(verify(RFC_SECRET, &anterior, t).unwrap().is_some());
        assert!(verify(RFC_SECRET, &seguinte, t).unwrap().is_some());

        // Mas dois passos fora ja e recusado.
        let longe = code_at(RFC_SECRET, t + 3 * STEP_SECS).unwrap();
        assert!(verify(RFC_SECRET, &longe, t).unwrap().is_none());
    }

    #[test]
    fn devolve_o_passo_para_bloquear_reuso() {
        let t = 1_700_000_000u64;
        let code = code_at(RFC_SECRET, t).unwrap();
        assert_eq!(verify(RFC_SECRET, &code, t).unwrap(), Some(t / STEP_SECS));
    }

    #[test]
    fn recusa_codigo_errado_ou_malformado() {
        let t = 1_700_000_000u64;
        assert!(verify(RFC_SECRET, "000000", t).unwrap().is_none());
        assert!(verify(RFC_SECRET, "12345", t).unwrap().is_none());
        assert!(verify(RFC_SECRET, "", t).unwrap().is_none());
        assert!(verify(RFC_SECRET, "abcdef", t).unwrap().is_none());
    }

    /// Autenticadores mostram o segredo em grupos; colar com espacos tem que
    /// funcionar.
    #[test]
    fn normaliza_segredo_colado_com_espacos() {
        let espacado = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(
            code_at(espacado, 59).unwrap(),
            code_at(RFC_SECRET, 59).unwrap()
        );
    }

    #[test]
    fn segredo_invalido_e_reportado() {
        assert!(matches!(
            code_at("!!!nao-e-base32!!!", 0),
            Err(TotpError::BadSecret)
        ));
        assert!(matches!(code_at("", 0), Err(TotpError::BadSecret)));
    }

    #[test]
    fn segredos_gerados_sao_utilizaveis_e_unicos() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        assert_ne!(a, b);
        assert_eq!(code_at(&a, 0).unwrap().len(), 6);
    }

    #[test]
    fn contagem_regressiva_cobre_a_janela() {
        assert_eq!(seconds_remaining(0), 30);
        assert_eq!(seconds_remaining(29), 1);
        assert_eq!(seconds_remaining(30), 30);
    }

    #[test]
    fn uri_e_qr_sao_gerados() {
        let uri = provisioning_uri(RFC_SECRET, "cofre local");
        assert!(uri.starts_with("otpauth://totp/PASSEC:"));
        assert!(uri.contains("cofre%20local"));
        assert!(uri.contains("period=30"));

        let svg = qr_svg(&uri).unwrap();
        assert!(svg.contains("<svg"));
    }
}
