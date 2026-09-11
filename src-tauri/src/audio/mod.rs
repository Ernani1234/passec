//! Transporte acustico: a ponte entre bytes cifrados e um arquivo WAV.
//!
//! A pilha tem tres camadas, sempre nesta ordem:
//!
//! ```text
//!   ciphertext  ──fec──►  blocos+CRC  ──modem──►  amostras  ──wav──►  arquivo
//! ```
//!
//! A ordem importa e nao e negociavel: **o audio nunca e a criptografia**.
//! Quem chama estas funcoes ja cifrou o conteudo; aqui so acontece mudanca de
//! formato. Se este WAV vazar, o atacante ganha ciphertext autenticado — o
//! mesmo que ganharia roubando o arquivo do cofre.

pub mod fec;
pub mod modem;
pub mod stego;
pub mod wav;

pub use fec::Robustness;

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("{0}")]
    Wav(String),
    #[error("correcao de erros: {0}")]
    Fec(String),
    #[error("modem: {0}")]
    Modem(String),
    #[error("esteganografia: {0}")]
    Stego(String),
}

/// Diagnostico de uma leitura, para a interface mostrar a margem que sobrou.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TransportReport {
    pub blocks_total: usize,
    pub blocks_corrupt: usize,
    pub blocks_recovered: usize,
    pub phase_error_deg: f32,
    /// `true` quando nenhum bloco precisou de reparo.
    pub pristine: bool,
}

/// Codifica bytes num WAV de 48 kHz: FEC, modulacao e serializacao.
pub fn to_wav(payload: &[u8], robustness: Robustness) -> Result<Vec<u8>, AudioError> {
    let framed = fec::encode(payload, robustness)?;
    let samples = modem::modulate(&framed)?;
    wav::encode(&samples)
}

/// Le um WAV e devolve os bytes originais.
pub fn from_wav(wav_bytes: &[u8]) -> Result<(Vec<u8>, TransportReport), AudioError> {
    let pcm = wav::decode(wav_bytes)?;
    let (framed, stats) = modem::demodulate(&pcm.samples, pcm.sample_rate)?;
    let decoded = fec::decode(&framed)?;

    Ok((
        decoded.payload,
        TransportReport {
            blocks_total: decoded.blocks_total,
            blocks_corrupt: decoded.blocks_corrupt,
            blocks_recovered: decoded.blocks_recovered,
            phase_error_deg: stats.phase_error_deg,
            pristine: decoded.blocks_corrupt == 0,
        },
    ))
}

/// Segundos de audio que `n_bytes` vao ocupar, ja contando a paridade.
pub fn estimate_duration_secs(n_bytes: usize, robustness: Robustness) -> f32 {
    let overhead = match robustness {
        Robustness::Digital => 1.15,
        Robustness::Airborne => 1.45,
    };
    modem::estimate_duration_secs((n_bytes as f32 * overhead) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciclo_completo_pela_pilha() {
        let segredo: Vec<u8> = (0..3000).map(|i| (i * 17 % 256) as u8).collect();
        let arquivo = to_wav(&segredo, Robustness::Digital).unwrap();

        // Tem que sair um WAV de verdade, reconhecivel por qualquer player.
        assert_eq!(&arquivo[0..4], b"RIFF");
        assert_eq!(&arquivo[8..12], b"WAVE");

        let (recuperado, report) = from_wav(&arquivo).unwrap();
        assert_eq!(recuperado, segredo);
        assert!(report.pristine);
        assert_eq!(report.blocks_corrupt, 0);
    }

    #[test]
    fn ciclo_sobrevive_a_corte_no_meio_do_audio() {
        let segredo: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
        let arquivo = to_wav(&segredo, Robustness::Airborne).unwrap();

        let mut pcm = wav::decode(&arquivo).unwrap();
        // Silencia 40 ms no meio: um clique de gravacao, um buffer perdido.
        let meio = pcm.samples.len() / 2;
        for s in pcm.samples[meio..meio + 1920].iter_mut() {
            *s = 0;
        }
        let danificado = wav::encode(&pcm.samples).unwrap();

        let (recuperado, report) = from_wav(&danificado).unwrap();
        assert_eq!(recuperado, segredo);
        assert!(!report.pristine, "o dano deveria ter sido registrado");
    }


    /// O contrato que importa para o usuario: sob ruido, a fita volta intacta
    /// ou falha alto — nunca devolve um cofre silenciosamente corrompido.
    #[test]
    fn pilha_completa_sobrevive_a_ruido() {
        let segredo: Vec<u8> = (0..4000).map(|i| (i * 29 % 256) as u8).collect();
        let arquivo = to_wav(&segredo, Robustness::Airborne).unwrap();

        let mut pcm = wav::decode(&arquivo).unwrap();
        let mut seed = 0x9E3779B9_7F4A7C15u64;
        for s in pcm.samples.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let n = ((seed >> 40) as i32 % 2048) - 1024;
            *s = (*s as i32 + n).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        }
        let ruidoso = wav::encode(&pcm.samples).unwrap();

        let (recuperado, _) = from_wav(&ruidoso).unwrap();
        assert_eq!(recuperado, segredo);
    }

    /// Ruido alem do que a paridade cobre precisa virar erro, nunca dados
    /// errados passados adiante como se fossem bons.
    #[test]
    fn ruido_excessivo_falha_em_vez_de_corromper() {
        let segredo: Vec<u8> = (0..4000).map(|i| (i * 29 % 256) as u8).collect();
        let arquivo = to_wav(&segredo, Robustness::Digital).unwrap();

        let mut pcm = wav::decode(&arquivo).unwrap();
        let mut seed = 0x2545F491_4F6CDD1Du64;
        for s in pcm.samples.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            // Ruido brutal: bem alem do orcamento de paridade.
            let n = ((seed >> 40) as i32 % 24000) - 12000;
            *s = (*s as i32 + n).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        }
        let destruido = wav::encode(&pcm.samples).unwrap();

        match from_wav(&destruido) {
            Err(_) => {}
            Ok((recuperado, _)) => assert_eq!(
                recuperado, segredo,
                "devolveu dados diferentes do original sem sinalizar erro"
            ),
        }
    }

    #[test]
    fn audio_qualquer_nao_vira_cofre() {
        let musica: Vec<i16> = (0..48_000)
            .map(|i| ((i as f32 * 0.05).sin() * 9000.0) as i16)
            .collect();
        let arquivo = wav::encode(&musica).unwrap();
        assert!(from_wav(&arquivo).is_err());
    }

    #[test]
    fn airborne_gera_audio_mais_longo_que_digital() {
        let n = 5000;
        assert!(
            estimate_duration_secs(n, Robustness::Airborne)
                > estimate_duration_secs(n, Robustness::Digital)
        );
    }
}
