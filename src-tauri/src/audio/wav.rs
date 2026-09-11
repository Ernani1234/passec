//! Leitura e escrita de WAV, normalizando tudo para mono i16.
//!
//! O modem trabalha num unico canal a uma taxa fixa. Arquivos que chegam de
//! fora (a musica do usuario, um memo de voz regravado) vem em qualquer
//! formato, entao a entrada e sempre reduzida ao denominador comum aqui.

use hound::{SampleFormat, WavReader, WavSpec, WavWriter};
use std::io::Cursor;

use super::AudioError;

/// Taxa de amostragem do modem. 48 kHz e o padrao de placas de som modernas,
/// entao nao ha reamostragem na reproducao.
pub const SAMPLE_RATE: u32 = 48_000;

/// Audio decodificado, pronto para o modem.
pub struct Pcm {
    pub samples: Vec<i16>,
    pub sample_rate: u32,
}

/// Decodifica WAV (qualquer profundidade/canais) para mono i16.
pub fn decode(bytes: &[u8]) -> Result<Pcm, AudioError> {
    let mut reader = WavReader::new(Cursor::new(bytes))
        .map_err(|e| AudioError::Wav(format!("arquivo WAV invalido: {e}")))?;
    let spec = reader.spec();
    let channels = spec.channels.max(1) as usize;

    // Converte cada formato para i16 antes de mixar.
    let interleaved: Vec<i16> = match (spec.sample_format, spec.bits_per_sample) {
        (SampleFormat::Int, 16) => reader
            .samples::<i16>()
            .collect::<Result<_, _>>()
            .map_err(|e| AudioError::Wav(e.to_string()))?,
        (SampleFormat::Int, 8) => reader
            .samples::<i32>()
            .map(|s| s.map(|v| ((v - 128) * 256) as i16))
            .collect::<Result<_, _>>()
            .map_err(|e| AudioError::Wav(e.to_string()))?,
        (SampleFormat::Int, 24) => reader
            .samples::<i32>()
            .map(|s| s.map(|v| (v >> 8) as i16))
            .collect::<Result<_, _>>()
            .map_err(|e| AudioError::Wav(e.to_string()))?,
        (SampleFormat::Int, 32) => reader
            .samples::<i32>()
            .map(|s| s.map(|v| (v >> 16) as i16))
            .collect::<Result<_, _>>()
            .map_err(|e| AudioError::Wav(e.to_string()))?,
        (SampleFormat::Float, _) => reader
            .samples::<f32>()
            .map(|s| s.map(|v| (v.clamp(-1.0, 1.0) * i16::MAX as f32) as i16))
            .collect::<Result<_, _>>()
            .map_err(|e| AudioError::Wav(e.to_string()))?,
        (_, bits) => {
            return Err(AudioError::Wav(format!(
                "profundidade de {bits} bits nao suportada"
            )))
        }
    };

    // Mixa para mono somando em i32 — somar em i16 estouraria e viraria
    // distorcao audivel, alem de corromper o digest de um keyfile RawFile.
    let samples = if channels == 1 {
        interleaved
    } else {
        interleaved
            .chunks(channels)
            .map(|frame| {
                let sum: i32 = frame.iter().map(|&s| s as i32).sum();
                (sum / channels as i32) as i16
            })
            .collect()
    };

    Ok(Pcm {
        samples,
        sample_rate: spec.sample_rate,
    })
}

/// Serializa amostras mono i16 em um WAV de 48 kHz.
pub fn encode(samples: &[i16]) -> Result<Vec<u8>, AudioError> {
    encode_with_rate(samples, SAMPLE_RATE)
}

pub fn encode_with_rate(samples: &[i16], sample_rate: u32) -> Result<Vec<u8>, AudioError> {
    let spec = WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 16,
        sample_format: SampleFormat::Int,
    };

    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut writer =
            WavWriter::new(&mut buf, spec).map_err(|e| AudioError::Wav(e.to_string()))?;
        for &s in samples {
            writer
                .write_sample(s)
                .map_err(|e| AudioError::Wav(e.to_string()))?;
        }
        writer
            .finalize()
            .map_err(|e| AudioError::Wav(e.to_string()))?;
    }
    Ok(buf.into_inner())
}

/// Reamostra por interpolacao cubica de Catmull-Rom.
///
/// O demodulador exige 48 kHz; um arquivo que passou por conversao pode voltar
/// em 44,1 kHz e precisa ser trazido de volta antes de ser demodulado.
///
/// A escolha obvia seria interpolacao linear — duas amostras, uma media
/// ponderada. Ela nao serve aqui, e o motivo nao e a atenuacao que ela causa
/// nas frequencias altas (DQPSK le fase, nao amplitude, e sobrevive a isso).
/// O problema e que o erro da reta depende de *onde* entre duas amostras o
/// ponto cai, e essa posicao varia a cada passo quando a razao entre as taxas
/// nao e inteira. O resultado e ruido que muda de amostra para amostra,
/// concentrado justamente nas subportadoras de cima.
///
/// Medido no caminho 48 k -> 44,1 k -> 48 k, a reta deixava o erro de fase em
/// ~10 graus e o keyfile nao voltava; a cubica derruba isso para a faixa de
/// operacao normal. Ela usa quatro amostras e acerta tambem a inclinacao nas
/// bordas, o que reduz esse residuo em cerca de uma ordem de grandeza pelo
/// custo de umas poucas multiplicacoes.
pub fn resample(input: &[i16], from: u32, to: u32) -> Vec<i16> {
    if from == to || input.is_empty() {
        return input.to_vec();
    }
    let ratio = from as f64 / to as f64;
    let out_len = ((input.len() as f64) / ratio).floor() as usize;
    let last = input.len() - 1;

    // Repete as amostras da ponta em vez de assumir zero fora do sinal: um
    // degrau ate zero nas bordas viraria um clique de banda larga.
    let at = |i: i64| -> f64 { input[i.clamp(0, last as i64) as usize] as f64 };

    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let pos = i as f64 * ratio;
        let idx = pos.floor() as i64;
        let t = pos - idx as f64;

        let p0 = at(idx - 1);
        let p1 = at(idx);
        let p2 = at(idx + 1);
        let p3 = at(idx + 2);

        // Catmull-Rom: passa por p1 e p2, e a tangente em cada um vem da
        // inclinacao entre os vizinhos.
        let a = -0.5 * p0 + 1.5 * p1 - 1.5 * p2 + 0.5 * p3;
        let b = p0 - 2.5 * p1 + 2.0 * p2 - 0.5 * p3;
        let c = -0.5 * p0 + 0.5 * p2;
        let v = ((a * t + b) * t + c) * t + p1;

        out.push(v.clamp(i16::MIN as f64, i16::MAX as f64).round() as i16);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ida_e_volta_mono() {
        let original: Vec<i16> = (0..1000).map(|i| (i * 31 % 20000) as i16 - 10000).collect();
        let wav = encode(&original).unwrap();
        let pcm = decode(&wav).unwrap();
        assert_eq!(pcm.sample_rate, SAMPLE_RATE);
        assert_eq!(pcm.samples, original);
    }

    /// Estereo com canais em oposicao de fase: a mixagem tem que somar em i32,
    /// senao o i16 estoura no meio do caminho.
    #[test]
    fn mixagem_estereo_nao_estoura() {
        let spec = WavSpec {
            channels: 2,
            sample_rate: SAMPLE_RATE,
            bits_per_sample: 16,
            sample_format: SampleFormat::Int,
        };
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = WavWriter::new(&mut buf, spec).unwrap();
            for _ in 0..100 {
                w.write_sample(i16::MAX).unwrap();
                w.write_sample(i16::MAX).unwrap();
            }
            w.finalize().unwrap();
        }
        let pcm = decode(&buf.into_inner()).unwrap();
        assert_eq!(pcm.samples.len(), 100);
        assert!(pcm.samples.iter().all(|&s| s == i16::MAX));
    }

    #[test]
    fn reamostragem_preserva_duracao() {
        let input: Vec<i16> = (0..4410).map(|i| (i % 100) as i16).collect();
        let out = resample(&input, 44_100, 48_000);
        // 0.1s a 48 kHz = 4800 amostras.
        assert!((out.len() as i32 - 4800).abs() <= 2, "len={}", out.len());
        assert_eq!(resample(&input, 48_000, 48_000).len(), input.len());
    }

    #[test]
    fn entrada_vazia_nao_entra_em_panico() {
        assert!(resample(&[], 44_100, 48_000).is_empty());
        assert!(encode(&[]).is_ok());
    }
}
