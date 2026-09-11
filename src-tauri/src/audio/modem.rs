//! Modem OFDM/DQPSK — converte bytes em som e som em bytes.
//!
//! # Por que OFDM
//!
//! Uma portadora unica com sinalizacao serial (FSK tipo modem discado) daria
//! algumas centenas de bits por segundo: exportar um cofre de 60 KB levaria
//! horas de chiado. OFDM divide a banda audivel em 373 subportadoras
//! independentes que transmitem em paralelo, o que rende ~31 kbit/s e faz o
//! mesmo cofre caber em ~18 segundos.
//!
//! O prefixo ciclico ([`CP_LEN`] amostras copiadas do fim do simbolo para a
//! frente dele) absorve o eco: se o som bate na parede e volta atrasado, o
//! atraso cai dentro do prefixo e nao contamina o simbolo seguinte. Sao 2,7 ms
//! de tolerancia, o suficiente para a reverberacao de uma sala comum.
//!
//! # Por que DQPSK e nao QPSK
//!
//! QPSK coerente exige saber a fase absoluta do canal, o que obrigaria a
//! estimar e rastrear a resposta do canal — e a fase absoluta muda com a
//! distancia ao microfone, com o atraso da placa de som, com tudo. DQPSK
//! codifica cada par de bits na *diferenca* de fase entre simbolos
//! consecutivos da mesma subportadora. O canal, desde que estavel pelos 24 ms
//! entre dois simbolos, se cancela sozinho na subtracao. Custa ~3 dB de SNR e
//! economiza o rastreador de canal inteiro.

use rustfft::{num_complex::Complex32, FftPlanner};
use std::f32::consts::PI;

use super::AudioError;
use super::wav::SAMPLE_RATE;

/// Tamanho da FFT. 1024 a 48 kHz da subportadoras de 46,875 Hz.
const FFT_SIZE: usize = 1024;
/// Prefixo ciclico: 2,7 ms de tolerancia a eco.
const CP_LEN: usize = 128;
const SYMBOL_LEN: usize = FFT_SIZE + CP_LEN;

/// Primeira subportadora: bin 12 = 562 Hz. Abaixo disso mora o ronco de rede,
/// o ruido de mesa e o corte dos alto-falantes pequenos.
const FIRST_BIN: usize = 12;
/// Ultima subportadora: bin 384 = 18 kHz. Acima disso o MP3 corta e muitas
/// placas fazem roll-off do filtro anti-aliasing.
const LAST_BIN: usize = 384;
const N_CARRIERS: usize = LAST_BIN - FIRST_BIN + 1;
/// DQPSK carrega 2 bits por subportadora por simbolo.
const BITS_PER_SYMBOL: usize = N_CARRIERS * 2;

/// Varredura de sincronismo, 85 ms.
const CHIRP_LEN: usize = 4096;
const CHIRP_F0: f32 = 500.0;
const CHIRP_F1: f32 = 18_000.0;
/// Silencio entre o chirp e o primeiro simbolo: deixa a cauda da varredura
/// morrer antes dos dados comecarem.
///
/// 43 ms, generoso de proposito. Os 10 ms iniciais deixavam os primeiros
/// simbolos mensuravelmente piores que o resto do stream — o rastro do chirp
/// (e, num canal real, a reverberacao dele) ainda estava em cima deles. Como
/// isso custa 43 ms num arquivo de dezenas de segundos, nao ha razao para
/// economizar.
const GUARD_LEN: usize = 2048;
/// Silencio no inicio e no fim do arquivo.
const LEAD_SILENCE: usize = 2400;

/// Amplitude de pico do arquivo gerado.
const PEAK: f32 = 0.9;

/// Fator de crista usado para normalizar os dados: quantos desvios-padrao
/// cabem antes do corte.
///
/// OFDM soma 373 senoides de fase independente, e pelo teorema central do
/// limite a amplitude resultante e quase gaussiana — com picos raros, mas
/// enormes (PAPR medido de ~15 dB). Normalizar pelo **maximo absoluto**, que e
/// o reflexo obvio, deixa a potencia media 15 dB abaixo do que o arquivo
/// comporta, e joga fora justamente a margem de ruido do sistema.
///
/// Normalizamos pelo RMS vezes este fator e cortamos o que passar: acima de
/// 3 sigma mora ~0,3% das amostras, e distorcer essas poucas custa muito
/// menos em taxa de erro do que perder 15 dB em todas as outras.
///
/// O valor 3,0 saiu de medicao, nao de estimativa. Varrendo de 2,5 a 6,0
/// contra ruido branco, o 3,0 empatou com os fatores mais conservadores em
/// ruido baixo e ganhou deles com folga quando o ruido apertou (1935 contra
/// 1478 bytes corretos em 2000, no degrau mais severo): a potencia extra
/// vale mais que a intermodulacao que o corte introduz.
const CREST_FACTOR: f32 = 3.0;

/// Teto de amostras aceitas na demodulacao (~10 min de audio).
///
/// A sincronizacao faz uma FFT do sinal inteiro; sem esse limite, um WAV
/// gigante (hostil ou so errado) alocaria memoria sem limite.
const MAX_INPUT_SAMPLES: usize = SAMPLE_RATE as usize * 600;

/// Constelacao DQPSK com codificacao Gray: pontos vizinhos diferem em um unico
/// bit, entao o erro de fase mais provavel — escorregar para o quadrante ao
/// lado — custa 1 bit errado em vez de 2.
const GRAY_TO_QUADRANT: [usize; 4] = [0, 1, 3, 2];
const QUADRANT_TO_GRAY: [u8; 4] = [0b00, 0b01, 0b11, 0b10];

// --- conversao bits <-> bytes ---------------------------------------------

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks_exact(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | (b & 1)))
        .collect()
}

// --- preambulo -------------------------------------------------------------

/// Varredura linear de frequencia usada para achar o inicio do sinal.
///
/// Chirp em vez de um tom ou de uma sequencia pseudoaleatoria porque sua
/// autocorrelacao e um pico estreito e isolado: correlacionar o gravado contra
/// esta referencia aponta o inicio com precisao de amostra, mesmo com o sinal
/// enterrado em ruido.
fn chirp_reference() -> Vec<f32> {
    let n = CHIRP_LEN as f32;
    let fs = SAMPLE_RATE as f32;
    (0..CHIRP_LEN)
        .map(|i| {
            let t = i as f32 / fs;
            let duration = n / fs;
            // Fase de uma varredura linear: f(t) = f0 + (f1-f0)*t/T, e a fase
            // e a integral disso.
            let phase = 2.0 * PI * (CHIRP_F0 * t + (CHIRP_F1 - CHIRP_F0) * t * t / (2.0 * duration));
            // Hann suaviza as pontas: um degrau na amplitude viraria um clique
            // de banda larga que suja a propria correlacao.
            let window = 0.5 * (1.0 - (2.0 * PI * i as f32 / n).cos());
            phase.sin() * window
        })
        .collect()
}

/// Localiza o inicio do chirp por correlacao cruzada no dominio da frequencia.
///
/// Correlacao direta seria O(N*4096) — bilhoes de operacoes para um audio de
/// 30 s. Via FFT sai em O(N log N).
fn find_preamble(samples: &[f32]) -> Option<usize> {
    let reference = chirp_reference();
    let n = (samples.len() + reference.len()).next_power_of_two();

    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(n);
    let ifft = planner.plan_fft_inverse(n);

    let mut sig: Vec<Complex32> = samples
        .iter()
        .map(|&s| Complex32::new(s, 0.0))
        .chain(std::iter::repeat(Complex32::new(0.0, 0.0)))
        .take(n)
        .collect();
    let mut refr: Vec<Complex32> = reference
        .iter()
        .map(|&s| Complex32::new(s, 0.0))
        .chain(std::iter::repeat(Complex32::new(0.0, 0.0)))
        .take(n)
        .collect();

    fft.process(&mut sig);
    fft.process(&mut refr);

    // Correlacao = IFFT(FFT(sinal) * conj(FFT(referencia))).
    for (s, r) in sig.iter_mut().zip(refr.iter()) {
        *s *= r.conj();
    }
    ifft.process(&mut sig);

    // So faz sentido procurar onde ainda cabe o chirp inteiro.
    let limit = samples.len().saturating_sub(reference.len());
    if limit == 0 {
        return None;
    }

    let mut best = 0usize;
    let mut best_val = f32::MIN;
    let mut sum = 0.0f64;
    for (i, c) in sig.iter().take(limit).enumerate() {
        let v = c.re;
        sum += v.abs() as f64;
        if v > best_val {
            best_val = v;
            best = i;
        }
    }

    // Limiar relativo: o pico tem que se destacar bem da correlacao media,
    // senao estamos olhando para ruido e qualquer maximo local venceria.
    let mean = (sum / limit as f64) as f32;
    if mean > 0.0 && best_val > mean * 8.0 {
        Some(best)
    } else {
        None
    }
}

// --- modulacao -------------------------------------------------------------

/// Converte bytes em amostras de audio de 48 kHz.
pub fn modulate(data: &[u8]) -> Result<Vec<i16>, AudioError> {
    if data.is_empty() {
        return Err(AudioError::Modem("nada para modular".into()));
    }

    let bits = bytes_to_bits(data);
    let n_data_symbols = bits.len().div_ceil(BITS_PER_SYMBOL);

    let mut planner = FftPlanner::<f32>::new();
    let ifft = planner.plan_fft_inverse(FFT_SIZE);

    // Os simbolos de dados vao para um buffer proprio. O chirp e normalizado
    // separadamente logo abaixo: como ele e uma senoide pura, seu pico e quase
    // o seu RMS, e se entrasse na mesma normalizacao dos dados dominaria o
    // maximo e empurraria o OFDM para 15 dB abaixo do necessario.
    let mut data: Vec<f32> = Vec::with_capacity((n_data_symbols + 1) * SYMBOL_LEN);

    // Fase corrente de cada subportadora. O primeiro simbolo emitido e a
    // referencia (todas em fase zero); ele nao carrega bits, so estabelece o
    // ponto de partida contra o qual o simbolo seguinte sera comparado.
    let mut phases = vec![0.0f32; N_CARRIERS];
    emit_symbol(&ifft, &phases, &mut data);

    for s in 0..n_data_symbols {
        for (c, phase) in phases.iter_mut().enumerate() {
            let bit_idx = s * BITS_PER_SYMBOL + c * 2;
            // O ultimo simbolo pode nao estar cheio; o resto vai como 00, que
            // o FEC descarta por CRC.
            let b0 = bits.get(bit_idx).copied().unwrap_or(0);
            let b1 = bits.get(bit_idx + 1).copied().unwrap_or(0);
            let gray = ((b0 << 1) | b1) as usize;
            let quadrant = GRAY_TO_QUADRANT[gray];
            *phase += quadrant as f32 * (PI / 2.0);
        }
        emit_symbol(&ifft, &phases, &mut data);
    }

    // Normaliza os dados pelo RMS, cortando os picos raros (ver CREST_FACTOR).
    let rms = (data.iter().map(|s| s * s).sum::<f32>() / data.len().max(1) as f32).sqrt();
    let gain = if rms > 0.0 {
        PEAK / (CREST_FACTOR * rms)
    } else {
        0.0
    };
    for s in data.iter_mut() {
        *s = (*s * gain).clamp(-PEAK, PEAK);
    }

    let mut signal: Vec<f32> =
        Vec::with_capacity(LEAD_SILENCE * 2 + CHIRP_LEN + GUARD_LEN + data.len());
    signal.extend(std::iter::repeat(0.0).take(LEAD_SILENCE));
    // O chirp usa o pico direto: e banda estreita a cada instante, entao seu
    // fator de crista e baixo e ele nao ganha nada com o corte.
    signal.extend(chirp_reference().iter().map(|&s| s * PEAK));
    signal.extend(std::iter::repeat(0.0).take(GUARD_LEN));
    signal.extend_from_slice(&data);
    signal.extend(std::iter::repeat(0.0).take(LEAD_SILENCE));

    Ok(signal
        .iter()
        .map(|&s| (s * i16::MAX as f32).clamp(i16::MIN as f32, i16::MAX as f32) as i16)
        .collect())
}

/// Sintetiza um simbolo OFDM a partir das fases e anexa com prefixo ciclico.
fn emit_symbol(
    ifft: &std::sync::Arc<dyn rustfft::Fft<f32>>,
    phases: &[f32],
    out: &mut Vec<f32>,
) {
    let mut spectrum = vec![Complex32::new(0.0, 0.0); FFT_SIZE];
    for (c, &phase) in phases.iter().enumerate() {
        let bin = FIRST_BIN + c;
        let value = Complex32::from_polar(1.0, phase);
        spectrum[bin] = value;
        // Simetria hermitiana garante que a IFFT saia puramente real — sem
        // isso o sinal teria parte imaginaria e nao seria audio valido.
        spectrum[FFT_SIZE - bin] = value.conj();
    }

    ifft.process(&mut spectrum);

    let time: Vec<f32> = spectrum.iter().map(|c| c.re / FFT_SIZE as f32).collect();
    // Prefixo ciclico: a cauda do simbolo repetida na frente.
    out.extend_from_slice(&time[FFT_SIZE - CP_LEN..]);
    out.extend_from_slice(&time);
}

// --- demodulacao -----------------------------------------------------------

/// Mediana da distancia entre cada delta de fase e o ponto ideal mais proximo
/// da constelacao.
///
/// Mede o quanto o canal torceu a fase num trecho do espectro, sem precisar
/// saber quais bits foram transmitidos: seja qual for o simbolo, o erro e a
/// sobra em relacao ao multiplo de 90 graus mais proximo.
fn mediana_do_erro(deltas: &[f32]) -> f32 {
    if deltas.is_empty() {
        return 0.0;
    }
    let mut erros: Vec<f32> = deltas
        .iter()
        .map(|&d| {
            let q = (d / (PI / 2.0)).round();
            d - q * (PI / 2.0)
        })
        .collect();
    erros.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    erros[erros.len() / 2]
}

/// Qualidade do sinal recebido, para a UI avisar antes de o cofre ficar
/// irrecuperavel.
pub struct DemodStats {
    /// Quanto as fases recebidas desviaram dos pontos ideais da constelacao,
    /// em graus. Ate ~15 graus e folgado; acima de 30 o FEC comeca a trabalhar.
    pub phase_error_deg: f32,
    pub symbols: usize,
}

/// Converte audio de volta em bytes.
pub fn demodulate(samples: &[i16], sample_rate: u32) -> Result<(Vec<u8>, DemodStats), AudioError> {
    if samples.len() > MAX_INPUT_SAMPLES {
        return Err(AudioError::Modem(
            "audio longo demais para demodular (limite de 10 minutos)".into(),
        ));
    }

    // O demodulador so opera na taxa nominal; um arquivo que passou por
    // conversao pode voltar em 44,1 kHz.
    let resampled;
    let samples = if sample_rate != SAMPLE_RATE {
        resampled = super::wav::resample(samples, sample_rate, SAMPLE_RATE);
        &resampled[..]
    } else {
        samples
    };

    let float: Vec<f32> = samples.iter().map(|&s| s as f32 / i16::MAX as f32).collect();

    let chirp_start = find_preamble(&float)
        .ok_or_else(|| AudioError::Modem("preambulo nao encontrado — este audio nao carrega um sinal PASSEC".into()))?;

    let data_start = chirp_start + CHIRP_LEN + GUARD_LEN;
    if data_start + SYMBOL_LEN > float.len() {
        return Err(AudioError::Modem("sinal truncado apos o preambulo".into()));
    }

    let available = float.len() - data_start;
    let n_symbols = available / SYMBOL_LEN;
    if n_symbols < 2 {
        return Err(AudioError::Modem("sinal curto demais para conter dados".into()));
    }

    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(FFT_SIZE);

    let read_symbol = |index: usize| -> Vec<f32> {
        // A janela e posta no *meio* do prefixo ciclico, nao no fim dele.
        //
        // O prefixo e uma copia da cauda do simbolo, entao qualquer janela que
        // caia inteiramente dentro de [inicio_do_prefixo, fim_do_simbolo)
        // produz a mesma FFT a menos de uma rotacao de fase linear — e essa
        // rotacao a correcao guiada por decisao ja desfaz. Comecar exatamente
        // no fim do prefixo, que e o reflexo obvio, desperdica metade dessa
        // tolerancia: sobra margem para adiantamento e nenhuma para atraso.
        // Centrando, ficam ±64 amostras dos dois lados, que e o que absorve o
        // desvio acumulado quando o arquivo passou por reamostragem.
        let start = data_start + index * SYMBOL_LEN + CP_LEN / 2;
        let mut buf = vec![Complex32::new(0.0, 0.0); FFT_SIZE];
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = Complex32::new(float[start + i], 0.0);
        }
        fft.process(&mut buf);
        (FIRST_BIN..=LAST_BIN).map(|b| buf[b].arg()).collect()
    };

    let mut prev = read_symbol(0);
    let mut bits: Vec<u8> = Vec::with_capacity((n_symbols - 1) * BITS_PER_SYMBOL);
    let mut total_error = 0.0f64;
    let mut error_count = 0usize;

    for s in 1..n_symbols {
        let current = read_symbol(s);

        // Diferenca de fase por subportadora. E aqui que o canal se cancela.
        let mut deltas: Vec<f32> = current
            .iter()
            .zip(prev.iter())
            .map(|(c, p)| {
                let mut d = c - p;
                while d < 0.0 {
                    d += 2.0 * PI;
                }
                while d >= 2.0 * PI {
                    d -= 2.0 * PI;
                }
                d
            })
            .collect();

        // Correcao guiada por decisao, com dois termos.
        //
        // O canal real distorce a fase de duas maneiras distintas, e tratar so
        // a primeira nao basta:
        //
        // * **Rotacao comum** — um desvio de frequencia entre quem gravou e
        //   quem toca gira todas as subportadoras pelo mesmo angulo. E um
        //   termo constante.
        // * **Erro de tempo** — se a janela da FFT cai alguns decimos de
        //   amostra fora do lugar, a rotacao e *proporcional a frequencia*:
        //   um atraso de `dt` gira a subportadora `k` por `2*pi*k*dt/N`. E um
        //   termo linear em `k`, e foi o que fez o keyfile nao sobreviver a
        //   ida e volta por 44,1 kHz: a reamostragem deixa um residuo de
        //   fracao de amostra que a correcao constante nao alcanca.
        //
        // Entao estimamos uma reta em vez de um nivel. Em vez de minimos
        // quadrados — que um punhado de subportadoras ruins arrastaria —
        // tiramos a mediana dos erros em duas metades do espectro e passamos a
        // reta pelos dois pontos. Mediana e robusta a outlier por construcao, e
        // dois pontos bastam para uma reta.
        let meio = deltas.len() / 2;
        let erro_baixo = mediana_do_erro(&deltas[..meio]);
        let erro_alto = mediana_do_erro(&deltas[meio..]);

        let k_baixo = meio as f32 / 2.0;
        let k_alto = meio as f32 + (deltas.len() - meio) as f32 / 2.0;
        let inclinacao = if k_alto > k_baixo {
            (erro_alto - erro_baixo) / (k_alto - k_baixo)
        } else {
            0.0
        };
        let intercepto = erro_baixo - inclinacao * k_baixo;

        for (k, d) in deltas.iter_mut().enumerate() {
            *d -= intercepto + inclinacao * k as f32;
        }

        for &d in &deltas {
            let q = (d / (PI / 2.0)).round();
            total_error += (d - q * (PI / 2.0)).abs() as f64;
            error_count += 1;

            let quadrant = ((q as i32).rem_euclid(4)) as usize;
            let gray = QUADRANT_TO_GRAY[quadrant];
            bits.push((gray >> 1) & 1);
            bits.push(gray & 1);
        }

        prev = current;
    }

    let phase_error_deg = if error_count > 0 {
        (total_error / error_count as f64) as f32 * 180.0 / PI
    } else {
        0.0
    };

    Ok((
        bits_to_bytes(&bits),
        DemodStats {
            phase_error_deg,
            symbols: n_symbols,
        },
    ))
}

/// Duracao estimada, em segundos, do audio que `n_bytes` vao gerar.
pub fn estimate_duration_secs(n_bytes: usize) -> f32 {
    let symbols = (n_bytes * 8).div_ceil(BITS_PER_SYMBOL) + 1;
    let total = LEAD_SILENCE * 2 + CHIRP_LEN + GUARD_LEN + symbols * SYMBOL_LEN;
    total as f32 / SAMPLE_RATE as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dados(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 37 % 256) as u8).collect()
    }

    /// Soma ruido uniforme de amplitude `amp`, de forma deterministica.
    fn com_ruido(audio: &[i16], amp: i32) -> Vec<i16> {
        let mut seed = 0x2545F491_4F6CDD1Du64;
        audio
            .iter()
            .map(|&s| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let n = if amp == 0 {
                    0
                } else {
                    // Mascara antes de centrar: sem isso sobra um nivel DC
                    // enorme em vez de ruido.
                    ((seed >> 40) as i32 % (2 * amp)) - amp
                };
                (s as i32 + n).clamp(i16::MIN as i32, i16::MAX as i32) as i16
            })
            .collect()
    }

    fn bytes_certos(audio: &[i16], esperado: &[u8]) -> usize {
        match demodulate(audio, SAMPLE_RATE) {
            Ok((rec, _)) => rec.iter().zip(esperado.iter()).filter(|(a, b)| a == b).count(),
            Err(_) => 0,
        }
    }

    #[test]
    fn bits_ida_e_volta() {
        let b = dados(64);
        assert_eq!(bits_to_bytes(&bytes_to_bits(&b)), b);
    }

    #[test]
    fn modula_e_demodula_sem_canal() {
        let original = dados(2000);
        let audio = modulate(&original).unwrap();
        let (recovered, stats) = demodulate(&audio, SAMPLE_RATE).unwrap();

        assert!(
            recovered.len() >= original.len(),
            "recuperado {} < original {}",
            recovered.len(),
            original.len()
        );
        assert_eq!(&recovered[..original.len()], &original[..]);
        // Canal ideal: o erro de fase e so o residuo do corte de picos.
        assert!(stats.phase_error_deg < 5.0, "erro {}", stats.phase_error_deg);
    }

    /// Sob ruido, o modem cru entrega quase tudo — mas nao tudo.
    ///
    /// O corte de picos deixa um piso de erro que nao cai por melhorar a SNR:
    /// a distorcao de intermodulacao e proporcional ao sinal, nao ao ruido.
    /// Medido, esse piso fica na casa de 1e-4 por bit. Exigir recuperacao
    /// perfeita aqui seria cobrar do modem uma garantia que so a pilha
    /// completa oferece — quem fecha essa conta e o FEC, e e
    /// `audio::tests::pilha_completa_sobrevive_a_ruido` que prova isso.
    #[test]
    fn sobrevive_a_ruido_branco() {
        let original = dados(1000);
        let audio = modulate(&original).unwrap();
        let certos = bytes_certos(&com_ruido(&audio, 1024), &original);
        assert!(
            certos >= 995,
            "com ruido ±1024 recuperou so {certos}/1000 bytes"
        );
    }

    /// Regressao sobre a curva de qualidade medida.
    ///
    /// Os limiares sao frouxos de proposito — o que se protege aqui e a forma
    /// da curva, nao o numero exato. Se uma mudanca no DSP derrubar qualquer
    /// degrau, este teste acusa antes de o usuario descobrir com uma fita que
    /// nao volta.
    #[test]
    fn degradacao_e_gradual() {
        let original = dados(2000);
        let audio = modulate(&original).unwrap();

        // (amplitude do ruido, minimo de bytes corretos exigido)
        for (amp, minimo) in [(0i32, 2000usize), (256, 2000), (1024, 1990), (2048, 1900)] {
            let certos = bytes_certos(&com_ruido(&audio, amp), &original);
            assert!(
                certos >= minimo,
                "com ruido ±{amp}: {certos}/2000 bytes, esperava ao menos {minimo}"
            );
        }
    }

    /// O sinal precisa usar a faixa dinamica de verdade.
    ///
    /// Este teste existe por causa de um bug real: o chirp de sincronismo
    /// entrava na mesma normalizacao dos dados e, por ser uma senoide de pico
    /// alto, definia sozinho o maximo — deixando o OFDM 15 dB abaixo do que o
    /// arquivo comportava e derrubando a tolerancia a ruido junto.
    #[test]
    fn dados_ocupam_a_faixa_dinamica() {
        let audio = modulate(&dados(2000)).unwrap();
        let rms = (audio.iter().map(|&s| (s as f64).powi(2)).sum::<f64>() / audio.len() as f64)
            .sqrt();
        assert!(rms > 7000.0, "RMS de apenas {rms:.0}; o sinal esta fraco demais");
    }

    /// O preambulo tem que ser encontrado mesmo com o sinal deslocado no
    /// tempo, que e o caso de qualquer gravacao real.
    #[test]
    fn acha_preambulo_com_offset() {
        let original = dados(300);
        let audio = modulate(&original).unwrap();

        let mut deslocado = vec![0i16; 7777];
        deslocado.extend_from_slice(&audio);

        let (recovered, _) = demodulate(&deslocado, SAMPLE_RATE).unwrap();
        assert_eq!(&recovered[..original.len()], &original[..]);
    }

    #[test]
    fn sincronizacao_e_exata() {
        let audio = modulate(&dados(500)).unwrap();
        let float: Vec<f32> = audio.iter().map(|&s| s as f32 / i16::MAX as f32).collect();
        assert_eq!(find_preamble(&float), Some(LEAD_SILENCE));
    }

    #[test]
    fn tolera_atenuacao_forte() {
        let original = dados(500);
        let audio = modulate(&original).unwrap();
        // Volume baixo: DQPSK so olha fase, entao amplitude nao deveria importar.
        let baixo: Vec<i16> = audio.iter().map(|&s| s / 20).collect();
        let (recovered, _) = demodulate(&baixo, SAMPLE_RATE).unwrap();
        assert_eq!(&recovered[..original.len()], &original[..]);
    }

    #[test]
    fn silencio_nao_e_confundido_com_sinal() {
        let silencio = vec![0i16; SAMPLE_RATE as usize];
        assert!(demodulate(&silencio, SAMPLE_RATE).is_err());
    }

    #[test]
    fn estimativa_de_duracao_e_plausivel() {
        // ~31 kbit/s: 10 KB devem caber em poucos segundos.
        let d = estimate_duration_secs(10_000);
        assert!(d > 1.0 && d < 6.0, "duracao estimada {d}s");
    }
}
