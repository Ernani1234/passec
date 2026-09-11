//! Esteganografia em audio: esconde bytes nos bits menos significativos de um
//! WAV comum, que continua tocando normalmente.
//!
//! # O que isto e e o que nao e
//!
//! Esconder **nao** e cifrar. O payload que entra aqui ja saiu do
//! XChaCha20-Poly1305; o LSB so decide *onde* esse ciphertext mora. Se alguem
//! descobrir o esconderijo, encontra ruido cifrado, nao senhas. A negacao
//! plausivel e um bonus — nunca a defesa.
//!
//! # Por que as posicoes dependem da chave
//!
//! LSB ingenuo escreve nos primeiros N samples em sequencia, e isso e
//! trivialmente detectavel: o inicio do arquivo fica com LSBs estatisticamente
//! aleatorios enquanto o resto mantem a correlacao natural da musica — um
//! teste qui-quadrado acusa na hora.
//!
//! Aqui o carregador e dividido em N janelas iguais e cada bit cai numa
//! posicao sorteada dentro da sua janela, com o sorteio vindo de um XOF BLAKE3
//! semeado pela chave do cofre. As alteracoes ficam espalhadas pelo arquivo
//! inteiro e, sem a chave, nem da para saber quais samples olhar.
//!
//! Um bit por sample em audio de 16 bits muda cada amostra em no maximo 1/32768
//! — cerca de -90 dBFS, abaixo do ruido de fundo de qualquer gravacao real.

use crc32fast::Hasher;

use super::AudioError;

const MAGIC: &[u8; 4] = b"PSTG";
const VERSION: u8 = 1;
/// `magic (4) + versao (1) + len (4) + crc32 (4) + reservado (3)`.
const HEADER_LEN: usize = 16;
const HEADER_BITS: usize = HEADER_LEN * 8;
/// Trecho inicial reservado ao cabecalho. Ele precisa morar num lugar que o
/// extrator ache *antes* de saber o tamanho do payload.
const HEADER_REGION: usize = 8192;

const DOMAIN_POSITIONS: &str = "passec.stego.positions.v1";
const DOMAIN_HEADER: &str = "passec.stego.header.v1";

/// Fluxo pseudoaleatorio deterministico derivado da chave do cofre.
struct KeyStream(blake3::OutputReader);

impl KeyStream {
    fn new(domain: &str, key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(key);
        Self(hasher.finalize_xof())
    }

    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_be_bytes(b)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// Calcula a posicao de cada bit: uma janela por bit, sorteio dentro da janela.
///
/// Janelas garantem que dois bits nunca disputem o mesmo sample, o que
/// dispensa tratar colisao e mantem o custo linear.
fn bit_positions(
    key: &[u8; 32],
    region_start: usize,
    region_len: usize,
    n_bits: usize,
) -> Result<Vec<usize>, AudioError> {
    if n_bits == 0 {
        return Ok(Vec::new());
    }
    let window = region_len / n_bits;
    if window == 0 {
        return Err(AudioError::Stego(
            "audio carregador curto demais para esconder este payload".into(),
        ));
    }

    let mut stream = KeyStream::new(DOMAIN_POSITIONS, key);
    Ok((0..n_bits)
        .map(|i| region_start + i * window + (stream.next_u32() as usize % window))
        .collect())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(bytes);
    h.finalize()
}

fn write_bits(samples: &mut [i16], positions: &[usize], bits: &[u8]) {
    for (&pos, &bit) in positions.iter().zip(bits.iter()) {
        // Mexe so no bit 0; o resto da amostra fica intacto.
        samples[pos] = (samples[pos] & !1) | (bit & 1) as i16;
    }
}

fn read_bits(samples: &[i16], positions: &[usize]) -> Vec<u8> {
    positions.iter().map(|&p| (samples[p] & 1) as u8).collect()
}

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

/// Quantos bytes cabem num carregador de `n_samples` amostras.
pub fn capacity_bytes(n_samples: usize) -> usize {
    n_samples.saturating_sub(HEADER_REGION) / 8
}

/// Esconde `payload` dentro de `carrier`, devolvendo as amostras alteradas.
pub fn embed(carrier: &[i16], payload: &[u8], key: &[u8; 32]) -> Result<Vec<i16>, AudioError> {
    if payload.is_empty() {
        return Err(AudioError::Stego("nada para esconder".into()));
    }
    if carrier.len() <= HEADER_REGION {
        return Err(AudioError::Stego(format!(
            "carregador precisa de mais de {HEADER_REGION} amostras"
        )));
    }
    let capacity = capacity_bytes(carrier.len());
    if payload.len() > capacity {
        return Err(AudioError::Stego(format!(
            "payload de {} B nao cabe: este audio comporta {} B",
            payload.len(),
            capacity
        )));
    }

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    header.extend_from_slice(&crc32(payload).to_be_bytes());
    header.extend_from_slice(&[0u8; 3]);

    // Mascara o cabecalho com o keystream: sem isso o marcador "PSTG" ficaria
    // legivel nos LSBs e entregaria tanto o esquema quanto o tamanho exato do
    // segredo escondido.
    let mut mask = [0u8; HEADER_LEN];
    KeyStream::new(DOMAIN_HEADER, key).fill(&mut mask);
    for (h, m) in header.iter_mut().zip(mask.iter()) {
        *h ^= m;
    }

    let mut out = carrier.to_vec();

    let header_positions = bit_positions(key, 0, HEADER_REGION, HEADER_BITS)?;
    write_bits(&mut out, &header_positions, &bytes_to_bits(&header));

    let payload_positions = bit_positions(
        key,
        HEADER_REGION,
        carrier.len() - HEADER_REGION,
        payload.len() * 8,
    )?;
    write_bits(&mut out, &payload_positions, &bytes_to_bits(payload));

    Ok(out)
}

/// Recupera o payload escondido em `samples`.
pub fn extract(samples: &[i16], key: &[u8; 32]) -> Result<Vec<u8>, AudioError> {
    if samples.len() <= HEADER_REGION {
        return Err(AudioError::Stego("audio curto demais".into()));
    }

    let header_positions = bit_positions(key, 0, HEADER_REGION, HEADER_BITS)?;
    let mut header = bits_to_bytes(&read_bits(samples, &header_positions));

    let mut mask = [0u8; HEADER_LEN];
    KeyStream::new(DOMAIN_HEADER, key).fill(&mut mask);
    for (h, m) in header.iter_mut().zip(mask.iter()) {
        *h ^= m;
    }

    if &header[0..4] != MAGIC || header[4] != VERSION {
        return Err(AudioError::Stego(
            "nenhum payload PASSEC encontrado neste audio (ou a chave nao confere)".into(),
        ));
    }

    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let expected_crc = u32::from_be_bytes([header[9], header[10], header[11], header[12]]);

    if len == 0 || len > capacity_bytes(samples.len()) {
        return Err(AudioError::Stego("cabecalho escondido inconsistente".into()));
    }

    let payload_positions =
        bit_positions(key, HEADER_REGION, samples.len() - HEADER_REGION, len * 8)?;
    let payload = bits_to_bytes(&read_bits(samples, &payload_positions));

    if crc32(&payload) != expected_crc {
        return Err(AudioError::Stego(
            "payload escondido corrompido — o audio foi reeditado ou recomprimido".into(),
        ));
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(n: usize) -> Vec<i16> {
        // Senoide: aproxima um sinal real melhor que ruido ou silencio.
        (0..n)
            .map(|i| ((i as f32 * 0.01).sin() * 12000.0) as i16)
            .collect()
    }

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn ida_e_volta() {
        let c = carrier(200_000);
        let payload: Vec<u8> = (0..2000).map(|i| (i * 13 % 256) as u8).collect();
        let stego = embed(&c, &payload, &key(1)).unwrap();
        assert_eq!(extract(&stego, &key(1)).unwrap(), payload);
    }

    #[test]
    fn chave_errada_nao_extrai() {
        let c = carrier(200_000);
        let payload = vec![42u8; 500];
        let stego = embed(&c, &payload, &key(1)).unwrap();
        assert!(extract(&stego, &key(2)).is_err());
    }

    #[test]
    fn audio_limpo_nao_reporta_payload() {
        assert!(extract(&carrier(200_000), &key(1)).is_err());
    }

    /// A distorcao tem que ser inaudivel: no maximo 1 unidade por amostra.
    #[test]
    fn alteracao_e_imperceptivel() {
        let c = carrier(200_000);
        let stego = embed(&c, &vec![7u8; 1000], &key(1)).unwrap();
        let max_delta = c
            .iter()
            .zip(stego.iter())
            .map(|(a, b)| (*a as i32 - *b as i32).abs())
            .max()
            .unwrap();
        assert!(max_delta <= 1, "delta maximo {max_delta}");
    }

    /// Se os bits ficassem amontoados no inicio, um teste estatistico acharia.
    /// Exigimos que as alteracoes cheguem perto do fim do arquivo.
    #[test]
    fn bits_se_espalham_pelo_arquivo_inteiro() {
        let n = 200_000;
        let c = carrier(n);
        let stego = embed(&c, &vec![0xA5u8; 1000], &key(1)).unwrap();
        let ultima = c
            .iter()
            .zip(stego.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .max()
            .unwrap();
        assert!(ultima > n * 3 / 4, "alteracoes param em {ultima} de {n}");
    }

    #[test]
    fn recusa_payload_grande_demais() {
        let c = carrier(20_000);
        let grande = vec![0u8; 10_000];
        let err = embed(&c, &grande, &key(1)).unwrap_err().to_string();
        assert!(err.contains("nao cabe"), "erro inesperado: {err}");
    }

    #[test]
    fn detecta_edicao_do_audio() {
        let c = carrier(200_000);
        let payload = vec![9u8; 800];
        let mut stego = embed(&c, &payload, &key(1)).unwrap();
        // Zera os LSBs de um trecho, como faria um reencode.
        for s in stego[100_000..120_000].iter_mut() {
            *s &= !1;
        }
        assert!(extract(&stego, &key(1)).is_err());
    }

    #[test]
    fn capacidade_bate_com_o_que_cabe() {
        let n = 100_000;
        let cap = capacity_bytes(n);
        let c = carrier(n);
        assert!(embed(&c, &vec![1u8; cap], &key(3)).is_ok());
        assert!(embed(&c, &vec![1u8; cap + 1], &key(3)).is_err());
    }
}
