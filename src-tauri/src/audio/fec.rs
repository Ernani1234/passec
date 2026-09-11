//! Enquadramento e correcao de erros do stream acustico.
//!
//! O canal de audio perde dados de dois jeitos bem diferentes:
//!
//! * **Copia digital** (o WAV vai do disco para o disco) — perda zero. O FEC
//!   aqui e so cinto de seguranca.
//! * **Caminho analogico** (tocar num alto-falante e regravar, ou passar por
//!   MP3) — perde em *rajadas*: um clique, uma saturacao, um corte de meio
//!   segundo. Erros isolados sao raros; blocos inteiros somem.
//!
//! Por isso o esquema e *erasure coding*, nao correcao de erro cega: cada
//! bloco carrega um CRC32 e, se o CRC nao bate, o bloco e descartado inteiro e
//! vira uma lacuna de posicao conhecida. Reed-Solomon reconstroi lacunas com o
//! dobro da eficiencia com que corrige erros de posicao desconhecida: `parity`
//! lacunas custam `parity` blocos, contra `2*parity` no caso cego.
//!
//! Pela mesma razao os blocos vao no fio em ordem sequencial, sem
//! interleaving. Interleaving espalharia uma rajada por muitos blocos,
//! estragando o CRC de todos eles; mantendo a ordem, a rajada se concentra em
//! poucos blocos e o resto sobrevive intacto.

use crc32fast::Hasher;
use reed_solomon_erasure::galois_8::ReedSolomon;

use super::AudioError;

const MAGIC: &[u8; 4] = b"PSC1";
const VERSION: u8 = 1;

/// Bytes uteis por bloco.
pub const SHARD_SIZE: usize = 223;
/// `idx (2) + crc32 (4) + payload`.
pub const BLOCK_SIZE: usize = 2 + 4 + SHARD_SIZE;

/// Teto de blocos por grupo RS: GF(2^8) so enderecca 256 shards.
const MAX_DATA_SHARDS: usize = 128;
/// Marcador de indice que identifica um bloco de cabecalho.
const HEADER_IDX: u16 = 0xFFFF;
/// Copias do cabecalho. Perder o cabecalho invalida o stream inteiro, entao
/// ele nao participa do RS — vai redundante na marra.
///
/// As copias sao **espalhadas** pelo stream (inicio, meio e fim), nao
/// empilhadas na frente. O motivo veio de medicao: o dano nao se distribui por
/// igual, concentra-se nos primeiros blocos, e com as tres copias juntas ali
/// um payload pequeno perdia o cabecalho inteiro e falhava — mesmo com os
/// blocos de dados intactos. Como cada bloco carrega o proprio indice, a
/// posicao no fio nao importa para remontar, e espalhar sai de graca.
const HEADER_COPIES: usize = 3;

const HEADER_FIELDS_LEN: usize = 17;
const HEADER_LEN: usize = HEADER_FIELDS_LEN + 4;

/// Quanto de paridade gastar, conforme o destino do audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Robustness {
    /// Arquivo que so sera copiado bit a bit. ~12% de overhead.
    Digital,
    /// Vai ser tocado, regravado ou recomprimido. ~40% de overhead.
    Airborne,
}

impl Robustness {
    fn parity_for(self, data_shards: usize) -> usize {
        let ratio = match self {
            Robustness::Digital => 0.12_f64,
            Robustness::Airborne => 0.40_f64,
        };
        let proporcional = (data_shards as f64 * ratio).ceil() as usize;

        // Paridade proporcional so faz sentido quando ha muitos shards. Um
        // payload pequeno — o keyfile de 64 bytes, uma senha avulsa — gera um
        // punhado de blocos, e 40% de um punhado e quase nada: bastavam duas
        // perdas para o arquivo virar lixo. Pior, a medicao mostrou que o dano
        // nao e proporcional ao tamanho (2 a 3 blocos danificados tanto num
        // stream de 6 quanto num de 54), entao quanto menor o payload, maior a
        // fracao destruida.
        //
        // Abaixo de 8 shards damos redundancia generosa. O custo absoluto e
        // irrisorio — leva o keyfile de 6 para 10 blocos, alguns centesimos de
        // segundo de audio — e o beneficio e o arquivo continuar abrindo o
        // cofre depois de anos de copias e conversoes.
        let piso = if data_shards <= 8 {
            (data_shards * 2).max(6)
        } else {
            2
        };

        // Teto respeita o limite de 256 shards por grupo do GF(2^8).
        proporcional.max(piso).clamp(2, 256 - data_shards)
    }
}

struct FrameHeader {
    payload_len: u32,
    payload_crc: u32,
    data_shards: u8,
    parity_shards: u8,
    shard_size: u16,
}

impl FrameHeader {
    fn encode(&self) -> Vec<u8> {
        let mut h = Vec::with_capacity(HEADER_LEN);
        h.extend_from_slice(MAGIC);
        h.push(VERSION);
        h.extend_from_slice(&self.payload_len.to_be_bytes());
        h.extend_from_slice(&self.payload_crc.to_be_bytes());
        h.push(self.data_shards);
        h.push(self.parity_shards);
        h.extend_from_slice(&self.shard_size.to_be_bytes());
        let crc = crc32(&h);
        h.extend_from_slice(&crc.to_be_bytes());
        h
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN || &bytes[0..4] != MAGIC || bytes[4] != VERSION {
            return None;
        }
        let stored = u32::from_be_bytes(bytes[17..21].try_into().ok()?);
        if crc32(&bytes[..HEADER_FIELDS_LEN]) != stored {
            return None;
        }
        let data_shards = bytes[13];
        let parity_shards = bytes[14];
        let shard_size = u16::from_be_bytes(bytes[15..17].try_into().ok()?);
        // Um cabecalho com CRC valido ainda pode vir de um arquivo hostil;
        // valores fora da faixa causariam alocacao absurda ou divisao por zero.
        if data_shards == 0 || parity_shards == 0 || shard_size == 0 {
            return None;
        }
        if data_shards as usize + parity_shards as usize > 256 {
            return None;
        }
        Some(Self {
            payload_len: u32::from_be_bytes(bytes[5..9].try_into().ok()?),
            payload_crc: u32::from_be_bytes(bytes[9..13].try_into().ok()?),
            data_shards,
            parity_shards,
            shard_size,
        })
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(bytes);
    h.finalize()
}

fn make_block(idx: u16, payload: &[u8], shard_size: usize) -> Vec<u8> {
    let mut block = Vec::with_capacity(6 + shard_size);
    block.extend_from_slice(&idx.to_be_bytes());
    let mut body = vec![0u8; shard_size];
    body[..payload.len()].copy_from_slice(payload);
    block.extend_from_slice(&crc32(&body).to_be_bytes());
    block.extend_from_slice(&body);
    block
}

/// Empacota `payload` numa sequencia de blocos prontos para modular.
pub fn encode(payload: &[u8], robustness: Robustness) -> Result<Vec<u8>, AudioError> {
    if payload.is_empty() {
        return Err(AudioError::Fec("payload vazio".into()));
    }

    let total_shards_needed = payload.len().div_ceil(SHARD_SIZE);
    let data_shards = total_shards_needed.clamp(1, MAX_DATA_SHARDS);
    let parity_shards = robustness.parity_for(data_shards);
    let groups = total_shards_needed.div_ceil(data_shards);

    let header = FrameHeader {
        payload_len: payload.len() as u32,
        payload_crc: crc32(payload),
        data_shards: data_shards as u8,
        parity_shards: parity_shards as u8,
        shard_size: SHARD_SIZE as u16,
    };

    let header_bytes = header.encode();
    let header_block = make_block(HEADER_IDX, &header_bytes, SHARD_SIZE);

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| AudioError::Fec(format!("RS({data_shards},{parity_shards}): {e}")))?;

    let mut data_blocks: Vec<Vec<u8>> = Vec::new();
    let group_bytes = data_shards * SHARD_SIZE;
    for g in 0..groups {
        let start = g * group_bytes;
        let end = (start + group_bytes).min(payload.len());
        let chunk = &payload[start..end];

        // Todo shard tem exatamente SHARD_SIZE; o ultimo grupo completa com
        // zeros, que o truncamento por `payload_len` remove na volta.
        let mut shards: Vec<Vec<u8>> = (0..data_shards + parity_shards)
            .map(|_| vec![0u8; SHARD_SIZE])
            .collect();
        for (i, piece) in chunk.chunks(SHARD_SIZE).enumerate() {
            shards[i][..piece.len()].copy_from_slice(piece);
        }

        rs.encode(&mut shards)
            .map_err(|e| AudioError::Fec(e.to_string()))?;

        for (i, shard) in shards.iter().enumerate() {
            let idx_usize = g * (data_shards + parity_shards) + i;
            if idx_usize >= HEADER_IDX as usize {
                return Err(AudioError::Fec("payload grande demais para o frame".into()));
            }
            data_blocks.push(make_block(idx_usize as u16, shard, SHARD_SIZE));
        }
    }

    // Intercala as copias do cabecalho em pontos afastados entre si.
    let total = data_blocks.len();
    let pontos = [0usize, total / 2, total];
    debug_assert_eq!(pontos.len(), HEADER_COPIES);

    let mut out = Vec::with_capacity((total + HEADER_COPIES) * BLOCK_SIZE);
    let mut proxima = 0usize;
    for (i, bloco) in data_blocks.iter().enumerate() {
        while proxima < pontos.len() && pontos[proxima] == i {
            out.extend_from_slice(&header_block);
            proxima += 1;
        }
        out.extend_from_slice(bloco);
    }
    // A copia final (ponto == total) e qualquer outra que caia no fim.
    while proxima < pontos.len() {
        out.extend_from_slice(&header_block);
        proxima += 1;
    }

    Ok(out)
}

/// Resultado de uma decodificacao, com estatisticas para a UI mostrar quao
/// perto da borda o sinal chegou.
pub struct Decoded {
    pub payload: Vec<u8>,
    pub blocks_total: usize,
    pub blocks_corrupt: usize,
    pub blocks_recovered: usize,
}

/// `Debug` escrito a mao para mostrar o tamanho do payload em vez do conteudo.
///
/// O derive imprimiria os bytes decifrados inteiros, e um `unwrap` que falhe
/// num teste — ou um log esquecido — despejaria o cofre no terminal.
impl std::fmt::Debug for Decoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoded")
            .field("payload_len", &self.payload.len())
            .field("blocks_total", &self.blocks_total)
            .field("blocks_corrupt", &self.blocks_corrupt)
            .field("blocks_recovered", &self.blocks_recovered)
            .finish()
    }
}

/// Remonta o payload a partir do stream de blocos.
pub fn decode(stream: &[u8]) -> Result<Decoded, AudioError> {
    if stream.len() < BLOCK_SIZE {
        return Err(AudioError::Fec("stream curto demais".into()));
    }

    // Primeira passada: confere o CRC de cada bloco e localiza o cabecalho.
    let mut header: Option<FrameHeader> = None;
    let mut blocos: Vec<(u16, bool, &[u8])> = Vec::new();

    for raw in stream.chunks_exact(BLOCK_SIZE) {
        let idx = u16::from_be_bytes([raw[0], raw[1]]);
        let stored_crc = u32::from_be_bytes([raw[2], raw[3], raw[4], raw[5]]);
        let body = &raw[6..];
        let integro = crc32(body) == stored_crc;

        if integro && idx == HEADER_IDX && header.is_none() {
            header = FrameHeader::decode(body);
        }
        blocos.push((idx, integro, body));
    }

    let header = header.ok_or_else(|| {
        AudioError::Fec("cabecalho nao encontrado — o audio nao parece ser um stream PASSEC".into())
    })?;

    let data_shards = header.data_shards as usize;
    let parity_shards = header.parity_shards as usize;
    let per_group = data_shards + parity_shards;
    let shard_size = header.shard_size as usize;

    if shard_size != SHARD_SIZE {
        return Err(AudioError::Fec(format!(
            "shard de {shard_size}B incompativel com esta versao"
        )));
    }

    let payload_len = header.payload_len as usize;
    let groups = payload_len.div_ceil(shard_size).div_ceil(data_shards).max(1);

    // Segunda passada, agora sabendo quantos blocos a transmissao tem.
    //
    // O modem trabalha em simbolos de 746 bits, que quase nunca terminam
    // exatamente no fim do ultimo bloco. Os bits de padding que sobram viram
    // bytes, e esses bytes podem formar blocos completos de lixo no fim do
    // stream. Eles nao fazem parte da transmissao: conta-los inflaria o numero
    // de blocos corrompidos e faria um arquivo perfeito ser reportado como
    // danificado.
    let esperados = HEADER_COPIES + groups * (data_shards + parity_shards);
    let uteis = blocos.len().min(esperados);

    let blocks_total = uteis;
    let blocks_corrupt = blocos[..uteis].iter().filter(|(_, ok, _)| !ok).count();

    let good: Vec<(u16, &[u8])> = blocos[..uteis]
        .iter()
        .filter(|(idx, ok, _)| *ok && *idx != HEADER_IDX)
        .map(|(idx, _, body)| (*idx, *body))
        .collect();

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| AudioError::Fec(e.to_string()))?;

    let mut payload = Vec::with_capacity(payload_len);
    let mut blocks_recovered = 0usize;

    for g in 0..groups {
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; per_group];
        for (idx, body) in &good {
            let idx = *idx as usize;
            if idx / per_group == g {
                let slot = idx % per_group;
                if body.len() == shard_size {
                    shards[slot] = Some(body.to_vec());
                }
            }
        }

        let presentes = shards.iter().filter(|s| s.is_some()).count();
        let faltando = per_group - presentes;
        if presentes < data_shards {
            return Err(AudioError::Fec(format!(
                "grupo {g}: {faltando} blocos perdidos, o limite recuperavel e {parity_shards}"
            )));
        }
        if faltando > 0 {
            rs.reconstruct(&mut shards)
                .map_err(|e| AudioError::Fec(format!("grupo {g}: {e}")))?;
            blocks_recovered += faltando;
        }

        for shard in shards.iter().take(data_shards) {
            let s = shard
                .as_ref()
                .ok_or_else(|| AudioError::Fec(format!("grupo {g}: reconstrucao incompleta")))?;
            payload.extend_from_slice(s);
        }
    }

    if payload.len() < payload_len {
        return Err(AudioError::Fec("payload truncado".into()));
    }
    payload.truncate(payload_len);

    // Checagem fim-a-fim: pega o caso em que cada bloco passou no CRC mas a
    // remontagem saiu errada (indices embaralhados, grupo faltando inteiro).
    if crc32(&payload) != header.payload_crc {
        return Err(AudioError::Fec(
            "CRC final nao confere — audio corrompido alem do reparo".into(),
        ));
    }

    Ok(Decoded {
        payload,
        blocks_total,
        blocks_corrupt,
        blocks_recovered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// Posicoes, em blocos, onde as copias do cabecalho caem no stream.
    fn posicoes_do_cabecalho(stream: &[u8]) -> Vec<usize> {
        stream
            .chunks_exact(BLOCK_SIZE)
            .enumerate()
            .filter(|(_, b)| u16::from_be_bytes([b[0], b[1]]) == HEADER_IDX)
            .map(|(i, _)| i)
            .collect()
    }

    fn posicoes_de_dados(stream: &[u8]) -> Vec<usize> {
        stream
            .chunks_exact(BLOCK_SIZE)
            .enumerate()
            .filter(|(_, b)| u16::from_be_bytes([b[0], b[1]]) != HEADER_IDX)
            .map(|(i, _)| i)
            .collect()
    }

    /// Estraga o bloco na posicao dada, invalidando o CRC dele.
    fn danifica(stream: &mut [u8], bloco: usize) {
        stream[bloco * BLOCK_SIZE + 10] ^= 0xFF;
    }

    #[test]
    fn ida_e_volta_sem_perda() {
        for n in [1usize, 64, 223, 224, 5000, 40_000] {
            let p = payload(n);
            let stream = encode(&p, Robustness::Digital).unwrap();
            let out = decode(&stream).unwrap();
            assert_eq!(out.payload, p, "falhou com n={n}");
            assert_eq!(out.blocks_corrupt, 0);
        }
    }

    #[test]
    fn recupera_rajada_dentro_do_orcamento() {
        let p = payload(20_000);
        let mut stream = encode(&p, Robustness::Airborne).unwrap();

        // Rajada em blocos de dados consecutivos: um corte no audio.
        let dados = posicoes_de_dados(&stream);
        for &b in dados.iter().take(8) {
            danifica(&mut stream, b);
        }

        let out = decode(&stream).unwrap();
        assert_eq!(out.payload, p);
        assert_eq!(out.blocks_corrupt, 8);
        assert!(out.blocks_recovered >= 8);
    }

    /// As copias do cabecalho existem para que perder algumas nao seja fatal.
    #[test]
    fn sobrevive_a_perda_de_todas_as_copias_do_cabecalho_menos_uma() {
        let p = payload(3000);
        let mut stream = encode(&p, Robustness::Digital).unwrap();

        let cabecalhos = posicoes_do_cabecalho(&stream);
        assert_eq!(cabecalhos.len(), HEADER_COPIES);
        for &b in cabecalhos.iter().take(HEADER_COPIES - 1) {
            danifica(&mut stream, b);
        }
        assert_eq!(decode(&stream).unwrap().payload, p);
    }

    /// As copias precisam ficar longe umas das outras: o dano real se concentra
    /// em regioes, e tres copias vizinhas morreriam juntas.
    #[test]
    fn copias_do_cabecalho_ficam_espalhadas() {
        let stream = encode(&payload(20_000), Robustness::Digital).unwrap();
        let total_blocos = stream.len() / BLOCK_SIZE;
        let pos = posicoes_do_cabecalho(&stream);

        assert_eq!(pos.len(), HEADER_COPIES);
        assert_eq!(pos[0], 0, "uma copia precisa abrir o stream");
        assert!(
            pos[HEADER_COPIES - 1] >= total_blocos - 2,
            "uma copia precisa fechar o stream; a ultima esta em {} de {total_blocos}",
            pos[HEADER_COPIES - 1]
        );
        // Nenhuma copia colada na outra.
        for par in pos.windows(2) {
            assert!(
                par[1] - par[0] > total_blocos / 4,
                "copias muito proximas: {par:?}"
            );
        }
    }

    #[test]
    fn falha_quando_a_perda_passa_do_orcamento() {
        let p = payload(20_000);
        let mut stream = encode(&p, Robustness::Digital).unwrap();
        let dados = posicoes_de_dados(&stream);
        // 12% de paridade sobre 90 shards da ~11; 40 perdas passa do limite.
        for &b in dados.iter().take(40) {
            danifica(&mut stream, b);
        }
        assert!(decode(&stream).is_err());
    }

    #[test]
    fn sem_cabecalho_valido_falha_claramente() {
        let lixo = vec![0u8; BLOCK_SIZE * 4];
        let err = decode(&lixo).unwrap_err().to_string();
        assert!(err.contains("cabecalho"), "erro inesperado: {err}");
    }

    #[test]
    fn airborne_gasta_mais_paridade_que_digital() {
        let p = payload(20_000);
        let d = encode(&p, Robustness::Digital).unwrap().len();
        let a = encode(&p, Robustness::Airborne).unwrap().len();
        assert!(a > d, "airborne={a} deveria exceder digital={d}");
    }

    /// Payload pequeno precisa de redundancia desproporcional.
    ///
    /// O dano medido nao encolhe junto com o arquivo: um stream de 6 blocos
    /// perde tantos blocos quanto um de 54. Sem este piso, um keyfile de 64
    /// bytes ficava com 3 blocos de dados e morria com duas perdas.
    #[test]
    fn payload_pequeno_recebe_paridade_generosa() {
        let stream = encode(&payload(64), Robustness::Airborne).unwrap();
        let blocos = stream.len() / BLOCK_SIZE;
        assert!(blocos >= 10, "apenas {blocos} blocos para um payload de 64 B");

        // E a redundancia precisa funcionar de fato: sobrevive a metade dos
        // blocos de dados sendo destruida.
        let dados = posicoes_de_dados(&stream);
        let mut danificado = stream.clone();
        for &b in dados.iter().take(dados.len() / 2) {
            danifica(&mut danificado, b);
        }
        assert_eq!(decode(&danificado).unwrap().payload, payload(64));
    }

    /// Bytes de padding depois do fim da transmissao nao sao dano.
    ///
    /// O modem fecha o ultimo simbolo com bits de enchimento, que podem formar
    /// blocos inteiros de lixo. Conta-los faria um arquivo perfeito ser
    /// reportado como corrompido.
    #[test]
    fn lixo_apos_o_fim_nao_conta_como_corrupcao() {
        let p = payload(3000);
        let mut stream = encode(&p, Robustness::Digital).unwrap();
        let blocos_reais = stream.len() / BLOCK_SIZE;

        stream.extend_from_slice(&vec![0xA5u8; BLOCK_SIZE * 3]);

        let out = decode(&stream).unwrap();
        assert_eq!(out.payload, p);
        assert_eq!(out.blocks_corrupt, 0, "o padding foi contado como dano");
        assert_eq!(out.blocks_total, blocos_reais);
    }
}
