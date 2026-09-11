//! Testes de ponta a ponta: os caminhos que o usuario percorre de verdade.
//!
//! Os testes unitarios cobrem cada camada isolada. Estes cobrem as juncoes,
//! que e onde os erros caros costumam morar — um keyfile que funciona no
//! modulo mas nao sobrevive ao ciclo pelo disco, uma fita que demodula mas nao
//! abre, uma senha trocada que invalida o cadastro do Hello.

use passec_lib::audio::{self, Robustness};
use passec_lib::crypto::kdf::{KdfParams, UnlockFactors};
use passec_lib::crypto::keyfile::{self, KeyfileMode};
use passec_lib::vault::model::{EntryKind, VaultEntry};
use passec_lib::vault::UnlockedVault;

/// Parametros baratos: estes testes exercitam fluxo, nao o custo do Argon2id.
fn params() -> KdfParams {
    KdfParams {
        memory_kib: 16 * 1024,
        iterations: 2,
        parallelism: 1,
    }
}

fn fatores<'a>(senha: &'a str, digest: Option<[u8; 32]>) -> UnlockFactors<'a> {
    UnlockFactors {
        password: senha,
        keyfile_digest: digest,
    }
}

fn cofre_de_exemplo(senha: &str, digest: Option<[u8; 32]>, modo: KeyfileMode) -> Vec<u8> {
    let mut v = UnlockedVault::create(&fatores(senha, digest), modo, params()).unwrap();

    let mut banco = VaultEntry::new(EntryKind::Login, "Banco Central".into());
    banco.username = "akira".into();
    banco.password = "S3nh4-mu1to-l0nga-e-aleatoria!".into();
    banco.url = "https://banco.exemplo".into();
    banco.tags = vec!["financeiro".into()];
    banco.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    v.body.entries.push(banco);

    let mut nota = VaultEntry::new(EntryKind::Note, "Frase de recuperacao".into());
    nota.notes = "palavra1 palavra2 palavra3 palavra4".into();
    v.body.entries.push(nota);

    v.serialize().unwrap()
}

/// O ciclo principal do produto: cofre vira fita, fita vira cofre.
#[test]
fn cofre_vai_para_fita_e_volta_inteiro() {
    let bytes = cofre_de_exemplo("senha-mestra-bem-longa", None, KeyfileMode::None);

    let wav = audio::to_wav(&bytes, Robustness::Digital).unwrap();
    assert_eq!(&wav[0..4], b"RIFF", "a fita precisa ser um WAV tocavel");

    let (recuperado, report) = audio::from_wav(&wav).unwrap();
    assert!(report.pristine);
    assert_eq!(recuperado, bytes, "a fita nao devolveu os mesmos bytes");

    let v = UnlockedVault::open(&recuperado, &fatores("senha-mestra-bem-longa", None)).unwrap();
    assert_eq!(v.body.entries.len(), 2);
    assert_eq!(v.body.entries[0].password, "S3nh4-mu1to-l0nga-e-aleatoria!");
    assert_eq!(
        v.body.entries[0].totp_secret.as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
    assert_eq!(v.body.entries[1].notes, "palavra1 palavra2 palavra3 palavra4");
}

/// O keyfile gerado tem que sobreviver ao caminho inteiro: entropia, modulacao,
/// arquivo WAV, demodulacao e de volta ao mesmo digest.
#[test]
fn keyfile_de_audio_abre_o_cofre_depois_do_ciclo_completo() {
    let payload = keyfile::new_payload().unwrap();
    let digest_original = keyfile::digest_payload(&payload);

    // Vira audio, como o comando `keyfile_generate` faz.
    let wav = audio::to_wav(&payload, Robustness::Airborne).unwrap();

    let bytes = cofre_de_exemplo("outra-senha-comprida", Some(digest_original), KeyfileMode::Generated);

    // E na hora de abrir, o digest e recalculado a partir do arquivo.
    let (payload_lido, _) = audio::from_wav(&wav).unwrap();
    let digest_lido = keyfile::digest_payload(&payload_lido);
    assert_eq!(digest_lido, digest_original);

    let v = UnlockedVault::open(&bytes, &fatores("outra-senha-comprida", Some(digest_lido))).unwrap();
    assert_eq!(v.body.entries.len(), 2);

    // E a senha sozinha nao basta.
    assert!(UnlockedVault::open(&bytes, &fatores("outra-senha-comprida", None)).is_err());
}

/// O keyfile precisa tolerar o mundo real: um WAV que passou por reamostragem.
#[test]
fn keyfile_sobrevive_a_reamostragem() {
    let payload = keyfile::new_payload().unwrap();
    let digest = keyfile::digest_payload(&payload);

    let wav = audio::to_wav(&payload, Robustness::Airborne).unwrap();
    let pcm = audio::wav::decode(&wav).unwrap();

    // 48k -> 44.1k -> 48k, o que acontece ao passar por qualquer editor.
    let em_44 = audio::wav::resample(&pcm.samples, 48_000, 44_100);
    let de_volta = audio::wav::encode_with_rate(&em_44, 44_100).unwrap();

    let (payload_lido, _) = audio::from_wav(&de_volta).unwrap();
    assert_eq!(keyfile::digest_payload(&payload_lido), digest);
}

/// O keyfile e sorteado, entao cada execucao testa um arquivo diferente.
///
/// Repetindo varias vezes por execucao, uma margem apertada falha sempre em vez
/// de falhar de vez em quando — e um keyfile que abre "quase sempre" e um cofre
/// que uma hora nao abre.
#[test]
fn keyfile_sobrevive_a_reamostragem_em_repeticao() {
    for tentativa in 0..8 {
        let payload = keyfile::new_payload().unwrap();
        let digest = keyfile::digest_payload(&payload);

        let wav = audio::to_wav(&payload, Robustness::Airborne).unwrap();
        let pcm = audio::wav::decode(&wav).unwrap();
        let em_44 = audio::wav::resample(&pcm.samples, 48_000, 44_100);
        let arquivo = audio::wav::encode_with_rate(&em_44, 44_100).unwrap();

        let (lido, _) = audio::from_wav(&arquivo)
            .unwrap_or_else(|e| panic!("tentativa {tentativa} nao voltou: {e}"));
        assert_eq!(
            keyfile::digest_payload(&lido),
            digest,
            "tentativa {tentativa} devolveu payload diferente"
        );
    }
}

/// Esconder o cofre numa musica e recupera-lo de la.
#[test]
fn cofre_escondido_em_musica_volta_intacto() {
    let bytes = cofre_de_exemplo("senha-do-cofre-longa", None, KeyfileMode::None);

    // "Musica": um acorde, mais parecido com sinal real que ruido ou silencio.
    let carregador: Vec<i16> = (0..900_000)
        .map(|i| {
            use std::f32::consts::TAU;
            let t = i as f32 / 48_000.0;
            let s = (t * 440.0 * TAU).sin() * 0.4
                + (t * 554.0 * TAU).sin() * 0.3
                + (t * 659.0 * TAU).sin() * 0.25;
            (s * 11_000.0) as i16
        })
        .collect();

    let chave = blake3::derive_key("passec.stego.key.v1", b"senha-do-esconderijo");
    let escondido = audio::stego::embed(&carregador, &bytes, &chave).unwrap();

    // A musica nao pode ter mudado de forma audivel.
    let maior_delta = carregador
        .iter()
        .zip(escondido.iter())
        .map(|(a, b)| (*a as i32 - *b as i32).abs())
        .max()
        .unwrap();
    assert!(maior_delta <= 1, "delta maximo de {maior_delta}");

    let extraido = audio::stego::extract(&escondido, &chave).unwrap();
    assert_eq!(extraido, bytes);

    let v = UnlockedVault::open(&extraido, &fatores("senha-do-cofre-longa", None)).unwrap();
    assert_eq!(v.body.entries.len(), 2);

    // Com a senha errada do esconderijo, nao se acha nada.
    let chave_errada = blake3::derive_key("passec.stego.key.v1", b"chute");
    assert!(audio::stego::extract(&escondido, &chave_errada).is_err());
}

/// Exportar uma credencial avulsa: WAV curto, senha propria, importavel noutro
/// cofre sem carregar a senha mestra junto.
#[test]
fn credencial_avulsa_viaja_sozinha() {
    let origem = cofre_de_exemplo("senha-da-origem-longa", None, KeyfileMode::None);
    let v = UnlockedVault::open(&origem, &fatores("senha-da-origem-longa", None)).unwrap();
    let item = v.body.entries[0].clone();

    // Empacota como um cofre de um item so, protegido por senha propria.
    let mut mini = UnlockedVault::create(
        &fatores("senha-so-deste-arquivo", None),
        KeyfileMode::None,
        params(),
    )
    .unwrap();
    mini.body.entries.push(item);
    let mini_bytes = mini.serialize().unwrap();

    let wav = audio::to_wav(&mini_bytes, Robustness::Airborne).unwrap();
    let duracao = (wav.len() - 44) / 2 / 48_000;
    assert!(duracao < 10, "audio de item avulso longo demais: {duracao}s");

    let (lido, _) = audio::from_wav(&wav).unwrap();
    let importado = UnlockedVault::open(&lido, &fatores("senha-so-deste-arquivo", None)).unwrap();
    assert_eq!(importado.body.entries[0].title, "Banco Central");
    assert_eq!(
        importado.body.entries[0].password,
        "S3nh4-mu1to-l0nga-e-aleatoria!"
    );

    // A senha do cofre de origem nao abre o arquivo avulso: sao segredos
    // separados de proposito.
    assert!(UnlockedVault::open(&lido, &fatores("senha-da-origem-longa", None)).is_err());
}

/// Trocar a senha mestra nao pode invalidar o que nao depende dela.
#[test]
fn troca_de_senha_preserva_totp_e_conteudo() {
    let bytes = cofre_de_exemplo("senha-antiga-comprida", None, KeyfileMode::None);
    let mut v = UnlockedVault::open(&bytes, &fatores("senha-antiga-comprida", None)).unwrap();

    v.set_totp_secret("JBSWY3DPEHPK3PXP").unwrap();
    v.change_master(&fatores("senha-nova-comprida", None), KeyfileMode::None)
        .unwrap();
    let regravado = v.serialize().unwrap();

    let reaberto = UnlockedVault::open(&regravado, &fatores("senha-nova-comprida", None)).unwrap();
    assert_eq!(reaberto.body.entries.len(), 2);
    assert_eq!(
        reaberto.totp_secret().unwrap().as_deref(),
        Some("JBSWY3DPEHPK3PXP"),
        "o segredo TOTP e cifrado com subchave da VaultKey, que a troca de senha nao muda"
    );
    assert!(UnlockedVault::open(&regravado, &fatores("senha-antiga-comprida", None)).is_err());
}

/// Um cofre grande ainda cabe num audio de duracao razoavel.
#[test]
fn cofre_grande_gera_fita_de_duracao_aceitavel() {
    let mut v = UnlockedVault::create(
        &fatores("uma-senha-mestra-bem-comprida", None),
        KeyfileMode::None,
        params(),
    )
    .unwrap();

    for i in 0..200 {
        let mut e = VaultEntry::new(EntryKind::Login, format!("Servico numero {i}"));
        e.username = format!("usuario{i}@exemplo.com");
        e.password = format!("senha-aleatoria-de-servico-{i}-XyZ!@#");
        e.url = format!("https://servico{i}.exemplo.com/login");
        e.notes = "anotacao de tamanho moderado sobre esta conta".into();
        v.body.entries.push(e);
    }

    let bytes = v.serialize().unwrap();
    assert!(bytes.len() > 20_000, "cofre de teste pequeno demais: {}", bytes.len());

    let wav = audio::to_wav(&bytes, Robustness::Digital).unwrap();
    let duracao = (wav.len() - 44) as f32 / 2.0 / 48_000.0;
    assert!(
        duracao < 60.0,
        "200 itens ({} KB) geraram {duracao:.1}s de audio",
        bytes.len() / 1024
    );

    let (volta, _) = audio::from_wav(&wav).unwrap();
    let reaberto = UnlockedVault::open(&volta, &fatores("uma-senha-mestra-bem-comprida", None)).unwrap();
    assert_eq!(reaberto.body.entries.len(), 200);
    assert_eq!(reaberto.body.entries[199].username, "usuario199@exemplo.com");
}
