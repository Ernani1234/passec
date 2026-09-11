//! Geracao e avaliacao de senhas.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{random_vec, CryptoError};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";
/// Caracteres que o usuario confunde ao transcrever de uma tela para um
/// teclado: zero e O, um e l e I.
const AMBIGUOUS: &str = "0OoIl1|`'\"";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Remove caracteres visualmente ambiguos do alfabeto.
    #[serde(default)]
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("selecione pelo menos um conjunto de caracteres")]
    EmptyAlphabet,
    #[error("o comprimento precisa ficar entre {MIN_LENGTH} e {MAX_LENGTH}")]
    BadLength,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

fn build_alphabet(opts: &PasswordOptions) -> Vec<char> {
    let mut alphabet = String::new();
    if opts.lowercase {
        alphabet.push_str(LOWERCASE);
    }
    if opts.uppercase {
        alphabet.push_str(UPPERCASE);
    }
    if opts.digits {
        alphabet.push_str(DIGITS);
    }
    if opts.symbols {
        alphabet.push_str(SYMBOLS);
    }
    if opts.exclude_ambiguous {
        alphabet.retain(|c| !AMBIGUOUS.contains(c));
    }
    alphabet.chars().collect()
}

/// Sorteia um indice uniforme em `0..n` por amostragem com rejeicao.
///
/// O atalho obvio, `byte % n`, distribui mal quando 256 nao e multiplo de `n`:
/// com um alfabeto de 26 letras, as seis primeiras sairiam com frequencia
/// maior que as demais, e a entropia real ficaria abaixo da anunciada.
/// Descartar os bytes da faixa incompleta custa algumas leituras a mais e
/// devolve uniformidade exata.
fn uniform_index(n: usize) -> Result<usize, CryptoError> {
    debug_assert!(n > 0 && n <= 256);
    let limit = 256 - (256 % n);
    loop {
        // Lote de bytes: uma syscall por caractere seria desperdicio.
        let batch = random_vec(32)?;
        for b in batch {
            if (b as usize) < limit {
                return Ok(b as usize % n);
            }
        }
    }
}

/// Gera uma senha, garantindo ao menos um caractere de cada classe pedida.
pub fn generate(opts: &PasswordOptions) -> Result<Zeroizing<String>, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&opts.length) {
        return Err(GeneratorError::BadLength);
    }
    let alphabet = build_alphabet(opts);
    if alphabet.is_empty() {
        return Err(GeneratorError::EmptyAlphabet);
    }

    // Cada classe ativa contribui com um caractere obrigatorio; sem isso, uma
    // senha de 24 caracteres ocasionalmente sai sem nenhum digito e e recusada
    // por sites que exigem todas as classes.
    let mut classes: Vec<Vec<char>> = Vec::new();
    for (ativo, conjunto) in [
        (opts.lowercase, LOWERCASE),
        (opts.uppercase, UPPERCASE),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ] {
        if ativo {
            let mut chars: Vec<char> = conjunto.chars().collect();
            if opts.exclude_ambiguous {
                chars.retain(|c| !AMBIGUOUS.contains(*c));
            }
            if !chars.is_empty() {
                classes.push(chars);
            }
        }
    }

    let mut chars: Vec<char> = Vec::with_capacity(opts.length);
    for class in &classes {
        if chars.len() < opts.length {
            chars.push(class[uniform_index(class.len())?]);
        }
    }
    while chars.len() < opts.length {
        chars.push(alphabet[uniform_index(alphabet.len())?]);
    }

    // Embaralha, senao as posicoes iniciais seguiriam sempre a ordem das
    // classes e a senha teria estrutura previsivel.
    for i in (1..chars.len()).rev() {
        let j = uniform_index(i + 1)?;
        chars.swap(i, j);
    }

    Ok(Zeroizing::new(chars.into_iter().collect()))
}

/// Entropia teorica de uma senha gerada com estas opcoes.
pub fn entropy_bits(opts: &PasswordOptions) -> f64 {
    let n = build_alphabet(opts).len();
    if n <= 1 {
        return 0.0;
    }
    opts.length as f64 * (n as f64).log2()
}

/// `log2(C(n, k))`, somando logaritmos.
///
/// Calcular o binomial e depois tirar o log estouraria: `C(94, 47)` passa de
/// 10^27 e nao cabe em `u64`.
fn log2_binomial(n: usize, k: usize) -> f64 {
    if k == 0 || k > n {
        return 0.0;
    }
    (0..k)
        .map(|i| ((n - i) as f64).log2() - ((i + 1) as f64).log2())
        .sum()
}

#[derive(Debug, Clone, Serialize)]
pub struct Strength {
    pub bits: f64,
    /// `weak`, `fair`, `good` ou `strong` — a interface traduz.
    pub label: &'static str,
    /// Problemas encontrados, para o usuario saber o que corrigir.
    pub warnings: Vec<String>,
}

/// Avalia uma senha digitada pelo usuario.
///
/// A estimativa e deliberadamente conservadora e **nao** e um oraculo: medir
/// forca de senha de verdade exigiria comparar contra listas de vazamentos, o
/// que este aplicativo nao faz por ser offline. Serve para pegar o obvio —
/// senha curta, uma classe so, repeticao — e nunca para dar carimbo de
/// aprovacao.
pub fn estimate_strength(password: &str) -> Strength {
    let mut warnings = Vec::new();

    if password.is_empty() {
        return Strength {
            bits: 0.0,
            label: "weak",
            warnings: vec!["senha vazia".into()],
        };
    }

    let chars: Vec<char> = password.chars().collect();
    let mut pool = 0usize;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if chars.iter().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }

    let distintos: std::collections::HashSet<char> = chars.iter().copied().collect();
    let d = distintos.len();

    // Duas estimativas; vale a menor, porque o atacante escolhe o caminho mais
    // barato.
    //
    // A primeira supoe que cada posicao foi sorteada do alfabeto inteiro.
    let bits_alfabeto = chars.len() as f64 * (pool.max(2) as f64).log2();
    //
    // A segunda supoe que o atacante primeiro adivinha *quais* simbolos a senha
    // usa e so depois o arranjo. Para "aaaaaaaaaaaa" isso e escolher uma letra
    // entre 26 e mais nada: cerca de 5 bits, nao os 56 que a primeira formula
    // anunciaria. E o que separa uma senha longa de uma senha longa e burra.
    let bits_simbolos = log2_binomial(pool.max(2), d) + chars.len() as f64 * (d.max(1) as f64).log2();

    let mut bits = bits_alfabeto.min(bits_simbolos);

    if (d as f64 / chars.len() as f64) < 0.5 {
        warnings.push("muitos caracteres repetidos".into());
    }

    // Sequencias triviais de teclado e contagem.
    let lower = password.to_lowercase();
    for padrao in ["1234", "abcd", "qwer", "asdf", "0000", "senha", "password"] {
        if lower.contains(padrao) {
            bits *= 0.6;
            warnings.push(format!("contem a sequencia previsivel \"{padrao}\""));
            break;
        }
    }

    if chars.len() < 12 {
        warnings.push("menos de 12 caracteres".into());
    }
    if pool <= 26 {
        warnings.push("usa um unico tipo de caractere".into());
    }

    let label = match bits {
        b if b < 45.0 => "weak",
        b if b < 70.0 => "fair",
        b if b < 100.0 => "good",
        _ => "strong",
    };

    Strength {
        bits,
        label,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respeita_comprimento_e_alfabeto() {
        let opts = PasswordOptions {
            length: 32,
            ..Default::default()
        };
        let senha = generate(&opts).unwrap();
        assert_eq!(senha.chars().count(), 32);
    }

    #[test]
    fn inclui_pelo_menos_um_de_cada_classe_pedida() {
        let opts = PasswordOptions {
            length: 12,
            ..Default::default()
        };
        // Repete: a garantia tem que valer sempre, nao na media.
        for _ in 0..50 {
            let s = generate(&opts).unwrap();
            assert!(s.chars().any(|c| c.is_ascii_lowercase()), "{}", s.as_str());
            assert!(s.chars().any(|c| c.is_ascii_uppercase()), "{}", s.as_str());
            assert!(s.chars().any(|c| c.is_ascii_digit()), "{}", s.as_str());
            assert!(s.chars().any(|c| !c.is_ascii_alphanumeric()), "{}", s.as_str());
        }
    }

    #[test]
    fn honra_classes_desligadas() {
        let opts = PasswordOptions {
            length: 40,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let s = generate(&opts).unwrap();
        assert!(s.chars().all(|c| c.is_ascii_lowercase()), "{}", s.as_str());
    }

    #[test]
    fn exclui_ambiguos_quando_pedido() {
        let opts = PasswordOptions {
            length: 64,
            exclude_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..20 {
            let s = generate(&opts).unwrap();
            assert!(!s.chars().any(|c| AMBIGUOUS.contains(c)), "{}", s.as_str());
        }
    }

    #[test]
    fn recusa_entrada_invalida() {
        assert!(matches!(
            generate(&PasswordOptions {
                length: 4,
                ..Default::default()
            }),
            Err(GeneratorError::BadLength)
        ));
        assert!(matches!(
            generate(&PasswordOptions {
                length: 16,
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: false,
                exclude_ambiguous: false,
            }),
            Err(GeneratorError::EmptyAlphabet)
        ));
    }

    #[test]
    fn senhas_nao_se_repetem() {
        let opts = PasswordOptions::default();
        let geradas: std::collections::HashSet<String> = (0..200)
            .map(|_| generate(&opts).unwrap().to_string())
            .collect();
        assert_eq!(geradas.len(), 200);
    }

    /// A amostragem com rejeicao precisa distribuir de forma uniforme; com
    /// `% n` enviesado, as primeiras letras apareceriam bem mais.
    #[test]
    fn distribuicao_e_uniforme_o_bastante() {
        let opts = PasswordOptions {
            length: 100,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let mut contagem = [0usize; 26];
        for _ in 0..100 {
            for c in generate(&opts).unwrap().chars() {
                contagem[(c as u8 - b'a') as usize] += 1;
            }
        }
        let total: usize = contagem.iter().sum();
        let esperado = total as f64 / 26.0;
        for (i, &n) in contagem.iter().enumerate() {
            let desvio = (n as f64 - esperado).abs() / esperado;
            assert!(desvio < 0.25, "letra {i}: {n} vs esperado {esperado:.0}");
        }
    }

    #[test]
    fn entropia_acompanha_o_alfabeto() {
        let so_minusculas = PasswordOptions {
            length: 20,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let completo = PasswordOptions {
            length: 20,
            ..Default::default()
        };
        assert!(entropy_bits(&completo) > entropy_bits(&so_minusculas));
        // 20 caracteres em 26 letras ~ 94 bits.
        assert!((entropy_bits(&so_minusculas) - 94.0).abs() < 1.0);
    }

    #[test]
    fn avaliacao_pega_os_casos_obvios() {
        assert_eq!(estimate_strength("").label, "weak");
        assert_eq!(estimate_strength("senha").label, "weak");
        assert_eq!(estimate_strength("aaaaaaaaaaaaaaaaaaaa").label, "weak");

        let fraca = estimate_strength("password1234");
        assert!(fraca.warnings.iter().any(|w| w.contains("previsivel")));

        let forte = estimate_strength(&generate(&PasswordOptions::default()).unwrap());
        assert_eq!(forte.label, "strong");
        assert!(forte.warnings.is_empty(), "{:?}", forte.warnings);
    }

    #[test]
    fn repeticao_e_penalizada_em_relacao_a_variedade() {
        let repetida = estimate_strength("abababababababab");
        let variada = estimate_strength("x7#Kq2!mZr9$Lw4@");
        assert!(variada.bits > repetida.bits);
    }
}
