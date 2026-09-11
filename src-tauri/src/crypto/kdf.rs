//! Derivacao da chave de embrulho (KEK) a partir dos fatores de posse do usuario.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{CryptoError, SecretKey, KEY_LEN};

pub const SALT_LEN: usize = 32;

/// Separador entre senha e keyfile no material de entrada do Argon2id.
///
/// Sem ele, ("senhaX", keyfile "Y") e ("senha", keyfile "XY") concatenariam
/// para o mesmo buffer e abririam o mesmo cofre. O byte 0x1F (unit separator)
/// nao aparece em senhas digitaveis.
const FACTOR_SEPARATOR: u8 = 0x1F;

/// Parametros do Argon2id gravados em claro no header do cofre.
///
/// Ficam no arquivo — e nao fixos no binario — para que um cofre criado hoje
/// continue abrindo depois que os defaults subirem em versoes futuras.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Custo de memoria em KiB.
    pub memory_kib: u32,
    /// Numero de passagens.
    pub iterations: u32,
    /// Pistas paralelas.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 256 MiB e o parametro que carrega a seguranca: obriga o atacante a
        // gastar 256 MiB *por tentativa em paralelo*, o que derruba o ganho de
        // GPU e inviabiliza ASIC. Custa ~1s em CPU de desktop moderna.
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    /// Piso de seguranca aceito na abertura de um cofre.
    ///
    /// Um header adulterado para custo irrisorio e rejeitado aqui, antes de
    /// qualquer trabalho — defesa em profundidade junto com o AAD, que ja
    /// detectaria a adulteracao na tag Poly1305.
    const MIN_MEMORY_KIB: u32 = 16 * 1024; // 16 MiB
    const MIN_ITERATIONS: u32 = 2;
    /// Teto contra um header hostil que peca 64 GiB e derrube a maquina.
    const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024; // 2 GiB

    pub fn validate(&self) -> Result<(), CryptoError> {
        let ok = self.memory_kib >= Self::MIN_MEMORY_KIB
            && self.memory_kib <= Self::MAX_MEMORY_KIB
            && self.iterations >= Self::MIN_ITERATIONS
            && self.iterations <= 32
            && self.parallelism >= 1
            && self.parallelism <= 16;
        if ok {
            Ok(())
        } else {
            Err(CryptoError::BadKdfParams)
        }
    }
}

/// Fatores que o usuario apresenta para destrancar o cofre.
///
/// O TOTP nao entra aqui de proposito: e um gate de aplicacao, verificado
/// depois que o cofre abre. Nao ha como derivar chave de um codigo de 6
/// digitos — o espaco de 10^6 cai em milissegundos. Quem quiser um segundo
/// fator que realmente entre na chave usa o keyfile de audio.
pub struct UnlockFactors<'a> {
    pub password: &'a str,
    /// BLAKE3 do PCM do keyfile de audio, quando o cofre exige um.
    pub keyfile_digest: Option<[u8; 32]>,
}

impl<'a> UnlockFactors<'a> {
    /// Monta o buffer de entrada do Argon2id, zerado no fim do escopo.
    fn material(&self) -> Zeroizing<Vec<u8>> {
        let pw = self.password.as_bytes();
        let mut buf = Vec::with_capacity(pw.len() + 1 + 32);
        buf.extend_from_slice(pw);
        if let Some(digest) = &self.keyfile_digest {
            buf.push(FACTOR_SEPARATOR);
            buf.extend_from_slice(digest);
        }
        Zeroizing::new(buf)
    }
}

/// Deriva a chave de embrulho (KEK) a partir dos fatores e do salt do cofre.
pub fn derive_kek(
    factors: &UnlockFactors<'_>,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    params.validate()?;

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let material = factors.material();
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(&material, salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    // `out` foi copiado para dentro de SecretKey, que zera no drop; zeramos a
    // copia da pilha aqui para nao deixar o material em dois lugares.
    let key = SecretKey::from_bytes(out);
    use zeroize::Zeroize;
    out.zeroize();
    Ok(key)
}

/// Sorteia um salt novo para um cofre recem-criado.
pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    super::random_array::<SALT_LEN>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parametros baratos: os testes exercitam a logica, nao o custo.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 16 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn mesma_entrada_deriva_mesma_chave() {
        let salt = [7u8; SALT_LEN];
        let f = UnlockFactors {
            password: "correct horse battery staple",
            keyfile_digest: None,
        };
        let a = derive_kek(&f, &salt, fast()).unwrap();
        let b = derive_kek(&f, &salt, fast()).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn keyfile_muda_a_chave() {
        let salt = [7u8; SALT_LEN];
        let sem = UnlockFactors {
            password: "senha",
            keyfile_digest: None,
        };
        let com = UnlockFactors {
            password: "senha",
            keyfile_digest: Some([42u8; 32]),
        };
        assert_ne!(
            derive_kek(&sem, &salt, fast()).unwrap().expose(),
            derive_kek(&com, &salt, fast()).unwrap().expose()
        );
    }

    /// O separador impede que mover bytes da fronteira senha/keyfile colida.
    #[test]
    fn fronteira_senha_keyfile_nao_colide() {
        let salt = [7u8; SALT_LEN];
        let mut digest_a = [0u8; 32];
        digest_a[0] = b'A';
        let a = UnlockFactors {
            password: "senha",
            keyfile_digest: Some(digest_a),
        };
        let b = UnlockFactors {
            password: "senhaA",
            keyfile_digest: Some([0u8; 32]),
        };
        assert_ne!(
            derive_kek(&a, &salt, fast()).unwrap().expose(),
            derive_kek(&b, &salt, fast()).unwrap().expose()
        );
    }

    #[test]
    fn salt_diferente_muda_a_chave() {
        let f = UnlockFactors {
            password: "senha",
            keyfile_digest: None,
        };
        assert_ne!(
            derive_kek(&f, &[1u8; SALT_LEN], fast()).unwrap().expose(),
            derive_kek(&f, &[2u8; SALT_LEN], fast()).unwrap().expose()
        );
    }

    #[test]
    fn rejeita_parametros_enfraquecidos() {
        let fraco = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        assert!(fraco.validate().is_err());
        assert!(KdfParams::default().validate().is_ok());
    }
}
