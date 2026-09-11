//! Windows Hello — destranca o cofre com digital ou rosto.
//!
//! # Como a biometria vira chave
//!
//! Digital nao e senha: o Windows nunca entrega a leitura biometrica para o
//! aplicativo, e nem deveria. O que ele oferece e um par de chaves RSA gerado
//! dentro do TPM, cuja chave privada so pode ser usada depois que o usuario se
//! autentica no gesto do Hello.
//!
//! O PASSEC usa isso assim:
//!
//! 1. No cadastro, sorteia um `challenge` de 32 bytes e o guarda em claro no
//!    cofre — ele nao e segredo, e so um valor fixo para assinar.
//! 2. Pede ao TPM a assinatura desse challenge. A assinatura so sai depois do
//!    gesto biometrico.
//! 3. Deriva uma chave da assinatura e sela a VaultKey com ela.
//!
//! Para reabrir, repete o passo 2: o TPM devolve a mesma assinatura, a mesma
//! chave sai dela, e a VaultKey se abre. A chave privada nunca deixa o TPM e o
//! blob so funciona naquela maquina — trocar de PC exige a senha mestra, que
//! continua sendo o caminho principal e o unico backup.
//!
//! # A armadilha do determinismo
//!
//! Tudo isso depende de `RequestSignAsync` devolver **sempre a mesma
//! assinatura** para a mesma entrada. Isso vale para RSASSA-PKCS1-v1_5, que e
//! o que o Hello usa hoje; nao valeria para RSA-PSS, que injeta sal aleatorio
//! em cada assinatura. Como isso e detalhe de implementacao da plataforma e
//! nao contrato documentado, [`enroll`] assina duas vezes e compara antes de
//! gravar qualquer coisa. Se as assinaturas divergirem, o cadastro e recusado
//! com uma explicacao — melhor falhar na hora de ligar do que descobrir na
//! proxima vez que o usuario precisar entrar.

use crate::crypto::{aead, domain, random_array, SecretKey};

/// Nome da credencial no cofre de chaves do Windows.
const CREDENTIAL_NAME: &str = "PASSEC.vault.v1";
const CHALLENGE_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    #[error("Windows Hello nao esta disponivel nesta maquina")]
    Unavailable,
    #[error("o gesto do Windows Hello foi cancelado")]
    Cancelled,
    #[error("credencial do PASSEC nao encontrada — refaca o cadastro do Hello")]
    NotEnrolled,
    #[error("Windows Hello: {0}")]
    Platform(String),
    #[error("a assinatura do Windows Hello nao e reproduzivel nesta maquina, entao ela nao serve para derivar chave; use a senha mestra")]
    NonDeterministic,
    #[error("dados do Windows Hello corrompidos no cofre")]
    CorruptBlob,
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// Deriva a chave de embrulho a partir da assinatura do TPM.
fn key_from_signature(signature: &[u8]) -> SecretKey {
    SecretKey::from_bytes(blake3::derive_key(domain::HELLO_WRAP, signature))
}

/// Monta o blob gravado no cofre: `challenge || VaultKey selada`.
fn build_blob(challenge: &[u8; CHALLENGE_LEN], sealed: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(CHALLENGE_LEN + sealed.len());
    blob.extend_from_slice(challenge);
    blob.extend_from_slice(sealed);
    blob
}

fn split_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), HelloError> {
    if blob.len() <= CHALLENGE_LEN {
        return Err(HelloError::CorruptBlob);
    }
    Ok(blob.split_at(CHALLENGE_LEN))
}

#[cfg(windows)]
mod platform {
    use super::{HelloError, CREDENTIAL_NAME};
    use windows::core::HSTRING;
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Storage::Streams::{DataReader, IBuffer};

    fn map_status(status: KeyCredentialStatus) -> HelloError {
        match status {
            KeyCredentialStatus::UserCanceled => HelloError::Cancelled,
            KeyCredentialStatus::NotFound => HelloError::NotEnrolled,
            KeyCredentialStatus::UserPrefersPassword => HelloError::Cancelled,
            KeyCredentialStatus::SecurityDeviceLocked => {
                HelloError::Platform("dispositivo de seguranca bloqueado".into())
            }
            KeyCredentialStatus::UnknownError => {
                HelloError::Platform("erro desconhecido do Hello".into())
            }
            _ => HelloError::Platform(format!("status {:?}", status.0)),
        }
    }

    fn buffer_to_vec(buffer: &IBuffer) -> Result<Vec<u8>, HelloError> {
        let len = buffer
            .Length()
            .map_err(|e| HelloError::Platform(e.to_string()))? as usize;
        let reader =
            DataReader::FromBuffer(buffer).map_err(|e| HelloError::Platform(e.to_string()))?;
        let mut bytes = vec![0u8; len];
        reader
            .ReadBytes(&mut bytes)
            .map_err(|e| HelloError::Platform(e.to_string()))?;
        Ok(bytes)
    }

    pub fn is_available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.get())
            .unwrap_or(false)
    }

    /// Assina `challenge` com a credencial, criando-a se `create` for `true`.
    ///
    /// Dispara o gesto biometrico do Windows.
    pub fn sign(challenge: &[u8], create: bool) -> Result<Vec<u8>, HelloError> {
        if !is_available() {
            return Err(HelloError::Unavailable);
        }
        let name = HSTRING::from(CREDENTIAL_NAME);

        let result = if create {
            KeyCredentialManager::RequestCreateAsync(
                &name,
                // O cadastro e explicito do usuario; substituir garante que
                // um cadastro antigo e orfao nao bloqueie o novo.
                KeyCredentialCreationOption::ReplaceExisting,
            )
        } else {
            KeyCredentialManager::OpenAsync(&name)
        }
        .map_err(|e| HelloError::Platform(e.to_string()))?
        .get()
        .map_err(|e| HelloError::Platform(e.to_string()))?;

        let status = result
            .Status()
            .map_err(|e| HelloError::Platform(e.to_string()))?;
        if status != KeyCredentialStatus::Success {
            return Err(map_status(status));
        }

        let credential = result
            .Credential()
            .map_err(|e| HelloError::Platform(e.to_string()))?;

        let input = CryptographicBuffer::CreateFromByteArray(challenge)
            .map_err(|e| HelloError::Platform(e.to_string()))?;

        let op = credential
            .RequestSignAsync(&input)
            .map_err(|e| HelloError::Platform(e.to_string()))?
            .get()
            .map_err(|e| HelloError::Platform(e.to_string()))?;

        let op_status = op
            .Status()
            .map_err(|e| HelloError::Platform(e.to_string()))?;
        if op_status != KeyCredentialStatus::Success {
            return Err(map_status(op_status));
        }

        let signature = op
            .Result()
            .map_err(|e| HelloError::Platform(e.to_string()))?;
        buffer_to_vec(&signature)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::HelloError;

    pub fn is_available() -> bool {
        false
    }

    pub fn sign(_challenge: &[u8], _create: bool) -> Result<Vec<u8>, HelloError> {
        Err(HelloError::Unavailable)
    }
}

/// `true` se a maquina tem Windows Hello configurado.
pub fn is_available() -> bool {
    platform::is_available()
}

/// Cadastra o Hello para este cofre e devolve o blob a ser gravado.
///
/// Pede o gesto biometrico duas vezes: a segunda confirma que a assinatura e
/// reproduzivel, sem o que a chave derivada seria diferente a cada acesso.
pub fn enroll(vault_key: &SecretKey) -> Result<Vec<u8>, HelloError> {
    let challenge = random_array::<CHALLENGE_LEN>()?;

    let first = platform::sign(&challenge, true)?;
    let second = platform::sign(&challenge, false)?;

    use subtle::ConstantTimeEq;
    let iguais: bool = (first.len() == second.len())
        && bool::from(first.ct_eq(&second));
    if !iguais {
        return Err(HelloError::NonDeterministic);
    }

    let wrap_key = key_from_signature(&first);
    // O challenge entra como AAD: o blob so abre com o challenge com que foi
    // criado, mesmo que alguem troque os 32 primeiros bytes do arquivo.
    let sealed = aead::seal(&wrap_key, vault_key.expose(), &challenge)?;
    Ok(build_blob(&challenge, &sealed))
}

/// Recupera a VaultKey a partir do blob, mediante o gesto do Hello.
pub fn unlock(blob: &[u8]) -> Result<SecretKey, HelloError> {
    let (challenge, sealed) = split_blob(blob)?;
    let signature = platform::sign(challenge, false)?;
    let wrap_key = key_from_signature(&signature);

    let plain = aead::open(&wrap_key, sealed, challenge)?;
    let arr: [u8; 32] = plain.as_slice().try_into().map_err(|_| HelloError::CorruptBlob)?;
    Ok(SecretKey::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O ciclo completo exige o TPM e o gesto do usuario, que nao existem no
    /// CI. O que da para testar sem hardware e a montagem do blob e a
    /// derivacao — ambas puras.
    #[test]
    fn blob_ida_e_volta_com_assinatura_simulada() {
        let vault_key = SecretKey::from_bytes([7u8; 32]);
        let challenge = [3u8; CHALLENGE_LEN];
        let assinatura_falsa = b"assinatura-reproduzivel-do-tpm";

        let wrap = key_from_signature(assinatura_falsa);
        let sealed = aead::seal(&wrap, vault_key.expose(), &challenge).unwrap();
        let blob = build_blob(&challenge, &sealed);

        let (c, s) = split_blob(&blob).unwrap();
        assert_eq!(c, &challenge);

        let recuperada = aead::open(&key_from_signature(assinatura_falsa), s, c).unwrap();
        assert_eq!(recuperada.as_slice(), vault_key.expose());
    }

    #[test]
    fn assinatura_diferente_nao_abre_o_blob() {
        let vault_key = SecretKey::from_bytes([7u8; 32]);
        let challenge = [3u8; CHALLENGE_LEN];
        let wrap = key_from_signature(b"assinatura-A");
        let sealed = aead::seal(&wrap, vault_key.expose(), &challenge).unwrap();

        let outra = key_from_signature(b"assinatura-B");
        assert!(aead::open(&outra, &sealed, &challenge).is_err());
    }

    /// Trocar o challenge no arquivo tem que invalidar o blob.
    #[test]
    fn challenge_adulterado_invalida() {
        let vault_key = SecretKey::from_bytes([7u8; 32]);
        let challenge = [3u8; CHALLENGE_LEN];
        let wrap = key_from_signature(b"sig");
        let sealed = aead::seal(&wrap, vault_key.expose(), &challenge).unwrap();

        let outro = [4u8; CHALLENGE_LEN];
        assert!(aead::open(&key_from_signature(b"sig"), &sealed, &outro).is_err());
    }

    #[test]
    fn blob_curto_e_recusado() {
        assert!(split_blob(&[]).is_err());
        assert!(split_blob(&[0u8; CHALLENGE_LEN]).is_err());
        assert!(matches!(
            unlock(&[0u8; 4]),
            Err(HelloError::CorruptBlob)
        ));
    }

    #[test]
    fn derivacao_e_deterministica_e_separa_dominios() {
        let a = key_from_signature(b"mesma-assinatura");
        let b = key_from_signature(b"mesma-assinatura");
        assert_eq!(a.expose(), b.expose());
        assert_ne!(
            a.expose(),
            &blake3::derive_key("outro.dominio", b"mesma-assinatura")
        );
    }
}
