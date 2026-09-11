//! Cliente da Contents API do GitHub.
//!
//! O cofre vive como um arquivo comum num repositorio **privado**. Cada escrita
//! vira um commit, o que da versionamento e historico de graca: recuperar o
//! cofre de duas semanas atras e navegar pelo historico do arquivo.
//!
//! Usamos a Contents API em vez de chamar o `git`: assim o aplicativo funciona
//! num computador que nao tem git instalado, e nao ha diretorio de trabalho,
//! indice nem merge do git para administrar — o merge acontece no nivel dos
//! itens do cofre, que e onde ele faz sentido.
//!
//! # O que o GitHub ve
//!
//! Bytes cifrados. O repositorio guarda o mesmo blob XChaCha20-Poly1305 que
//! estaria no disco, entao a confidencialidade nao depende do GitHub — apenas
//! a disponibilidade. Ainda assim o repositorio deve ser privado: publica-lo
//! entregaria ao mundo um alvo para forca bruta offline sobre a senha mestra.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Deserialize;

const API: &str = "https://api.github.com";
const USER_AGENT: &str = "PASSEC/0.1";
const API_VERSION: &str = "2022-11-28";

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("token do GitHub invalido ou expirado")]
    Unauthorized,

    #[error("o token nao tem permissao de escrita neste repositorio (precisa do escopo Contents: read and write)")]
    Forbidden,

    #[error("repositorio ou caminho nao encontrado — confira dono, nome e se o token enxerga repositorios privados")]
    NotFound,

    #[error("o cofre remoto mudou desde a ultima leitura; sincronize de novo")]
    Conflict,

    #[error("o GitHub recusou a requisicao: {0}")]
    Api(String),

    #[error("falha de rede: {0}")]
    Network(String),

    #[error("resposta do GitHub em formato inesperado: {0}")]
    Malformed(String),

    #[error("arquivo remoto grande demais para a Contents API")]
    TooLarge,
}

/// Arquivo lido do repositorio.
pub struct RemoteFile {
    pub bytes: Vec<u8>,
    /// Identificador da versao. O GitHub exige devolve-lo na escrita, e recusa
    /// se nao corresponder mais — e o que impede sobrescrever cegamente o
    /// trabalho de outro computador.
    pub sha: String,
}

/// Credenciais e localizacao do cofre remoto.
#[derive(Debug, Clone)]
pub struct Repo {
    pub owner: String,
    pub repo: String,
    pub path: String,
    pub token: String,
}

impl Repo {
    fn contents_url(&self) -> String {
        format!(
            "{API}/repos/{}/{}/contents/{}",
            self.owner.trim(),
            self.repo.trim(),
            self.path.trim().trim_start_matches('/')
        )
    }

    fn repo_url(&self) -> String {
        format!("{API}/repos/{}/{}", self.owner.trim(), self.repo.trim())
    }

    /// Erros de digitacao aqui viram 404 confuso; melhor pegar antes.
    pub fn validate(&self) -> Result<(), GithubError> {
        let vazio = self.owner.trim().is_empty()
            || self.repo.trim().is_empty()
            || self.path.trim().is_empty()
            || self.token.trim().is_empty();
        if vazio {
            return Err(GithubError::Api(
                "preencha dono, repositorio, caminho e token".into(),
            ));
        }
        if self.owner.contains('/') || self.repo.contains('/') {
            return Err(GithubError::Api(
                "dono e repositorio sao campos separados; nao use barra".into(),
            ));
        }
        Ok(())
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
}

fn autenticar(req: ureq::Request, token: &str) -> ureq::Request {
    req.set("Authorization", &format!("Bearer {}", token.trim()))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", API_VERSION)
        .set("User-Agent", USER_AGENT)
}

/// Traduz o erro do ureq para algo que o usuario possa agir.
fn traduzir(e: ureq::Error) -> GithubError {
    match e {
        ureq::Error::Status(401, _) => GithubError::Unauthorized,
        ureq::Error::Status(403, resp) => {
            // 403 tambem e usado para limite de requisicoes; a distincao
            // importa porque uma se resolve esperando e a outra nao.
            let corpo = resp.into_string().unwrap_or_default();
            if corpo.contains("rate limit") {
                GithubError::Api("limite de requisicoes do GitHub atingido; tente em alguns minutos".into())
            } else {
                GithubError::Forbidden
            }
        }
        ureq::Error::Status(404, _) => GithubError::NotFound,
        ureq::Error::Status(409, _) | ureq::Error::Status(422, _) => GithubError::Conflict,
        ureq::Error::Status(code, resp) => {
            let corpo = resp.into_string().unwrap_or_default();
            let msg = extrair_mensagem(&corpo).unwrap_or_else(|| corpo.chars().take(200).collect());
            GithubError::Api(format!("HTTP {code}: {msg}"))
        }
        ureq::Error::Transport(t) => GithubError::Network(t.to_string()),
    }
}

/// O GitHub devolve `{"message": "..."}` nos erros.
fn extrair_mensagem(corpo: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Erro {
        message: String,
    }
    serde_json::from_str::<Erro>(corpo).ok().map(|e| e.message)
}

#[derive(Deserialize)]
struct ContentsResponse {
    content: Option<String>,
    sha: String,
    encoding: Option<String>,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize)]
struct PutResponse {
    content: PutContent,
}

#[derive(Deserialize)]
struct PutContent {
    sha: String,
}

/// Confere que o token enxerga o repositorio e que ele e privado.
///
/// Devolve `true` se o repositorio for privado. A interface avisa em vez de
/// recusar: publicar o cofre e uma decisao ruim, mas e do usuario.
pub fn check_access(repo: &Repo) -> Result<bool, GithubError> {
    repo.validate()?;

    #[derive(Deserialize)]
    struct RepoInfo {
        private: bool,
        permissions: Option<Permissions>,
    }
    #[derive(Deserialize)]
    struct Permissions {
        push: bool,
    }

    let resp = autenticar(agent().get(&repo.repo_url()), &repo.token)
        .call()
        .map_err(traduzir)?;

    let info: RepoInfo = resp
        .into_json()
        .map_err(|e| GithubError::Malformed(e.to_string()))?;

    if let Some(p) = &info.permissions {
        if !p.push {
            return Err(GithubError::Forbidden);
        }
    }
    Ok(info.private)
}

/// Le o cofre remoto. `Ok(None)` significa que o arquivo ainda nao existe.
pub fn fetch(repo: &Repo) -> Result<Option<RemoteFile>, GithubError> {
    repo.validate()?;

    let resp = match autenticar(agent().get(&repo.contents_url()), &repo.token).call() {
        Ok(r) => r,
        // Um arquivo ausente e estado normal na primeira sincronizacao, nao
        // erro — mas um repositorio ausente tambem devolve 404. A distincao e
        // feita por quem chama, que ja validou o acesso ao repositorio.
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(e) => return Err(traduzir(e)),
    };

    let body: ContentsResponse = resp
        .into_json()
        .map_err(|e| GithubError::Malformed(e.to_string()))?;

    // Acima de 1 MB a Contents API devolve metadados sem conteudo. Um cofre
    // passar disso seria muito atipico, mas falhar claro e melhor que devolver
    // um arquivo vazio.
    let conteudo = match (&body.content, body.encoding.as_deref()) {
        (Some(c), Some("base64")) if !c.trim().is_empty() => c,
        _ if body.size > 1_000_000 => return Err(GithubError::TooLarge),
        _ => {
            return Err(GithubError::Malformed(
                "o GitHub nao devolveu o conteudo do arquivo".into(),
            ))
        }
    };

    // O base64 vem quebrado em linhas de 60 caracteres.
    let limpo: String = conteudo.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = B64
        .decode(limpo)
        .map_err(|e| GithubError::Malformed(format!("base64 invalido: {e}")))?;

    Ok(Some(RemoteFile {
        bytes,
        sha: body.sha,
    }))
}

/// Grava o cofre remoto e devolve o `sha` da nova versao.
///
/// `sha_anterior` precisa ser o da versao que foi lida. Se o arquivo mudou
/// nesse meio tempo, o GitHub recusa e devolvemos [`GithubError::Conflict`] —
/// e isso e uma defesa, nao um estorvo: sem ela, dois computadores salvando ao
/// mesmo tempo perderiam o trabalho de um deles.
pub fn put(
    repo: &Repo,
    bytes: &[u8],
    sha_anterior: Option<&str>,
    mensagem: &str,
) -> Result<String, GithubError> {
    repo.validate()?;

    let mut corpo = serde_json::json!({
        "message": mensagem,
        "content": B64.encode(bytes),
    });
    if let Some(sha) = sha_anterior.filter(|s| !s.is_empty()) {
        corpo["sha"] = serde_json::Value::String(sha.to_string());
    }

    let resp = autenticar(agent().put(&repo.contents_url()), &repo.token)
        .send_json(corpo)
        .map_err(traduzir)?;

    let body: PutResponse = resp
        .into_json()
        .map_err(|e| GithubError::Malformed(e.to_string()))?;

    Ok(body.content.sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> Repo {
        Repo {
            owner: "Ernani1234".into(),
            repo: "passec-vault".into(),
            path: "passec.vault".into(),
            token: "ghp_exemplo".into(),
        }
    }

    #[test]
    fn monta_as_urls_certas() {
        let r = repo();
        assert_eq!(
            r.contents_url(),
            "https://api.github.com/repos/Ernani1234/passec-vault/contents/passec.vault"
        );
        assert_eq!(
            r.repo_url(),
            "https://api.github.com/repos/Ernani1234/passec-vault"
        );
    }

    /// Barra sobrando no caminho geraria `contents//arquivo`, que o GitHub
    /// rejeita com um 404 sem explicacao.
    #[test]
    fn normaliza_barra_inicial_do_caminho() {
        let mut r = repo();
        r.path = "/cofres/passec.vault".into();
        assert!(r.contents_url().ends_with("/contents/cofres/passec.vault"));
    }

    #[test]
    fn recusa_configuracao_incompleta() {
        let mut r = repo();
        r.token = "  ".into();
        assert!(r.validate().is_err());

        let mut r = repo();
        r.owner = "".into();
        assert!(r.validate().is_err());
    }

    /// Erro comum: colar "usuario/repo" no campo do dono.
    #[test]
    fn recusa_dono_com_barra() {
        let mut r = repo();
        r.owner = "Ernani1234/passec-vault".into();
        let msg = r.validate().unwrap_err().to_string();
        assert!(msg.contains("barra"), "mensagem inesperada: {msg}");
    }

    #[test]
    fn extrai_mensagem_de_erro_do_github() {
        let corpo = r#"{"message":"Bad credentials","documentation_url":"https://docs.github.com"}"#;
        assert_eq!(extrair_mensagem(corpo).as_deref(), Some("Bad credentials"));
        assert!(extrair_mensagem("nao e json").is_none());
    }

    #[test]
    fn base64_com_quebras_de_linha_e_aceito() {
        let original = b"conteudo do cofre";
        let codificado = B64.encode(original);
        // A API quebra em linhas; simulamos isso.
        let com_quebras = format!("{}\n{}\n", &codificado[..4], &codificado[4..]);
        let limpo: String = com_quebras.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(B64.decode(limpo).unwrap(), original);
    }
}
