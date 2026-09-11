//! Autenticacao: como o usuario prova que pode abrir o cofre.
//!
//! Os tres mecanismos operam em camadas bem diferentes, e vale ter isso claro:
//!
//! | Mecanismo        | Entra na chave? | Protege contra                      |
//! |------------------|-----------------|-------------------------------------|
//! | Senha mestra     | sim, via KDF    | qualquer um sem a senha             |
//! | Keyfile de audio | sim, via KDF    | quem tem a senha mas nao o arquivo  |
//! | TOTP             | nao             | acesso oportunista a esta instalacao|
//! | Windows Hello    | caminho paralelo| conveniencia nesta maquina          |
//!
//! Somente os dois primeiros mudam o que um atacante de posse do arquivo
//! precisa quebrar. Os outros dois valem pelo que valem — e a interface diz
//! isso ao usuario em vez de sugerir seguranca que nao existe.

pub mod hello;
pub mod totp;

pub use hello::HelloError;
pub use totp::TotpError;
