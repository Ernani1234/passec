//! Utilidades pequenas compartilhadas entre os modulos.

/// Codifica bytes em hexadecimal minusculo.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodifica hexadecimal, aceitando maiusculas.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Le um u32 big-endian e avanca o cursor.
pub fn read_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let slice = bytes.get(*cursor..*cursor + 4)?;
    *cursor += 4;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

/// Le um bloco prefixado por tamanho, recusando tamanhos que nao cabem no
/// arquivo — um cabecalho hostil nao deve conseguir provocar alocacao enorme.
pub fn read_chunk<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32(bytes, cursor)? as usize;
    if len > bytes.len() - *cursor {
        return None;
    }
    let slice = bytes.get(*cursor..*cursor + len)?;
    *cursor += len;
    Some(slice)
}

/// Escreve um bloco prefixado por tamanho.
pub fn write_chunk(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ida_e_volta() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(to_hex(&bytes), "000fa5ff");
        assert_eq!(from_hex("000fa5ff").unwrap(), bytes);
        assert_eq!(from_hex("000FA5FF").unwrap(), bytes);
    }

    #[test]
    fn hex_invalido_devolve_none() {
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }

    #[test]
    fn chunks_ida_e_volta() {
        let mut buf = Vec::new();
        write_chunk(&mut buf, b"primeiro");
        write_chunk(&mut buf, b"segundo");
        let mut c = 0;
        assert_eq!(read_chunk(&buf, &mut c).unwrap(), b"primeiro");
        assert_eq!(read_chunk(&buf, &mut c).unwrap(), b"segundo");
        assert!(read_chunk(&buf, &mut c).is_none());
    }

    #[test]
    fn tamanho_mentiroso_nao_estoura() {
        // Arquivo diz conter 4 GB e tem 4 bytes.
        let buf = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut c = 0;
        assert!(read_chunk(&buf, &mut c).is_none());
    }
}
