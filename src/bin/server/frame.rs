use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Write a framed packet (type + LE32 length + payload) to an async writer.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, ftype: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[ftype]).await?;
    let len: u32 = payload.len().try_into().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload too large"))?;
    w.write_all(&len.to_le_bytes()).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    w.flush().await?;
    Ok(())
}

/// Serialize a value as JSON and send it as a framed packet.
pub async fn write_json_frame<W: AsyncWriteExt + Unpin>(w: &mut W, ftype: u8, val: &impl serde::Serialize) -> std::io::Result<()> {
    let json = serde_json::to_string(val).unwrap_or_default();
    write_frame(w, ftype, json.as_bytes()).await
}

/// Read a framed packet (type + LE32 length + payload) from an async reader.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;
    let ftype = header[0];
    let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((ftype, payload))
}

/// Hex-encode bytes to a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    unsafe { String::from_utf8_unchecked(out) }
}
