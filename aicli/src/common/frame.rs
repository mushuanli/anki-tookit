// src/common/frame.rs

use crate::common::types::PacketType;
use crate::error::{AppError, Result};
use tokio::io::{AsyncReadExt};

#[derive(Debug)]
pub struct Frame {
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Option<Frame>> {
    let mut type_buf = [0u8; 1];
    if stream.read_exact(&mut type_buf).await.is_err() {
        return Ok(None); // Clean disconnect
    }

    let packet_type = PacketType::from_u8(type_buf[0])
        .ok_or_else(|| AppError::ParseError(format!("Invalid packet type: {}", type_buf[0])))?;

    let len = stream.read_u32().await?;
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;

    Ok(Some(Frame { packet_type, payload }))
}

pub fn encode_frame(packet_type: PacketType, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(packet_type as u8);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/*
// In src/common/types.rs
impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        // ... (implementation from server/handler.rs)
        // This should be public now.
    }
}
 */
