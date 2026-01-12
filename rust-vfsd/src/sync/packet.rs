// src/sync/packet.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
//use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::models::{ChunkReference, SyncChange};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineContent {
    pub data: String,           // Base64 encoded
    pub encoding: String,       // "base64"
    pub original_size: i64,
    pub compressed: bool,
    pub compression_algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPacket {
    pub packet_id: String,
    pub peer_id: String,        // device_id
    pub module_id: String,
    pub timestamp: i64,
    pub changes: Vec<SyncChange>,
    pub inline_contents: Option<HashMap<String, InlineContent>>,
    pub chunk_refs: Option<Vec<ChunkReference>>,
    pub compression: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPacketResponse {
    pub success: bool,
    pub processed_count: usize,
    pub missing_chunks: Option<Vec<String>>,
    pub conflicts: Option<Vec<String>>,
    pub error: Option<String>,
}

/// WebSocket 消息枚举
/// 使用 tag = "type" 与客户端保持一致
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "ping")]
    Ping { timestamp: i64 },
    
    #[serde(rename = "pong")]
    Pong { timestamp: i64 },
    
    #[serde(rename = "sync_packet")]
    SyncPacket { 
        req_id: String, 
        payload: SyncPacket 
    },
    
    #[serde(rename = "ack")]
    Ack { 
        req_id: String, 
        response: SyncPacketResponse 
    },
    
    #[serde(rename = "error")]
    Error { 
        req_id: Option<String>, 
        message: String 
    },
    
    #[serde(rename = "request_chunk")]
    RequestChunk {
        req_id: String,
        content_hash: String,
        index: i32,
        node_id: String,
    },
    
    /// 分片头信息（JSON）
    /// 发送后紧跟一个二进制帧
    #[serde(rename = "chunk_header")]
    ChunkHeader {
        req_id: String,
        content_hash: String,
        index: i32,
        total_chunks: i32,
        checksum: String,
        size: i64,
    },
    
    /// 分片响应头（服务端响应分片请求时使用）
    /// 发送后紧跟一个二进制帧
    #[serde(rename = "chunk_response")]
    ChunkResponse {
        req_id: String,
        content_hash: String,
        index: i32,
        total_chunks: i32,
        checksum: String,
        size: i64,
    },
    
    /// 分片上传请求头（客户端上传分片时使用）
    #[serde(rename = "chunk_upload")]
    ChunkUpload {
        req_id: String,
        content_hash: String,
        index: i32,
        total_chunks: i32,
        checksum: String,
        size: i64,
        node_id: String,
    },
    
    /// 分片上传确认
    #[serde(rename = "chunk_ack")]
    ChunkAck {
        req_id: String,
        content_hash: String,
        index: i32,
        success: bool,
        error: Option<String>,
    },
}

/// 用于发送二进制数据的包装
/// 注意：这不是 WsMessage 的一部分，而是用于内部处理
#[derive(Debug, Clone)]
pub enum OutgoingMessage {
    Json(WsMessage),
    Binary(Vec<u8>),
}
