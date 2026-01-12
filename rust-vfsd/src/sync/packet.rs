// src/sync/packet.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    
    #[serde(rename = "chunk_header")]
    ChunkHeader {
        req_id: String,
        content_hash: String,
        index: i32,
        total_chunks: i32,
        checksum: String,
        size: i64,
    },
    
    #[serde(rename = "chunk_data")]
    ChunkData {
        req_id: String,
        data: Vec<u8>,
    },
}
