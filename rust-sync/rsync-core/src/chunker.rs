// file: rustSync/rsync-core/src/chunker.rs
use fastcdc::v2020::FastCDC;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub offset: u64,
    pub length: u32,
    pub hash: String,
}

/// 对数据进行 CDC 分片并计算 Hash
/// min_size: 最小分片大小 (推荐 8KB)
/// avg_size: 平均分片大小 (推荐 16KB)
/// max_size: 最大分片大小 (推荐 64KB)
pub fn generate_chunks(data: &[u8]) -> (String, Vec<FileChunk>) {
    let mut chunks = Vec::new();
    let mut hasher = blake3::Hasher::new();
    
    // 计算全量文件 Hash
    hasher.update(data);
    let full_hash = hasher.finalize().to_hex().to_string();

    // 计算分片
    // 8KB min, 16KB avg, 64KB max
    let chunker = FastCDC::new(data, 8192, 16384, 65536);

    for entry in chunker {
        let chunk_data = &data[entry.offset..entry.offset + entry.length];
        let chunk_hash = blake3::hash(chunk_data).to_hex().to_string();

        chunks.push(FileChunk {
            offset: entry.offset as u64,
            length: entry.length as u32,
            hash: chunk_hash,
        });
    }

    (full_hash, chunks)
}
