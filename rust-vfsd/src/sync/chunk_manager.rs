// src/sync/chunk_manager.rs

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

use crate::config::StorageConfig;
use crate::error::{AppError, AppResult};
use crate::models::FileChunk;
use crate::storage::Database;

pub struct ChunkManager {
    storage_path: PathBuf,
    chunk_size: usize,
    db: Database,
}

impl ChunkManager {
    pub fn new(config: &StorageConfig, chunk_size: usize, db: Database) -> Self {
        let storage_path = config
            .local_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./data/chunks"));

        Self {
            storage_path,
            chunk_size,
            db,
        }
    }

    /// 存储分片
    pub async fn store_chunk(
        &self,
        user_id: Uuid,
        content_hash: &str,
        index: i32,
        total_chunks: i32,
        data: &[u8],
        checksum: &str,
    ) -> AppResult<FileChunk> {
        // 验证校验和
        let actual_checksum = self.calculate_checksum(data);
        if actual_checksum != checksum {
            return Err(AppError::ValidationError(format!(
                "Checksum mismatch: expected {}, got {}",
                checksum, actual_checksum
            )));
        }

        // 创建存储路径
        let chunk_id = format!("{}_{}", content_hash, index);
        let storage_path = self.get_chunk_path(user_id, content_hash, index);

        // 确保目录存在
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                AppError::InternalError(format!("Failed to create directory: {}", e))
            })?;
        }

        // 写入文件
        fs::write(&storage_path, data).await.map_err(|e| {
            AppError::InternalError(format!("Failed to write chunk: {}", e))
        })?;

        // 保存到数据库
        let chunk = FileChunk {
            id: chunk_id,
            user_id,
            content_hash: content_hash.to_string(),
            chunk_index: index,
            total_chunks,
            size: data.len() as i64,
            checksum: checksum.to_string(),
            storage_path: storage_path.to_string_lossy().to_string(),
            created_at: chrono::Utc::now(),
        };

        self.db.save_chunk(&chunk).await?;

        Ok(chunk)
    }

    /// 获取分片
    pub async fn get_chunk(
        &self,
        user_id: Uuid,
        content_hash: &str,
        index: i32,
    ) -> AppResult<Vec<u8>> {
        let chunk = self.db.get_chunk(user_id, content_hash, index).await?;

        match chunk {
            Some(c) => {
                let data = fs::read(&c.storage_path).await.map_err(|e| {
                    AppError::InternalError(format!("Failed to read chunk: {}", e))
                })?;
                Ok(data)
            }
            None => Err(AppError::NotFound(format!(
                "Chunk not found: {}[{}]",
                content_hash, index
            ))),
        }
    }

    /// 检查缺失的分片
    pub async fn get_missing_chunks(
        &self,
        user_id: Uuid,
        content_hash: &str,
        total_chunks: i32,
    ) -> AppResult<Vec<i32>> {
        let existing = self.db.get_chunks_by_hash(user_id, content_hash).await?;
        let existing_indices: std::collections::HashSet<i32> =
            existing.iter().map(|c| c.chunk_index).collect();

        let missing: Vec<i32> = (0..total_chunks)
            .filter(|i| !existing_indices.contains(i))
            .collect();

        Ok(missing)
    }

    /// 重组文件
    pub async fn reassemble(
        &self,
        user_id: Uuid,
        content_hash: &str,
        total_chunks: i32,
    ) -> AppResult<Vec<u8>> {
        let mut result = Vec::new();

        for index in 0..total_chunks {
            let chunk_data = self.get_chunk(user_id, content_hash, index).await?;
            result.extend_from_slice(&chunk_data);
        }

        // 验证完整文件的哈希
        let actual_hash = self.calculate_file_hash(&result);
        if actual_hash != content_hash {
            return Err(AppError::ValidationError(format!(
                "Content hash mismatch after reassembly: expected {}, got {}",
                content_hash, actual_hash
            )));
        }

        Ok(result)
    }

    /// 清理分片
    pub async fn cleanup_chunks(&self, user_id: Uuid, content_hash: &str) -> AppResult<()> {
        let chunks = self.db.get_chunks_by_hash(user_id, content_hash).await?;

        for chunk in chunks {
            // 删除文件
            if let Err(e) = fs::remove_file(&chunk.storage_path).await {
                tracing::warn!("Failed to delete chunk file {}: {}", chunk.storage_path, e);
            }
        }

        // 从数据库删除
        self.db.delete_chunks_by_hash(user_id, content_hash).await?;

        Ok(())
    }

    fn get_chunk_path(&self, user_id: Uuid, content_hash: &str, index: i32) -> PathBuf {
        self.storage_path
            .join(user_id.to_string())
            .join(&content_hash[..2])
            .join(&content_hash[2..4])
            .join(format!("{}_{}", content_hash, index))
    }

    fn calculate_checksum(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn calculate_file_hash(&self, data: &[u8]) -> String {
        self.calculate_checksum(data)
    }
}
