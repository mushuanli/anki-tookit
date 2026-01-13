// src/storage/file_store.rs

use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use vfs_core::config::StorageConfig;
use vfs_core::error::{AppError, AppResult};

/// 本地文件存储
pub struct FileStore {
    content_path: PathBuf,
    chunks_path: PathBuf,
}

impl FileStore {
    pub async fn new(config: &StorageConfig) -> AppResult<Self> {
        let content_path = config.content_path();
        let chunks_path = config.chunks_path();

        // 确保目录存在
        fs::create_dir_all(&content_path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to create content directory: {}", e))
        })?;
        fs::create_dir_all(&chunks_path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to create chunks directory: {}", e))
        })?;

        Ok(Self {
            content_path,
            chunks_path,
        })
    }

    /// 获取内容文件路径
    fn get_content_path(&self, user_id: Uuid, content_hash: &str) -> PathBuf {
        // 使用前两个字符创建子目录，避免单目录文件过多
        let prefix = &content_hash[..2.min(content_hash.len())];
        self.content_path
            .join(user_id.to_string())
            .join(prefix)
            .join(content_hash)
    }

    /// 获取分片文件路径
    fn get_chunk_path(&self, user_id: Uuid, content_hash: &str, index: i32) -> PathBuf {
        let prefix = &content_hash[..2.min(content_hash.len())];
        self.chunks_path
            .join(user_id.to_string())
            .join(prefix)
            .join(format!("{}_{}", content_hash, index))
    }

    // ==================== 内容存储 ====================

    /// 保存内容
    pub async fn save_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
        data: &[u8],
    ) -> AppResult<String> {
        let path = self.get_content_path(user_id, content_hash);

        // 确保目录存在
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                AppError::InternalError(format!("Failed to create directory: {}", e))
            })?;
        }

        // 写入文件
        let mut file = fs::File::create(&path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to create file: {}", e))
        })?;

        file.write_all(data).await.map_err(|e| {
            AppError::InternalError(format!("Failed to write file: {}", e))
        })?;

        file.flush().await.map_err(|e| {
            AppError::InternalError(format!("Failed to flush file: {}", e))
        })?;

        Ok(path.to_string_lossy().to_string())
    }

    /// 读取内容
    pub async fn get_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Option<Vec<u8>>> {
        let path = self.get_content_path(user_id, content_hash);

        match fs::read(&path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::InternalError(format!("Failed to read file: {}", e))),
        }
    }

    /// 删除内容
    pub async fn delete_content(&self, user_id: Uuid, content_hash: &str) -> AppResult<()> {
        let path = self.get_content_path(user_id, content_hash);

        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AppError::InternalError(format!("Failed to delete file: {}", e))),
        }
    }

    /// 检查内容是否存在
    pub async fn content_exists(&self, user_id: Uuid, content_hash: &str) -> bool {
        let path = self.get_content_path(user_id, content_hash);
        path.exists()
    }

    // ==================== 分片存储 ====================

    /// 保存分片
    pub async fn save_chunk(
        &self,
        user_id: Uuid,
        content_hash: &str,
        index: i32,
        data: &[u8],
    ) -> AppResult<String> {
        let path = self.get_chunk_path(user_id, content_hash, index);

        // 确保目录存在
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                AppError::InternalError(format!("Failed to create directory: {}", e))
            })?;
        }

        // 写入文件
        let mut file = fs::File::create(&path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to create chunk file: {}", e))
        })?;

        file.write_all(data).await.map_err(|e| {
            AppError::InternalError(format!("Failed to write chunk file: {}", e))
        })?;

        Ok(path.to_string_lossy().to_string())
    }

    /// 读取分片
    pub async fn get_chunk(
        &self,
        user_id: Uuid,
        content_hash: &str,
        index: i32,
    ) -> AppResult<Option<Vec<u8>>> {
        let path = self.get_chunk_path(user_id, content_hash, index);

        match fs::read(&path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::InternalError(format!("Failed to read chunk: {}", e))),
        }
    }

    /// 删除分片
    pub async fn delete_chunk(
        &self,
        user_id: Uuid,
        content_hash: &str,
        index: i32,
    ) -> AppResult<()> {
        let path = self.get_chunk_path(user_id, content_hash, index);

        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AppError::InternalError(format!("Failed to delete chunk: {}", e))),
        }
    }

    /// 删除指定内容的所有分片
    pub async fn delete_all_chunks(&self, user_id: Uuid, content_hash: &str) -> AppResult<()> {
        let prefix = &content_hash[..2.min(content_hash.len())];
        let dir = self.chunks_path.join(user_id.to_string()).join(prefix);

        if !dir.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(&dir).await.map_err(|e| {
            AppError::InternalError(format!("Failed to read directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            AppError::InternalError(format!("Failed to read entry: {}", e))
        })? {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(content_hash) {
                    if let Err(e) = fs::remove_file(entry.path()).await {
                        tracing::warn!("Failed to delete chunk file {}: {}", name, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// 获取用户存储使用量
    pub async fn get_user_storage_usage(&self, user_id: Uuid) -> AppResult<i64> {
        let user_content_path = self.content_path.join(user_id.to_string());
        let user_chunks_path = self.chunks_path.join(user_id.to_string());

        let mut total_size: i64 = 0;

        // 计算内容大小
        if user_content_path.exists() {
            total_size += Self::calculate_dir_size(&user_content_path).await?;
        }

        // 计算分片大小
        if user_chunks_path.exists() {
            total_size += Self::calculate_dir_size(&user_chunks_path).await?;
        }

        Ok(total_size)
    }

    async fn calculate_dir_size(path: &PathBuf) -> AppResult<i64> {
        let mut total: i64 = 0;
        let mut stack = vec![path.clone()];

        while let Some(current) = stack.pop() {
            let mut entries = fs::read_dir(&current).await.map_err(|e| {
                AppError::InternalError(format!("Failed to read directory: {}", e))
            })?;

            while let Some(entry) = entries.next_entry().await.map_err(|e| {
                AppError::InternalError(format!("Failed to read entry: {}", e))
            })? {
                let metadata = entry.metadata().await.map_err(|e| {
                    AppError::InternalError(format!("Failed to get metadata: {}", e))
                })?;

                if metadata.is_file() {
                    total += metadata.len() as i64;
                } else if metadata.is_dir() {
                    stack.push(entry.path());
                }
            }
        }

        Ok(total)
    }
}
