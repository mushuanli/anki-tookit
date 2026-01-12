// src/storage/object_store.rs

use async_trait::async_trait;
use bytes::Bytes;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::error::{AppError, AppResult};

/// 对象存储接口
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, data: Bytes) -> AppResult<()>;
    async fn get(&self, key: &str) -> AppResult<Option<Bytes>>;
    async fn delete(&self, key: &str) -> AppResult<()>;
    async fn exists(&self, key: &str) -> AppResult<bool>;
    async fn list(&self, prefix: &str) -> AppResult<Vec<String>>;
}

/// 本地文件系统存储
pub struct LocalStore {
    base_path: PathBuf,
}

impl LocalStore {
    pub async fn new(base_path: &str) -> AppResult<Self> {
        let path = PathBuf::from(base_path);
        fs::create_dir_all(&path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to create storage directory: {}", e))
        })?;

        Ok(Self { base_path: path })
    }

    fn get_path(&self, key: &str) -> PathBuf {
        // 使用前两个字符创建子目录，避免单目录文件过多
        let (prefix, rest) = if key.len() >= 2 {
            (&key[..2], &key[2..])
        } else {
            (key, "")
        };

        self.base_path
            .join(prefix)
            .join(format!("{}{}", prefix, rest))
    }
}

#[async_trait]
impl ObjectStore for LocalStore {
    async fn put(&self, key: &str, data: Bytes) -> AppResult<()> {
        let path = self.get_path(key);
        
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                AppError::InternalError(format!("Failed to create directory: {}", e))
            })?;
        }

        let mut file = fs::File::create(&path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to create file: {}", e))
        })?;

        file.write_all(&data).await.map_err(|e| {
            AppError::InternalError(format!("Failed to write file: {}", e))
        })?;

        Ok(())
    }

    async fn get(&self, key: &str) -> AppResult<Option<Bytes>> {
        let path = self.get_path(key);

        match fs::read(&path).await {
            Ok(data) => Ok(Some(Bytes::from(data))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::InternalError(format!("Failed to read file: {}", e))),
        }
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let path = self.get_path(key);

        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AppError::InternalError(format!("Failed to delete file: {}", e))),
        }
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        let path = self.get_path(key);
        Ok(path.exists())
    }

    async fn list(&self, prefix: &str) -> AppResult<Vec<String>> {
        let search_path = if prefix.len() >= 2 {
            self.base_path.join(&prefix[..2])
        } else {
            self.base_path.clone()
        };

        let mut results = Vec::new();

        if !search_path.exists() {
            return Ok(results);
        }

        let mut entries = fs::read_dir(&search_path).await.map_err(|e| {
            AppError::InternalError(format!("Failed to read directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            AppError::InternalError(format!("Failed to read entry: {}", e))
        })? {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(prefix) {
                    results.push(name.to_string());
                }
            }
        }

        Ok(results)
    }
}

/// 创建对象存储实例
pub async fn create_object_store(data_dir: &str) -> AppResult<Box<dyn ObjectStore>> {
    Ok(Box::new(LocalStore::new(data_dir).await?))
}
