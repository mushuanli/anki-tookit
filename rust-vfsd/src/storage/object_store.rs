// src/storage/object_store.rs

use async_trait::async_trait;
use bytes::Bytes;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::config::{StorageConfig};
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

/// S3 存储
#[cfg(feature = "s3")]
pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

#[cfg(feature = "s3")]
impl S3Store {
    pub async fn new(bucket: &str, region: &str, prefix: Option<String>) -> AppResult<Self> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;

        let client = aws_sdk_s3::Client::new(&config);

        Ok(Self {
            client,
            bucket: bucket.to_string(),
            prefix: prefix.unwrap_or_default(),
        })
    }

    fn get_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.prefix, key)
        }
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl ObjectStore for S3Store {
    async fn put(&self, key: &str, data: Bytes) -> AppResult<()> {
        let s3_key = self.get_key(key);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .body(data.into())
            .send()
            .await
            .map_err(|e| AppError::InternalError(format!("S3 put failed: {}", e)))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> AppResult<Option<Bytes>> {
        let s3_key = self.get_key(key);

        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
        {
            Ok(output) => {
                let data = output
                    .body
                    .collect()
                    .await
                    .map_err(|e| AppError::InternalError(format!("Failed to read S3 body: {}", e)))?;
                Ok(Some(data.into_bytes()))
            }
            Err(aws_sdk_s3::error::SdkError::ServiceError(err))
                if err.err().is_no_such_key() =>
            {
                Ok(None)
            }
            Err(e) => Err(AppError::InternalError(format!("S3 get failed: {}", e))),
        }
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let s3_key = self.get_key(key);

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| AppError::InternalError(format!("S3 delete failed: {}", e)))?;

        Ok(())
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        let s3_key = self.get_key(key);

        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(aws_sdk_s3::error::SdkError::ServiceError(err))
                if err.err().is_not_found() =>
            {
                Ok(false)
            }
            Err(e) => Err(AppError::InternalError(format!("S3 head failed: {}", e))),
        }
    }

    async fn list(&self, prefix: &str) -> AppResult<Vec<String>> {
        let s3_prefix = self.get_key(prefix);

        let output = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&s3_prefix)
            .send()
            .await
            .map_err(|e| AppError::InternalError(format!("S3 list failed: {}", e)))?;

        let keys = output
            .contents()
            .iter()
            .filter_map(|obj| obj.key())
            .map(|k| {
                k.strip_prefix(&format!("{}/", self.prefix))
                    .unwrap_or(k)
                    .to_string()
            })
            .collect();

        Ok(keys)
    }
}

/// 创建对象存储实例
pub async fn create_object_store(config: &StorageConfig) -> AppResult<Box<dyn ObjectStore>> {
    use crate::config::StorageType;
    
    match &config.storage_type {
        StorageType::Local => {
            let path = config.local_path.as_deref().unwrap_or("./data");
            Ok(Box::new(LocalStore::new(path).await?))
        }
        #[cfg(feature = "s3")]
        StorageType::S3 => {
            let bucket = config
                .s3_bucket
                .as_ref()
                .ok_or_else(|| AppError::ConfigError("S3 bucket not configured".to_string()))?;
            let region = config
                .s3_region
                .as_ref()
                .ok_or_else(|| AppError::ConfigError("S3 region not configured".to_string()))?;

            Ok(Box::new(S3Store::new(bucket, region, config.s3_prefix.clone()).await?))
        }
        #[cfg(not(feature = "s3"))]
        StorageType::S3 => {
            Err(AppError::ConfigError(
                "S3 storage type requires 's3' feature to be enabled".to_string()
            ))
        }
    }
}
