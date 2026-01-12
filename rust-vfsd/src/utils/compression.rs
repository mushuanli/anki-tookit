// src/utils/compression.rs

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};

use crate::error::{AppError, AppResult};

pub struct CompressionUtils;

impl CompressionUtils {
    /// 压缩数据
    pub fn compress(data: &[u8], algorithm: &str) -> AppResult<Vec<u8>> {
        match algorithm {
            "gzip" => Self::gzip_compress(data),
            "brotli" => Self::brotli_compress(data),
            _ => Err(AppError::ValidationError(format!(
                "Unsupported compression algorithm: {}",
                algorithm
            ))),
        }
    }

    /// 解压数据
    pub fn decompress(data: &[u8], algorithm: &str) -> AppResult<Vec<u8>> {
        match algorithm {
            "gzip" => Self::gzip_decompress(data),
            "brotli" => Self::brotli_decompress(data),
            _ => Err(AppError::ValidationError(format!(
                "Unsupported compression algorithm: {}",
                algorithm
            ))),
        }
    }

    fn gzip_compress(data: &[u8]) -> AppResult<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(data)
            .map_err(|e| AppError::InternalError(format!("Gzip compression failed: {}", e)))?;
        encoder
            .finish()
            .map_err(|e| AppError::InternalError(format!("Gzip compression failed: {}", e)))
    }

    fn gzip_decompress(data: &[u8]) -> AppResult<Vec<u8>> {
        let mut decoder = GzDecoder::new(data);
        let mut result = Vec::new();
        decoder
            .read_to_end(&mut result)
            .map_err(|e| AppError::InternalError(format!("Gzip decompression failed: {}", e)))?;
        Ok(result)
    }

    fn brotli_compress(data: &[u8]) -> AppResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut writer = brotli::CompressorWriter::new(&mut result, 4096, 4, 22);
        writer
            .write_all(data)
            .map_err(|e| AppError::InternalError(format!("Brotli compression failed: {}", e)))?;
        drop(writer);
        Ok(result)
    }

    fn brotli_decompress(data: &[u8]) -> AppResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut reader = brotli::Decompressor::new(data, 4096);
        reader
            .read_to_end(&mut result)
            .map_err(|e| AppError::InternalError(format!("Brotli decompression failed: {}", e)))?;
        Ok(result)
    }

    /// 判断是否值得压缩
    pub fn should_compress(size: usize, min_size: usize) -> bool {
        size >= min_size
    }
}
