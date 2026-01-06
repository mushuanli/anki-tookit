// file: rustSync/rsync-core/src/lib.rs
pub mod chunker;

#[cfg(test)]
mod tests {
    use super::chunker::generate_chunks;

    #[test]
    fn test_chunking() {
        // 创建 100KB 的随机数据
        let data = vec![1u8; 100 * 1024]; 
        let (hash, chunks) = generate_chunks(&data);
        
        println!("Full Hash: {}", hash);
        println!("Chunks count: {}", chunks.len());
        
        assert!(!hash.is_empty());
        assert!(chunks.len() > 1); // 100KB 肯定会被切分
        
        let mut total_len = 0;
        for c in chunks {
            total_len += c.length;
        }
        assert_eq!(total_len as usize, data.len());
    }
}
