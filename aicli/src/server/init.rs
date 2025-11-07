// src/server/init.rs

use crate::error::{AppError, Result};
use std::fs;
use std::path::Path;

pub fn run() -> Result<()> {
    println!("Initializing server configuration...");

    // FIX: Define the data directory path
    let data_dir = Path::new("data");

    // Ensure the data directory exists
    fs::create_dir_all(data_dir)?;

    // FIX: Define paths for the key and certificate inside the data directory
    let cert_path = data_dir.join("cert.pem");
    let key_path = data_dir.join("key.pem");

    if cert_path.exists() || key_path.exists() {
        println!("SSL certificate/key files already exist in 'data/' directory. Skipping generation.");
    } else {
        println!("Generating self-signed SSL certificate...");
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| AppError::ConfigError(format!("Failed to generate certificate: {}", e)))?;
        
        let cert_pem = certified_key.cert.pem();
        let key_pem = certified_key.key_pair.serialize_pem();

        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;

        println!("✓ Successfully generated '{}' and '{}'.", cert_path.display(), key_path.display());
    }

    println!("\nConfiguration complete! ");
    Ok(())
}
