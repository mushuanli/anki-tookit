// file: rustSync/server/src/auth.rs

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const JWT_SECRET: &[u8] = b"secret_key_change_me_in_prod"; // 生产环境请从环境变量读取

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,       // User ID
    pub dev: String,       // Device ID
    pub scope: String,     // 允许访问的目录，例如 "/" 或 "/photos"
    pub perm: String,      // "rw" or "ro"
    pub exp: usize,
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    // 修复点：使用 map_err 手动处理错误转换
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{}", e))? 
        .to_string();
        
    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

pub fn create_token(user_id: &str, device_id: &str, scope: &str) -> anyhow::Result<String> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as usize + 3600 * 24 * 7; // 7天有效

    let claims = Claims {
        sub: user_id.to_string(),
        dev: device_id.to_string(),
        scope: scope.to_string(),
        perm: "rw".to_string(), // 默认读写，后续可从 DB 读取
        exp: expiration,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))?;
    Ok(token)
}

pub fn decode_token(token: &str) -> anyhow::Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::new(Algorithm::HS256),
    )?;
    Ok(token_data.claims)
}
