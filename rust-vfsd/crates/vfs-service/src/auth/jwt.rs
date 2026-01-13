// crates/vfs-service/src/auth/jwt.rs
// 与原有代码相同，仅调整引用路径

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vfs_core::config::AuthConfig;
use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{PathPermission, PermissionLevel};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub device_id: Option<String>,
    pub permission_level: PermissionLevel,
    pub path_permissions: Option<Vec<PathPermission>>,
    pub exp: i64,
    pub iat: i64,
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_hours: i64,
}

impl JwtService {
    pub fn new(config: &AuthConfig) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            expiry_hours: config.jwt_expiry_hours,
        }
    }

    pub fn generate_token(
        &self,
        user_id: Uuid,
        username: &str,
        device_id: Option<String>,
        permission_level: PermissionLevel,
        path_permissions: Option<Vec<PathPermission>>,
    ) -> AppResult<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiry_hours);

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            device_id,
            permission_level,
            path_permissions,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::AuthError(format!("Failed to generate token: {}", e)))
    }

    pub fn validate_token(&self, token: &str) -> AppResult<TokenData<Claims>> {
        decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| AppError::AuthError(format!("Invalid token: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_jwt_service() -> JwtService {
        let config = AuthConfig {
            jwt_secret: "test-secret-key-for-testing".to_string(),
            jwt_expiry_hours: 24,
            refresh_expiry_days: 30,
        };
        JwtService::new(&config)
    }

    #[test]
    fn test_generate_and_validate_token() {
        let service = create_test_jwt_service();
        let user_id = Uuid::new_v4();

        let token = service
            .generate_token(
                user_id,
                "testuser",
                Some("device1".to_string()),
                PermissionLevel::ReadWrite,
                None,
            )
            .unwrap();

        let token_data = service.validate_token(&token).unwrap();
        
        assert_eq!(token_data.claims.sub, user_id);
        assert_eq!(token_data.claims.username, "testuser");
        assert_eq!(token_data.claims.device_id, Some("device1".to_string()));
    }

    #[test]
    fn test_invalid_token() {
        let service = create_test_jwt_service();
        
        let result = service.validate_token("invalid.token.here");
        assert!(result.is_err());
    }
}
