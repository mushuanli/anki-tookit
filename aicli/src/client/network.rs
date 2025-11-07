// src/client/network.rs

use crate::common::frame::{encode_frame, read_frame};
use crate::common::types::PacketType;
use crate::error::{AppError, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use serde_json::{json, from_slice};
use std::fs;
use std::io::ErrorKind;
use std::str::FromStr;
//use std::collections::HashMap; // <-- ADD THIS
use uuid::Uuid;
// TLS support
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use std::sync::Arc;

// REFACTOR: This is the data structure for a task as received from the server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemoteTask {
    pub uuid: Uuid,
    pub title: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub error_message: Option<String>,
}

// The struct holds the communication stream.
pub struct NetworkClient<S: AsyncRead + AsyncWrite + Unpin> {
    pub stream: S,
    // MODIFIED: The list is now a Vec of strings
    pub models: Vec<String>, 
    pub default_model: String,
}

// We implement methods on a generic stream so we can test with mock streams.
impl<S: AsyncRead + AsyncWrite + Unpin> NetworkClient<S> {
    #[cfg(test)]
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            models: Vec::new(),
            default_model: String::new(),
        }
    }

    async fn send_and_receive(&mut self, req_type: PacketType, req_payload: &[u8], expected_resp_type: PacketType) -> Result<Vec<u8>> {
        let request_frame = encode_frame(req_type, req_payload);
        self.stream.write_all(&request_frame).await?;

        if let Some(response_frame) = read_frame(&mut self.stream).await? {
            if response_frame.packet_type == expected_resp_type {
                Ok(response_frame.payload)
            } else if response_frame.packet_type == PacketType::Error {
                let error_msg = String::from_utf8_lossy(&response_frame.payload).to_string();
                Err(AppError::NetworkError(format!("Server error: {}", error_msg)))
            } else {
                Err(AppError::NetworkError(format!(
                    "Unexpected response type. Expected {:?}, got {:?}",
                    expected_resp_type, response_frame.packet_type
                )))
            }
        } else {
            Err(AppError::NetworkError("Server disconnected unexpectedly".into()))
        }
    }

    // --- NEW NETWORK FUNCTIONS ---

    pub async fn list_tasks(&mut self) -> Result<Vec<RemoteTask>> {
        let payload = self.send_and_receive(PacketType::CmdList, &[], PacketType::ResponseList).await?;
        let tasks: Vec<RemoteTask> = serde_json::from_slice(&payload)?;
        Ok(tasks)
    }

    pub async fn download_task(&mut self, uuid: Uuid) -> Result<String> {
        let payload = self.send_and_receive(PacketType::CmdGet, uuid.to_string().as_bytes(), PacketType::ResponseChatLog).await?;
        Ok(String::from_utf8(payload).map_err(|e| AppError::ParseError(e.to_string()))?)
    }

    pub async fn delete_task(&mut self, uuid: Uuid) -> Result<()> {
        self.send_and_receive(PacketType::CmdDelete, uuid.to_string().as_bytes(), PacketType::Ack).await?;
        Ok(())
    }


    /// Sends a chat file to the server for execution.
    pub async fn execute_chat(&mut self, chat_file_content: &str) -> Result<Uuid> {
        let payload = self.send_and_receive(PacketType::CmdExec, chat_file_content.as_bytes(), PacketType::Ack).await?;
        let uuid_str = String::from_utf8(payload).map_err(|_| AppError::ParseError("Server sent invalid UUID".to_string()))?;
        Uuid::from_str(&uuid_str).map_err(|_| AppError::ParseError("Failed to parse UUID from server".to_string()))
    }

    // NEW function
    pub async fn update_task(&mut self, uuid: Uuid, content: &str) -> Result<()> {
        let payload = serde_json::to_vec(&serde_json::json!({ "uuid": uuid, "content": content }))?;
        self.send_and_receive(PacketType::CmdUpdate, &payload, PacketType::Ack).await?;
        Ok(())
    }

    // --- We will implement list, get, delete here later ---
}

// Define a type alias for our client's stream for simplicity
pub type TlsClientStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

// The concrete implementation now uses the TlsClientStream type
impl NetworkClient<TlsClientStream> {
    pub async fn connect(server_addr: &str, username: &str, private_key_path: &str) -> Result<Self> {
        let private_key_content = fs::read_to_string(private_key_path).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                AppError::AuthError(format!("Private key file not found at '{}'. Please run 'client init' first.", private_key_path))
            } else {
                AppError::IoWithContext { context: format!("Failed to read private key file '{}'", private_key_path), source: e }
            }
        })?;

        // --- START ROBUST FIX ---
        // Take only the first line of the file and ignore any surrounding whitespace.
        // This is much safer than relying on the whole file content.
        let key_str_on_first_line = private_key_content.lines().next().unwrap_or("").trim();
        
        if key_str_on_first_line.is_empty() {
            return Err(AppError::AuthError(format!("Private key file '{}' is empty or contains no key.", private_key_path)));
        }


        let decoded_with_version = bs58::decode(key_str_on_first_line)
            .with_check(None) // Decode with checksum, but don't check version byte yet.
            .into_vec()
            .map_err(|e| AppError::AuthError(format!("Invalid private key format or checksum: {}", e)))?;

        // --- MANUAL VERSION CHECK AND STRIP ---
        if decoded_with_version.is_empty() || decoded_with_version[0] != 0 {
            return Err(AppError::AuthError("Private key has incorrect version byte. Expected 0.".to_string()));
        }
        let key_bytes_vec = &decoded_with_version[1..]; // This slice is the actual 32-byte key
        // --- END MANUAL CHECK ---
        
        let key_array: [u8; SECRET_KEY_LENGTH] = key_bytes_vec.try_into().map_err(|_| AppError::AuthError(format!("Private key has incorrect length. Expected 32, got {}.", key_bytes_vec.len())))?;
        let signing_key = SigningKey::from_bytes(&key_array);

        // Configure TLS to be insecure for local testing with self-signed certs.
        struct NoVerification;
        impl rustls::client::ServerCertVerifier for NoVerification {
            fn verify_server_cert(&self, _: &rustls::Certificate, _: &[rustls::Certificate], _: &rustls::ServerName, _: &mut dyn Iterator<Item = &[u8]>, _: &[u8], _: std::time::SystemTime) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::ServerCertVerified::assertion())
            }
        }
        
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoVerification))
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
        let domain = rustls::ServerName::try_from("localhost").map_err(|_| AppError::NetworkError("Invalid DNS name for TLS".to_string()))?;
        
        // 3. Connect to server with TCP and then perform TLS handshake
        let tcp_stream = tokio::net::TcpStream::connect(server_addr).await?;
        let mut stream = connector.connect(domain, tcp_stream).await?;
        
        //log::info!("TLS connection established to server at {}", server_addr);
        
        // 4. Send username
        let auth_req_payload = json!({ "username": username }).to_string();
        let auth_req_frame = encode_frame(PacketType::CmdAuthRequest, auth_req_payload.as_bytes());
        stream.write_all(&auth_req_frame).await?;

        let challenge_frame = read_frame(&mut stream).await?.ok_or_else(|| AppError::AuthError("Server disconnected before challenge".to_string()))?;
        if challenge_frame.packet_type != PacketType::CmdAuthChallenge {
            return Err(AppError::AuthError("Expected challenge from server".to_string()));
        }
        let challenge_val: serde_json::Value = from_slice(&challenge_frame.payload)?;
        let challenge_bs58 = challenge_val["challenge"].as_str().ok_or(AppError::ParseError("Challenge missing in server response".to_string()))?;
        let challenge = bs58::decode(challenge_bs58).into_vec()?;

        // 5. Sign challenge and send response
        let signature = signing_key.sign(&challenge);
        let auth_resp_payload = json!({ "signature": bs58::encode(signature.to_bytes()).into_string() }).to_string();
        let auth_resp_frame = encode_frame(PacketType::CmdAuthResponse, auth_resp_payload.as_bytes());
        stream.write_all(&auth_resp_frame).await?;

        // 6. Wait for final ACK and parse model info
        if let Some(frame) = read_frame(&mut stream).await? {
            if frame.packet_type == PacketType::Ack {
                log::info!("Authentication successful...");
                
                let ack_data: serde_json::Value = from_slice(&frame.payload)?;
                let models: Vec<String> = serde_json::from_value(
                    ack_data["models"].clone()
                ).unwrap_or_default();
                let default_model = ack_data["default_model"].as_str().unwrap_or("").to_string();

                Ok(Self {
                    stream,
                    models,
                    default_model,
                })
                // --- END NEW ---

            } else {
                let error_msg = String::from_utf8_lossy(&frame.payload);
                Err(AppError::AuthError(format!("Server rejected auth: {}", error_msg)))
            }
        } else {
            Err(AppError::AuthError("Server disconnected during auth".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::PacketType;
    use tokio::io::DuplexStream;

    // Helper to create a mock stream for testing.
    fn create_mock_stream() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(1024)
    }

    #[tokio::test]
    async fn test_execute_chat_flow() {
        let (client_end, mut server_end) = create_mock_stream();
        let mut client = NetworkClient { stream: client_end };

        let server_task = tokio::spawn(async move {
            // Server side: simulate receiving CmdExec and sending Ack
            let request = read_frame(&mut server_end).await.unwrap().unwrap();
            assert_eq!(request.packet_type, PacketType::CmdExec);
            assert_eq!(String::from_utf8_lossy(&request.payload), "test chat");

            let test_uuid = Uuid::new_v4();
            let response = encode_frame(PacketType::Ack, test_uuid.to_string().as_bytes());
            server_end.write_all(&response).await.unwrap();
            test_uuid
        });

        // Client side: call the method
        let returned_uuid = client.execute_chat("test chat").await.unwrap();
        
        // Assert
        let expected_uuid = server_task.await.unwrap();
        assert_eq!(returned_uuid, expected_uuid);
    }
}
