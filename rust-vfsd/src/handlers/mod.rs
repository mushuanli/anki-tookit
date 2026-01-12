// src/handlers/mod.rs

pub mod websocket;
pub mod rest;
pub mod admin;
pub mod health;

pub use websocket::*;
pub use rest::*;
pub use admin::*;
pub use health::*;
