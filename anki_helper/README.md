# Anki Helper

A powerful, AI-driven command-line tool written in Rust to automate the creation of Anki flashcards.

This tool can generate rich, multimedia cards for English words or recitation content (like poems) by leveraging AI for content generation and text-to-speech/text-to-image services for media.

## Features

- **User-Friendly CLI**: Powered by `clap`, with clear commands, arguments, and help messages.
- **Unified Generation**: A single executable handles different card types (words, poems, etc.).
- **AI-Powered Content**: Uses OpenAI-compatible APIs (like DeepSeek) to generate card details (definitions, examples, memory tips).
- **Multimedia Generation**:
  - **Audio**: Creates audio for text using macOS's `say` command or `edge-tts` on other platforms.
  - **Images**: Generates relevant images from text prompts using Alibaba's Flux API.
- **High Performance**: Asynchronous-first design using `tokio` for concurrent network and file operations.
- **Robust & Safe**: Built with Rust for type safety and reliable error handling.

## Installation

1.  **Install Rust**: If you haven't already, install Rust via [rustup](https://rustup.rs/).

2.  **Install Dependencies**:
    - **`lame` (macOS only)**: For converting audio to MP3.
      ```bash
      brew install lame
      ```
    - **`edge-tts` (Linux/Windows)**: For text-to-speech.
      ```bash
      pip install edge-tts
      ```

3.  **Clone & Build**:
    ```bash
    git clone <repository_url>
    cd helper
    cargo build --release
    ```
    The executable will be located at `./target/release/helper`.

## Configuration

1.  **Copy the template**:
    ```bash
    cp config.toml.example config.toml
    ```

2.  **Edit `config.toml`**:
    - Open `config.toml` and fill in your details.
    - **API Keys**: It is **highly recommended** to set API keys as environment variables for security. The application will use environment variables if the fields in `config.toml` are left empty.
      ```bash
      export OPENAI_API_KEY="your_deepseek_or_openai_key"
      export FLUX_API_KEY="your_alibaba_flux_key"
      ```

## Usage

The tool uses subcommands to specify the task.

### General Help

```bash
./target/release/helper --help