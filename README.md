# Secure File Server (SFS)

<div align="center">

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Axum](https://img.shields.io/badge/Axum-000000?style=for-the-badge&logo=rust&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)

</div>

## Description

**Secure File Server (SFS)** is a web-based file storage and sharing application built with Rust. This project provides a secure platform for users to upload, download, share, and manage files with fine-grained access control. The system implements JWT-based authentication, password hashing with Argon2, and supports both private and public file sharing.

This project was developed as part of the **Programming** course at **Opole University of Technology** under the guidance of **Courtney Robinson**.

### Key Features

- 🔐 **Secure Authentication**: JWT-based authentication with refresh token rotation
- 📁 **File Management**: Upload, download, and organize personal files
- 👥 **File Sharing**: Share files with specific users or make them publicly accessible
- 🔒 **Access Control**: Fine-grained permissions for file access
- 🛡️ **Security**: Argon2 password hashing, secure token storage, and input validation
- 🚀 **Performance**: Async/await architecture with efficient file streaming

## Technologies Used

<div align="center">

[![Rust](https://img.shields.io/badge/Rust-1.0+-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-000000?style=flat-square&logo=rust&logoColor=white)](https://github.com/tokio-rs/axum)
[![Tokio](https://img.shields.io/badge/Tokio-1.0-000000?style=flat-square&logo=tokio&logoColor=white)](https://tokio.rs/)
[![SQLx](https://img.shields.io/badge/SQLx-0.7-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://github.com/launchbadge/sqlx)
[![SQLite](https://img.shields.io/badge/SQLite-3.0-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Argon2](https://img.shields.io/badge/Argon2-0.5-FF6B6B?style=flat-square)](https://github.com/RustCrypto/password-hashes)
[![JWT](https://img.shields.io/badge/JWT-9.0-000000?style=flat-square&logo=json-web-tokens&logoColor=white)](https://jwt.io/)
[![Serde](https://img.shields.io/badge/Serde-1.0-000000?style=flat-square&logo=rust&logoColor=white)](https://serde.rs/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=flat-square&logo=bootstrap&logoColor=white)](https://getbootstrap.com/)

</div>

## Design Overview

### Architecture

The application follows a modular architecture with clear separation of concerns:

```
SFS/
├── src/
│   ├── main.rs           # Application entry point and route configuration
│   ├── config.rs         # Configuration management from environment variables
│   ├── state.rs          # Application state (database pool, config)
│   ├── errors.rs         # Custom error types and HTTP error handling
│   ├── auth/             # Authentication module
│   │   ├── jwt.rs        # JWT token creation
│   │   ├── middleware.rs # Authentication middleware
│   │   └── mod.rs
│   ├── database/         # Database operations
│   │   └── mod.rs        # SQL queries and database functions
│   └── handlers/         # HTTP request handlers
│       ├── auth.rs       # Authentication endpoints (login, register, logout)
│       ├── files.rs      # File operations (upload, download, share)
│       ├── profile.rs    # User profile management
│       └── health.rs      # Health check endpoint
└── static/               # Frontend files
    ├── index.html        # Web interface
    └── style.css         # Styling
```

### Security Features

1. **Password Security**
   - Argon2 password hashing with random salts
   - Strong password requirements (uppercase, lowercase, digit, symbol)

2. **Token Management**
   - JWT access tokens for API authentication
   - Refresh tokens stored as SHA256 hashes in database
   - Token rotation on refresh to prevent reuse attacks

3. **File Access Control**
   - Private files: Only owner and explicitly shared users can access
   - Public files: Accessible without authentication
   - Permission-based sharing system

4. **Input Validation**
   - Username format validation
   - Password strength requirements
   - SQL injection prevention via parameterized queries

### Database Schema

- **users**: User accounts with hashed passwords
- **files**: File metadata (actual files stored on disk)
- **permissions**: File sharing relationships
- **tokens**: Refresh token hashes with expiration tracking

## Usage

### Web Interface

1. **Register**: Create a new account with a username and strong password
2. **Login**: Authenticate to receive access and refresh tokens
3. **Upload Files**: Select and upload files through the web interface
4. **Download Files**: Download your own files or files shared with you
5. **Share Files**: 
   - Share with specific users by username
   - Make files public for anonymous access
6. **Manage Profile**: View profile information and refresh tokens

### API Endpoints

#### Public Endpoints
- `POST /register` - Create a new user account
- `POST /login` - Authenticate and receive tokens
- `POST /token/refresh` - Refresh access token
- `POST /logout` - Revoke refresh token
- `GET /file/public/:id` - Download public file
- `GET /health` - Health check

#### Protected Endpoints (Require JWT)
- `GET /profile` - Get user profile information
- `POST /file/upload` - Upload a new file
- `GET /file/:id` - Download private/shared file
- `POST /file/:id/share` - Share file with user
- `DELETE /file/:id/share/:username` - Revoke file sharing
- `POST /file/:id/public` - Make file public
- `DELETE /file/:id/public` - Make file private

## Setup

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- Cargo (comes with Rust)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SFS
   ```

2. **Configure environment variables** (optional)
   
   Create a `.env` file in the project root:
   ```env
   ADDRESS=127.0.0.1:8080
   DB_URL=data/server.db
   FILES_PATH=data/files
   JWT_SECRET=your-secret-key-here
   ```
   
   If no `.env` file is provided, the application will use default values.

3. **Build the project**
   ```bash
   cargo build
   ```

4. **Run the server**
   ```bash
   cargo run
   ```

5. **Access the application**
   
   Open your browser and navigate to:
   ```
   http://127.0.0.1:8080
   ```

### Directory Structure

The application will automatically create the following directories:
- `data/` - Database and configuration files
- `data/files/` - Uploaded files storage

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `ADDRESS` | `127.0.0.1:8080` | Server bind address |
| `DB_URL` | `data/server.db` | SQLite database path |
| `FILES_PATH` | `data/files` | Directory for uploaded files |
| `JWT_SECRET` | `default-secret-key-which-shouldn't-be-used` | Secret key for JWT signing |

## Thanks

### Opole University of Technology

I extend my sincere gratitude to **Opole University of Technology** for providing the educational framework and resources that made this project possible. Special thanks to **Courtney Robinson** for guidance and instruction in the Programming course.

### Open Source Community

This project is built upon the excellent work of the open-source community:
- **Rust** - The systems programming language that powers this application
- **Axum** - The web framework that makes building async HTTP services a joy
- **Tokio** - The async runtime that enables high-performance concurrent operations
- **SQLx** - The type-safe SQL toolkit that ensures database safety
- **Argon2** - The password hashing algorithm that keeps user credentials secure
- **jsonwebtoken** - The JWT library that handles token creation and validation
- **Bootstrap** - The CSS framework that provides a beautiful user interface

And all the other amazing open-source projects that make modern software development possible.

---

<div align="center">

**Built with ❤️ for the Programming course at Opole University of Technology**

</div>
