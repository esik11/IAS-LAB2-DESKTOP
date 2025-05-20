CREATE DATABASE ias_auth;

USE ias_auth;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    firebase_uid VARCHAR(128) UNIQUE NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    access_token VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255) NOT NULL,
    access_token_expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_access_token (access_token),
    INDEX idx_refresh_token (refresh_token),
    INDEX idx_expires_at (access_token_expires_at, refresh_token_expires_at)
);

CREATE TABLE backup_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    code VARCHAR(8) NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE otp_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    otp VARCHAR(6) NOT NULL,
    otp_type ENUM('LOGIN', 'VERIFY_EMAIL') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    is_successful BOOLEAN DEFAULT FALSE,
    INDEX idx_email_time (email, attempt_time)
);

CREATE TABLE security_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_user_event (user_id, event_type)
);