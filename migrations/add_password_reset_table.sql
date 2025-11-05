USE flowauth;

-- Add password reset token table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id int PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(64) NOT NULL UNIQUE,
    userId int NOT NULL,
    email VARCHAR(255) NOT NULL,
    expiresAt DATETIME NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_id (userId),
    INDEX idx_expires_at (expiresAt),
    INDEX idx_used (used)
);

DESCRIBE password_reset_tokens;
