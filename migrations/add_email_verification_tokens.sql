USE flowauth;

-- Add email verification tokens table
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    used TINYINT(1) DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_email_used_expires (email, used, expires_at),
    INDEX idx_token (token),
    
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

DESCRIBE email_verification_tokens;
