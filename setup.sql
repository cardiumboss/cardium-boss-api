CREATE DATABASE IF NOT EXISTS cardium_boss;
USE cardium_boss;

CREATE TABLE IF NOT EXISTS users (
  id                 INT AUTO_INCREMENT PRIMARY KEY,
  email              VARCHAR(255) UNIQUE NOT NULL,
  password_hash      VARCHAR(255) NOT NULL,
  verified           TINYINT(1) NOT NULL DEFAULT 0,
  verification_token VARCHAR(255),
  created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
