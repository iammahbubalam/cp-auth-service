-- ========================
-- USERS TABLE
-- ========================
CREATE TABLE auth_user
(
    user_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username           VARCHAR(100) NOT NULL UNIQUE,
    email              VARCHAR(255) NOT NULL UNIQUE,
    password           VARCHAR(255) NOT NULL,
    first_name         VARCHAR(100),
    last_name          VARCHAR(100),
    is_active          BOOLEAN          DEFAULT TRUE,
    creation_date      TIMESTAMP        DEFAULT CURRENT_TIMESTAMP,
    last_modified_date TIMESTAMP        DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for faster lookups
CREATE INDEX idx_auth_user_username ON auth_user (username);
CREATE INDEX idx_auth_user_email ON auth_user (email);
CREATE INDEX idx_auth_user_active ON auth_user (is_active);

-- ========================
-- USER ROLES TABLE
-- ========================
CREATE TABLE user_roles
(
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID        NOT NULL,
    role    VARCHAR(50) NOT NULL,
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES auth_user (user_id) ON DELETE CASCADE
);

-- Index for faster joins and role queries
CREATE INDEX idx_user_roles_user_id ON user_roles (user_id);
CREATE INDEX idx_user_roles_role ON user_roles (role);

-- ========================
-- REFRESH TOKENS TABLE
-- ========================
CREATE TABLE refresh_tokens
(
    id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID           NOT NULL,
    user_id    UUID         NOT NULL,
    expires_at TIMESTAMP    NOT NULL,
    created_at TIMESTAMP        DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN          DEFAULT FALSE,

    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES auth_user (user_id) ON DELETE CASCADE
);

-- Indexes for token lookups
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_token_id ON refresh_tokens (token_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
