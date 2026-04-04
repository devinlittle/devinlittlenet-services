CREATE TABLE refresh_tokens (
    id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id     UUID NOT NULL,
    token_hash  VARCHAR(255) NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW(),
    revoked_at  TIMESTAMP NULL,
    replaced_by_token VARCHAR(255) NULL,

    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_user_tokens ON refresh_tokens(user_id);
