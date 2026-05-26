CREATE TABLE refresh_tokens (
    id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id     UUID NOT NULL,
    token_hash  BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ NULL,
    replaced_by_token UUID NULL,
    user_agent TEXT NOT NULL,

    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT fk_replaced_by_token
        FOREIGN KEY (replaced_by_token) REFERENCES refresh_tokens(id)
        ON DELETE SET NULL
);

CREATE UNIQUE INDEX idx_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_user_tokens ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_user_expires ON refresh_tokens(user_id, expires_at);
