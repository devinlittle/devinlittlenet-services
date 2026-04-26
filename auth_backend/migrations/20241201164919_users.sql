CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,      -- Unique user identifier
    username VARCHAR(50) NOT NULL UNIQUE,               -- Username for login
    password_hash TEXT NOT NULL,                        -- Hashed password
    created_at TIMESTAMP DEFAULT NOW(),                 -- Account creation timestamp
    bio TEXT,
    public_key TEXT,
    recovery_hash TEXT,
    encrypted_private_key TEXT,
    active BOOL DEFAULT false,
    last_seen TIMESTAMPTZ,
    last_seen_visible BOOL DEFAULT true
);

ALTER TABLE users
ADD COLUMN roles JSONB NOT NULL DEFAULT '{"global": "user"}';
