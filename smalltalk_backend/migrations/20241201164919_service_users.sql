CREATE TABLE service_users (
    id UUID PRIMARY KEY,      -- Unique user identifier
    username VARCHAR(50) NOT NULL UNIQUE,               -- Username for login
    created_at TIMESTAMP DEFAULT NOW()                  -- Account creation timestamp
);
