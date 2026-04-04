CREATE TABLE grades (
    id UUID PRIMARY KEY,  -- User's service uuid
    grades JSONB,         -- JSON string
    FOREIGN KEY (id) REFERENCES service_users(id) ON DELETE CASCADE
);
