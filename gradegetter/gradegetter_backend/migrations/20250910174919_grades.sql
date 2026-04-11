CREATE TABLE grades (
    id UUID PRIMARY KEY,  -- User's service uuid
    grades TEXT NOT NULL,         -- Encyrpted JSON string
    FOREIGN KEY (id) REFERENCES service_users(id) ON DELETE CASCADE
);
