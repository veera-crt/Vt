-- Users Table (Voters and Admins)
DROP TABLE IF EXISTS votes;
DROP TABLE IF EXISTS candidates;
DROP TABLE IF EXISTS elections;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL, -- Encrypted
    voter_id VARCHAR(255) UNIQUE NOT NULL, -- Encrypted
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_approved BOOLEAN DEFAULT FALSE, -- Admin approval
    rejection_reason TEXT,
    otp_code VARCHAR(6),
    otp_expiry TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Elections Table
CREATE TABLE elections (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    status VARCHAR(20) DEFAULT 'upcoming', -- upcoming, active, ended, hidden
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Candidates Table
CREATE TABLE candidates (
    id SERIAL PRIMARY KEY,
    election_id INTEGER REFERENCES elections(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    party VARCHAR(100),
    manifesto TEXT,
    image_url VARCHAR(255),
    vote_count INTEGER DEFAULT 0
);

-- Votes Table
CREATE TABLE votes (
    id SERIAL PRIMARY KEY,
    election_id INTEGER REFERENCES elections(id) ON DELETE CASCADE,
    voter_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(election_id, voter_id) -- Prevents double voting
);
