CREATE TABLE Users (
    UserID INT IDENTITY(1,1) PRIMARY KEY, -- The Identity Key
    Username VARCHAR(50) NOT NULL UNIQUE, -- Must be unique
    Email VARCHAR(100) NOT NULL UNIQUE,   -- Must be unique
    PasswordHash VARCHAR(255) NOT NULL,   -- Login password (Bcrypt/Argon2)
    ProfileImage VARCHAR(255) DEFAULT NULL,
    CreatedAt DATETIME DEFAULT GETDATE()
);

CREATE TABLE UserFiles (
    FileID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT NOT NULL,
    
    -- Display Info (Visible to user)
    FileName VARCHAR(255) NOT NULL,     -- e.g. "Tax_Report.pdf"
    FileSizeBytes BIGINT NOT NULL,      -- e.g. 204800 (for progress bars)
    FileType VARCHAR(50),               -- e.g. "application/pdf"
    
    -- Cloud Storage Reference
    FirebasePath VARCHAR(500) NOT NULL, -- e.g. "users/101/enc_5f3a1...blob"
    
    -- CRYPTO METADATA (Crucial for Zero-Knowledge)
    -- We do NOT store the PIN. We store the ingredients needed to USE the PIN.
    EncryptionSalt VARCHAR(255) NOT NULL, -- Random data mixed with PIN
    EncryptionIV VARCHAR(255) NOT NULL,   -- Random vector for AES-GCM
    
    UploadDate DATETIME DEFAULT GETDATE(),
    
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);