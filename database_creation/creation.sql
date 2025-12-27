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

    -- Display Info
    FileName VARCHAR(255) NOT NULL,
    FileSizeBytes BIGINT NOT NULL,
    FileType VARCHAR(50),

    -- Cloud Storage Reference (Supabase)
    StoragePath VARCHAR(500) NOT NULL,   -- e.g. "user-files/101/enc_xxx.bin"
    StorageProvider VARCHAR(50) DEFAULT 'supabase',

    -- Crypto Metadata (Zero-Knowledge)
    EncryptionSalt VARCHAR(255) NOT NULL,
    EncryptionIV VARCHAR(255) NOT NULL,

    UploadDate DATETIME DEFAULT GETDATE(),

    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

