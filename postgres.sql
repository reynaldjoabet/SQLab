IF exists(SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[RefreshTokens]') AND type IN (N'U'))
    DROP TABLE [dbo].[RefreshTokens]
GO
CREATE TABLE RefreshTokens
(
    Id                  INT IDENTITY (1,1) PRIMARY KEY,
    SessionId           NVARCHAR(100)   NOT NULL,
    Provider            NVARCHAR(100)   NOT NULL,
    UserId              NVARCHAR(100)   NOT NULL,
    Token               NVARCHAR(255)   NOT NULL,
    ExpiryDate          DATETIME        NOT NULL,
    CreatedByIp         NVARCHAR(50)    NOT NULL,
    CreatedAt           DATETIME        NOT NULL DEFAULT GETDATE(),
    IsRevoked           BIT             NOT NULL DEFAULT 0,
    RevokedAt           DATETIME        NULL,
    RevokedByIp         NVARCHAR(50)    NULL,
    ReplacedByToken     NVARCHAR(255)   NULL,
    ReasonRevoked       NVARCHAR(255)   NULL,
    LastActivityDate    DATETIME        NOT NULL,
    CONSTRAINT UK_Token UNIQUE (Token)
);
GO

CREATE INDEX IX_RefreshTokens_UserId_Provider ON RefreshTokens(UserId, Provider);
CREATE INDEX IX_RefreshTokens_ExpiryDate ON RefreshTokens(ExpiryDate);
GO
-- SessionId
ALTER TABLE RefreshTokens
ADD CONSTRAINT FK_RefreshTokens_UserSessions FOREIGN KEY (SessionId) 
    REFERENCES UserSessions (SessionId)
ON DELETE CASCADE;

IF exists(SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[UserSessions]') AND type IN (N'U'))
    DROP TABLE [dbo].[UserSessions]
GO
CREATE TABLE UserSessions
(
    Id                INT IDENTITY (1,1) PRIMARY KEY,
    Provider          NVARCHAR(100) NOT NULL,
    UserId            NVARCHAR(100) NOT NULL,
    SessionId         NVARCHAR(100) NOT NULL,
    IpAddress         NVARCHAR(50)  NOT NULL,
    CreatedAt         DATETIME      NOT NULL DEFAULT GETDATE(),
    LastActivityAt    DATETIME      NOT NULL,
    IsActive          BIT           NOT NULL DEFAULT 1,
    ExpiryDate        DATETIME      NOT NULL,
    DeactivatedAt     DATETIME      NULL,
    DeactivatedReason NVARCHAR(255) NULL,
    CONSTRAINT UK_SessionId UNIQUE (SessionId),
);
GO

CREATE INDEX IX_UserSessions_UserId_Provider ON UserSessions(UserId, Provider);
CREATE INDEX IX_UserSessions_ExpiryDate ON UserSessions(ExpiryDate);
CREATE INDEX IX_UserSessions_IsActive ON UserSessions(IsActive);
GO
