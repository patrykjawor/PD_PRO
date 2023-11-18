-- Tworzy tabelę z użytkownikami --
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    magicnumber TEXT NOT NULL,
    two_factory_auth TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    fileid INTEGER PRIMARY KEY AUTOINCREMENT,
    filehash TEXT UNIQUE NOT NULL,
    owner TEXT NOT NULL,
    filename TEXT NOT NULL,
    checksum TEXT NOT NULL,
    FOREIGN KEY(owner) REFERENCES users(username)
);