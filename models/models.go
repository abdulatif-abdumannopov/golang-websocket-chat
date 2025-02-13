package models

import (
	"database/sql"
	"log"
	_ "modernc.org/sqlite" // Пакет драйвера
)

type Users struct {
	ID       int    `json:"id"`
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RefreshToken struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func InitDB() *sql.DB {
	db, err := sql.Open("sqlite", "./project.db")
	if err != nil {
		log.Fatal(err)
	}

	userTable := `
	CREATE TABLE IF NOT EXISTS users (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    username TEXT NOT NULL UNIQUE,
	    email TEXT NOT NULL UNIQUE,
	    password TEXT NOT NULL,
	    salt TEXT NOT NULL,
	    role TEXT NOT NULL
	)
	`
	_, err = db.Exec(userTable)
	if err != nil {
		log.Fatal(err)
	}

	refreshTokenTable := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    user_id INTEGER NOT NULL,
	    token TEXT NOT NULL UNIQUE,
	    expires_at TIMESTAMP NOT NULL,
	    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)
	`
	_, err = db.Exec(refreshTokenTable)
	if err != nil {
		log.Fatal(err)
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		from_user TEXT,
		to_user TEXT,
		content TEXT,
		created_at DATETIME
	);
	`
	if _, err := db.Exec(createTableQuery); err != nil {
		log.Fatal("Ошибка создания таблицы:", err)
	}

	return db
}
