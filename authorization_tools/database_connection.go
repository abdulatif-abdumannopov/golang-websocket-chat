package authorization_tools

import (
	"database/sql"
)

func FindUsername(username string, db *sql.DB) (string, string, error) {
	var userName string
	var password string
	var salt string
	row := db.QueryRow("SELECT username, password, salt FROM users WHERE username=?", username)
	err := row.Scan(&userName, &password, &salt)
	if err != nil {
		return "", "", err
	}
	return password, salt, nil
}

func DeleteUser(username string, db *sql.DB) error {
	_, err := db.Exec("DELETE FROM users WHERE username=?", username)
	return err
}
