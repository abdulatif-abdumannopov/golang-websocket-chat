package authorization_tools

import (
	"database/sql"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"log"
	"os"
	"strings"
	"time"
)

func getJWTSecretKey() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Ошибка при загрузке .env файла")
	}

	secretKey := os.Getenv("JWT_SECRET_KEY")
	return secretKey
}

func ExtractToken(authorizationHeader string) (string, error) {
	const prefix = "Bearer "
	if authorizationHeader == "" {
		return "", errors.New("заголовок Authorization отсутствует")
	}

	if !strings.HasPrefix(authorizationHeader, prefix) {
		return "", errors.New("неверный формат заголовка Authorization")
	}

	return strings.TrimPrefix(authorizationHeader, prefix), nil
}

func GenerateAccessToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"type":     "access",
	})

	return token.SignedString([]byte(getJWTSecretKey()))
}

func GenerateRefreshToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(30 * 24 * time.Hour).Unix(),
		"type":     "refresh",
	})

	return token.SignedString([]byte(getJWTSecretKey()))
}

func ValidateAccessToken(accessToken string) (bool, error) {
	secretKey := getJWTSecretKey()

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("неподдерживаемый метод подписи")
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return false, errors.New("недействительный или истекший access токен")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("не удалось извлечь claims из access токена")
	}

	// Проверяем, что это действительно access токен
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "access" {
		return false, errors.New("неверный тип токена: ожидается access токен")
	}

	return true, nil
}

func GetClaims(currentToken string) (map[string]interface{}, error) {
	secretKey := getJWTSecretKey()

	token, err := jwt.Parse(currentToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("неподдерживаемый метод подписи")
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("недействительный или истекший access токен")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("не удалось извлечь claims из access токена")
	}
	return claims, nil
}

func SetRefreshTokenDB(username string, token string, db *sql.DB) error {
	var userID int
	query := `SELECT id FROM users WHERE username = ?`
	err := db.QueryRow(query, username).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("пользователь не найден")
		}
		log.Println("Ошибка при запросе к базе:", err)
		return err
	}

	insertQuery := `
		INSERT INTO refresh_tokens (user_id, token, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`
	_, err = db.Exec(insertQuery, userID, token, time.Now().Add(30*24*time.Hour), time.Now())
	if err != nil {
		log.Println("Ошибка при сохранении токена в базе:", err)
		return err
	}
	return nil
}

func ValidateRefreshToken(refreshToken string, db *sql.DB) (bool, error) {
	secretKey := getJWTSecretKey()

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("неподдерживаемый метод подписи")
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return false, errors.New("недействительный или истекший refresh токен")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("не удалось извлечь claims из refresh токена")
	}

	// Проверяем, что это действительно refresh токен
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return false, errors.New("неверный тип токена: ожидается refresh токен")
	}

	var tokenInDB string
	query := `SELECT token FROM refresh_tokens WHERE token = ?`
	err = db.QueryRow(query, refreshToken).Scan(&tokenInDB)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, errors.New("refresh токен не найден в базе")
		}
		return false, errors.New("ошибка при запросе к базе: " + err.Error())
	}

	return true, nil
}

func UpdateRefreshToken(refreshToken string, newRefreshToken string, db *sql.DB) error {
	updateQuery := `
		UPDATE refresh_tokens 
		SET token = ?, expires_at = ?
		WHERE token = ?
	`
	_, err := db.Exec(updateQuery, newRefreshToken, time.Now().Add(30*24*time.Hour), refreshToken)
	if err != nil {
		log.Println("Ошибка при обновлении refresh токена в базе:", err)
		return err
	}
	return nil
}
