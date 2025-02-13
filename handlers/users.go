package handlers

import (
	"database/sql"
	"github.com/gin-gonic/gin"
	"gorutines/authorization_tools"
	"gorutines/crypt_tools"
	"gorutines/models"
	"log"
	"net/http"
)

func GetUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var users []models.Users
		rows, err := db.Query("SELECT id, username, email, password FROM users")
		if err != nil {
			log.Println("Ошибка при получении пользователей: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить пользователей"})
			return
		}
		defer rows.Close()

		// Чтение пользователей из базы данных
		for rows.Next() {
			var user models.Users
			if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Password); err != nil {
				log.Println("Ошибка при сканировании данных пользователя: ", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных"})
				return
			}
			users = append(users, user)
		}

		// Отправка списка пользователей в ответ
		c.JSON(http.StatusOK, users)
	}
}

func CreateUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.Users
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		salt, err := authorization_tools.GenerateSalt(32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		hashPassword, err := authorization_tools.HashPassword(user.Password, salt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err = db.Exec("INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)", user.Username, user.Email, hashPassword, salt, "user")
		if err != nil {
			if err.Error() == "UNIQUE constraint failed: users.email" {
				c.JSON(http.StatusConflict, gin.H{
					"error": "Пользователь с таким email уже существует",
				})
				return
			}
			log.Println("Ошибка при вставке пользователя: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать пользователя"})
			return
		}
		row := db.QueryRow("SELECT id FROM users WHERE username = ?", user.Username)
		err = row.Scan(&user.ID)
		if err != nil {
			log.Println("Ошибка при получении ID пользователя: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить ID пользователя"})
			return
		}
		c.JSON(http.StatusCreated, user.Username)
	}
}

func Login(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var credentials struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		storedHash, storedSalt, err := authorization_tools.FindUsername(credentials.Username, db)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := authorization_tools.VerifyPassword(credentials.Password, storedHash, storedSalt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !result {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка учетной записи"})
			return
		}

		accessToken, err := authorization_tools.GenerateAccessToken(credentials.Username)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		refreshToken, err := authorization_tools.GenerateRefreshToken(credentials.Username)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err = authorization_tools.SetRefreshTokenDB(credentials.Username, refreshToken, db)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

		c.JSON(http.StatusOK, gin.H{
			"username":     credentials.Username,
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		})
	}
}

func DeleteUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var credentials struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		storedHash, storedSalt, err := authorization_tools.FindUsername(credentials.Username, db)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := authorization_tools.VerifyPassword(credentials.Password, storedHash, storedSalt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !result {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка учетной записи"})
			return
		}

		err = authorization_tools.DeleteUser(credentials.Username, db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": credentials.Username + " deleted",
		})
	}
}

func RefreshToken(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := authorization_tools.ExtractToken(c.GetHeader("Authorization"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		status, err := authorization_tools.ValidateRefreshToken(token, db)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !status {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка проверки токена"})
			return
		}

		claims, err := authorization_tools.GetClaims(token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		accessToken, err := authorization_tools.GenerateAccessToken(claims["username"].(string))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		refreshToken, err := authorization_tools.GenerateRefreshToken(claims["username"].(string))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err = authorization_tools.UpdateRefreshToken(token, refreshToken, db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		})
	}
}

func CryptText() gin.HandlerFunc {
	return func(c *gin.Context) {
		var credentials struct {
			Text     string `json:"text" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		crypt, err := crypt_tools.EncryptAES(credentials.Text, credentials.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"Crypt": crypt,
		})
	}
}

func DecryptText() gin.HandlerFunc {
	return func(c *gin.Context) {
		var credentials struct {
			Text     string `json:"text" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		text, err := crypt_tools.DecryptAES(credentials.Text, credentials.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"Text": text,
		})
	}
}
