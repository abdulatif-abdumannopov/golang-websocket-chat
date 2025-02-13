package handlers

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorutines/authorization_tools"
	"net/http"
)

// ChatPreview — структура для списка чатов
type ChatPreview struct {
	Username    string `json:"username"`     // Имя собеседника
	LastMessage string `json:"last_message"` // Последнее сообщение
	Timestamp   string `json:"timestamp"`    // Время последнего сообщения
}

type ChatMessage struct {
	ID        int    `json:"id"`
	FromUser  string `json:"from"`
	ToUser    string `json:"to"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}

// GetUserChats — загрузка списка чатов для пользователя
func GetUserChats(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получаем токен и извлекаем username
		tokenString, err := authorization_tools.ExtractToken(c.GetHeader("Authorization"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		status, err := authorization_tools.ValidateAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !status {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		claims, err := authorization_tools.GetClaims(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен"})
			return
		}
		username := claims["username"].(string)

		// SQL-запрос: Найти все чаты пользователя и последние сообщения
		query := `
			SELECT 
				CASE 
					WHEN from_user = ? THEN to_user 
					ELSE from_user 
				END AS username, 
				content, created_at 
			FROM messages 
			WHERE from_user = ? OR to_user = ? 
			GROUP BY username
			ORDER BY created_at DESC;`

		rows, err := db.Query(query, username, username, username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
			return
		}
		defer rows.Close()

		var chats []ChatPreview
		for rows.Next() {
			var chat ChatPreview
			if err := rows.Scan(&chat.Username, &chat.LastMessage, &chat.Timestamp); err != nil {
				continue
			}
			chats = append(chats, chat)
		}

		c.JSON(http.StatusOK, chats)
	}
}

// GetChatMessages — загрузка сообщений с определённым пользователем
func GetChatMessages(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := authorization_tools.ExtractToken(c.GetHeader("Authorization"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		status, err := authorization_tools.ValidateAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !status {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		claims, err := authorization_tools.GetClaims(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен"})
			return
		}
		currentUser := claims["username"].(string)

		// Получаем имя собеседника из параметров запроса
		otherUser := c.Query("user")
		if otherUser == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан пользователь"})
			return
		}

		// SQL-запрос: Получаем все сообщения между пользователями
		query := `
			SELECT id, from_user, to_user, content, created_at 
			FROM messages 
			WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) 
			ORDER BY created_at ASC;`

		rows, err := db.Query(query, currentUser, otherUser, otherUser, currentUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
			return
		}
		defer rows.Close()

		var messages []ChatMessage
		for rows.Next() {
			var msg ChatMessage
			if err := rows.Scan(&msg.ID, &msg.FromUser, &msg.ToUser, &msg.Content, &msg.Timestamp); err != nil {
				continue
			}
			messages = append(messages, msg)
		}

		c.JSON(http.StatusOK, messages)
	}
}

func DeleteMessage(db *sql.DB, messageID int, username string) error {
	var author string
	err := db.QueryRow("SELECT from_user FROM messages WHERE id = ?", messageID).Scan(&author)
	if err != nil {
		return fmt.Errorf("ошибка при получении автора сообщения: %v", err)
	}

	// Проверяем, является ли текущий пользователь автором
	if author != username {
		return fmt.Errorf("пользователь %s пытался удалить чужое сообщение", username)
	}

	// Удаляем сообщение
	_, err = db.Exec("DELETE FROM messages WHERE id = ?", messageID)
	if err != nil {
		return fmt.Errorf("ошибка при удалении сообщения %d: %v", messageID, err)
	}

	// Отправляем уведомление WebSocket-клиентам
	SendDeleteMessageNotification(messageID)
	fmt.Printf("Сообщение %d удалено пользователем %s\n", messageID, username)

	return nil
}

func EditMessage(db *sql.DB, messageID int, username string, newContent string) error {
	var author string
	err := db.QueryRow("SELECT from_user FROM messages WHERE id = ?", messageID).Scan(&author)
	if err != nil {
		return fmt.Errorf("ошибка при получении автора сообщения: %v", err)
	}

	// Проверяем, является ли текущий пользователь автором
	if author != username {
		return fmt.Errorf("пользователь %s пытался удалить чужое сообщение", username)
	}

	query := `UPDATE messages SET content = ? WHERE id = ? AND from_user = ?`
	res, err := db.Exec(query, newContent, messageID, username)
	if err != nil {
		return fmt.Errorf("ошибка обновления сообщения: %v", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("сообщение не найдено или у вас нет прав")
	}

	// Отправляем всем клиентам событие об изменении сообщения
	SendEditMessageNotification(messageID, newContent)
	return nil
}
