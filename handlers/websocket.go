package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorutines/authorization_tools"
	"log"
	"net/http"
	"sync"
	"time"
)

// Message — структура для передачи и хранения сообщений
type Message struct {
	ID        int       `json:"id"`
	From      string    `json:"from"`       // отправитель
	To        string    `json:"to"`         // получатель
	Content   string    `json:"content"`    // текст сообщения
	CreatedAt time.Time `json:"created_at"` // время создания
}

// clients хранит активные WebSocket-соединения: ключ — идентификатор пользователя
var clients = make(map[string]*websocket.Conn)
var clientsMu sync.RWMutex

// upgrader для перехода от HTTP к WebSocket
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // разрешаем подключения отовсюду
	},
}

func ExtractUsername(tokenString string) (string, error) {
	claims, err := authorization_tools.GetClaims(tokenString)
	if err != nil {
		return "", fmt.Errorf("не удалось получить claims из токена: %v", err)
	}

	username, ok := claims["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("токен не содержит username")
	}

	return username, nil
}

// WebSocketHandler обрабатывает установление WebSocket-соединения и получение сообщений
// db передаётся для сохранения сообщений в базу
func WebSocketHandler(c *gin.Context, db *sql.DB) {
	tokenString := c.Query("token")

	username, err := ExtractUsername(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка WebSocket"})
		return
	}
	fmt.Printf("Пользователь %s подключился\n", username)

	clientsMu.Lock()
	clients[username] = conn
	clientsMu.Unlock()

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("Ошибка чтения сообщения от %s: %v\n", username, err)
			conn.Close()
			clientsMu.Lock()
			delete(clients, username)
			clientsMu.Unlock()
			break
		}

		var event map[string]interface{}
		if err := json.Unmarshal(msgBytes, &event); err != nil {
			fmt.Printf("Ошибка парсинга JSON от %s: %v\n", username, err)
			continue
		}

		action, ok := event["action"].(string)
		if !ok {
			fmt.Println("Отсутствует action в WebSocket-сообщении")
			continue
		}

		switch action {
		case "send_message":
			var msg Message
			if err := json.Unmarshal(msgBytes, &msg); err != nil {
				fmt.Printf("Ошибка парсинга JSON от %s: %v\n", username, err)
				continue
			}

			msg.From = username
			msg.CreatedAt = time.Now()

			// Сохраняем сообщение в БД и обновляем msg.ID
			_, err := SaveMessageToDB(db, &msg)
			if err != nil {
				fmt.Printf("Ошибка сохранения сообщения в БД: %v\n", err)
				continue
			}
			fmt.Printf("Получено сообщение от %s для %s: %s (ID: %d)\n", msg.From, msg.To, msg.Content, msg.ID)
			go sendPrivateMessage(msg)

		case "delete_message":
			messageIDFloat, ok := event["message_id"].(float64)
			if !ok {
				fmt.Println("Неверный формат message_id")
				continue
			}
			messageID := int(messageIDFloat)

			if err := DeleteMessage(db, messageID, username); err != nil {
				fmt.Println(err)
				continue
			}
		case "edit_message":
			messageIDFloat, ok := event["message_id"].(float64)
			if !ok {
				fmt.Println("Неверный формат message_id")
				continue
			}
			messageID := int(messageIDFloat)

			newContent, ok := event["new_content"].(string)
			if !ok || newContent == "" {
				fmt.Println("Неверный формат new_content")
				continue
			}

			if err := EditMessage(db, messageID, username, newContent); err != nil {
				fmt.Println("Ошибка редактирования сообщения:", err)
				continue
			}

		default:
			fmt.Printf("Неизвестный action: %s\n", action)
		}
	}
}

// SaveMessageToDB сохраняет сообщение в базу через database/sql
func SaveMessageToDB(db *sql.DB, msg *Message) (int, error) {
	query := `INSERT INTO messages (from_user, to_user, content, created_at) VALUES (?, ?, ?, ?)`
	res, err := db.Exec(query, msg.From, msg.To, msg.Content, msg.CreatedAt)
	if err != nil {
		return 0, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	msg.ID = int(id) // Обновляем ID в исходном объекте
	return msg.ID, nil
}

type SendMessageEvent struct {
	Action    string `json:"action"`
	MessageID int    `json:"message_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Content   string `json:"content"`
	Created   string `json:"created"`
}

func sendPrivateMessage(msg Message) {
	event := SendMessageEvent{
		Action:    "send_message",
		MessageID: msg.ID,
		From:      msg.From,
		To:        msg.To,
		Content:   msg.Content,
		Created:   msg.CreatedAt.Format(time.RFC3339),
	}

	msgBytes, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("Ошибка маршалинга события: %v\n", err)
		return
	}

	clientsMu.RLock()
	recipientConn, recipientExists := clients[msg.To]
	senderConn, senderExists := clients[msg.From]
	clientsMu.RUnlock()

	// Отправка получателю
	if recipientExists {
		if err := recipientConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
			fmt.Printf("Ошибка отправки получателю %s: %v\n", msg.To, err)
			recipientConn.Close()
			clientsMu.Lock()
			if clients[msg.To] == recipientConn { // Проверяем, не изменился ли клиент
				delete(clients, msg.To)
			}
			clientsMu.Unlock()
		}
	} else {
		fmt.Printf("Пользователь %s не найден или не подключён\n", msg.To)
	}

	// Отправка отправителю (чтобы он сразу видел своё сообщение)
	if senderExists {
		if err := senderConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
			fmt.Printf("Ошибка отправки отправителю %s: %v\n", msg.From, err)
			senderConn.Close()
			clientsMu.Lock()
			if clients[msg.From] == senderConn { // Проверяем, не изменился ли клиент
				delete(clients, msg.From)
			}
			clientsMu.Unlock()
		}
	}
}

type DeleteMessageEvent struct {
	Action    string `json:"action"`
	MessageID int    `json:"message_id"`
}

// SendDeleteMessageNotification — отправляет всем WebSocket-клиентам уведомление об удалении сообщения
func SendDeleteMessageNotification(messageID int) {
	clientsMu.RLock()
	defer clientsMu.RUnlock()

	event := DeleteMessageEvent{
		Action:    "delete_message",
		MessageID: messageID,
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Ошибка маршалинга JSON: %v", err)
		return
	}

	// Отправляем сообщение всем активным клиентам
	for username, conn := range clients {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Ошибка отправки удаления пользователю %s: %v", username, err)
			conn.Close()
			delete(clients, username)
		}
	}
}

// SendEditMessageNotification — отправляет клиентам уведомление об изменении сообщения
func SendEditMessageNotification(messageID int, newContent string) {
	clientsMu.RLock()
	defer clientsMu.RUnlock()

	event := map[string]interface{}{
		"action":      "edit_message",
		"message_id":  messageID,
		"new_content": newContent,
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Ошибка маршалинга JSON: %v", err)
		return
	}

	for username, conn := range clients {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("Ошибка отправки редактирования пользователю %s: %v", username, err)
			conn.Close()
			delete(clients, username)
		}
	}
}
