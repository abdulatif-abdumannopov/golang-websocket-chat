package routes

import (
	"database/sql"
	"github.com/gin-gonic/gin"
	"gorutines/handlers"
	"net/http"
)

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")

		// Если это OPTIONS-запрос, сразу завершаем обработку
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func RegisterRoutes(r *gin.Engine, db *sql.DB) {
	r.GET("/users", handlers.GetUsers(db))
	r.POST("/users", handlers.CreateUsers(db))
	r.POST("/login", handlers.Login(db))
	r.POST("/delete", handlers.DeleteUser(db))
	r.POST("/encrypt", handlers.CryptText())
	r.POST("/decrypt", handlers.DecryptText())
	r.POST("/refresh", handlers.RefreshToken(db))
	r.GET("/get-chats", handlers.GetUserChats(db))
	r.GET("/get-messages", handlers.GetChatMessages(db))
	//r.POST("/delete-message", handlers.DeleteMessage(db))
	//r.POST("/update-message", handlers.UpdateMessage(db))

	r.GET("/ws", func(c *gin.Context) {
		handlers.WebSocketHandler(c, db)
	})
}
