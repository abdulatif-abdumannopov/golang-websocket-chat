package main

import (
	"github.com/gin-gonic/gin"
	"gorutines/models"
	"gorutines/routes"
	"log"
)

func main() {
	db := models.InitDB()
	defer db.Close()

	router := gin.Default()
	router.Use(routes.CORSMiddleware())
	routes.RegisterRoutes(router, db)

	if err := router.Run(":8080"); err != nil {
		log.Fatal("Не удалось запустить сервер: ", err)
	}
}
