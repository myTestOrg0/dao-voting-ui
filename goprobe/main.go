package main

import (
	"fmt"
	"os"

	_ "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

func main() {
	var config map[string]string
	data, _ := os.ReadFile(os.Args[1])
	_ = yaml.Unmarshal(data, &config)
	tags, _, _ := language.ParseAcceptLanguage(config["lang"])
	hash, _ := bcrypt.GenerateFromPassword([]byte(config["password"]), 10)
	fmt.Println(tags, len(hash))
	router := gin.Default()
	router.GET("/", func(c *gin.Context) { c.String(200, "ok") })
	_ = router.Run()
}
