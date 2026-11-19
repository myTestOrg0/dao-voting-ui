package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

func main() {
	tag, _ := language.Parse("en-US")
	var out map[string]interface{}
	_ = yaml.Unmarshal([]byte("a: 1"), &out)
	r := gin.New()
	fmt.Println(tag, out, r != nil)
}
