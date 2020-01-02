package middleware

import (
	"clashconfig/logging"

	"github.com/gin-gonic/gin"
)

func Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		ip := c.ClientIP()
		logging.Info(ip, path+"?"+raw)
		c.Next()
	}
}
