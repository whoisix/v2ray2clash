package middleware

import (
	"clashconfig/util"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Result struct {
	r   *http.Response
	err error
}

func httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := make(chan Result)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		c <- Result{r: resp, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-c:
		if res.err != nil || res.r.StatusCode != http.StatusOK {
			return nil, err
		}
		defer res.r.Body.Close()
		s, err := ioutil.ReadAll(res.r.Body)
		return s, err
	}
}

func PreMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Request.URL.String()
		idx := strings.Index(query, "sub_link=")

		if idx < 0 {
			c.String(http.StatusBadRequest, "sub_link=订阅链接.")
			c.Abort()
			return
		}

		sublinks := query[idx+9:]
		if sublinks == "" {
			c.String(http.StatusBadRequest, "sub_link=订阅链接.")
			c.Abort()
			return
		}

		linkSlice := strings.Split(sublinks, ",")

		decodeBodySlice := make([]string, 0)
		for _, v := range linkSlice {
			s, err := httpGet(v)

			if nil != err {
				c.String(http.StatusBadRequest, "sublink 不能访问")
				c.Abort()
				return
			}
			protoPrefix := "vmess://"
			protoCheck := true
			switch c.Request.URL.Path {
			case "/ssr2clashr":
				protoPrefix = "ssr://"
			case "/ssrv2toclashr":
				protoCheck = false
			case "/":
				protoCheck = false
			}

			subContent := string(s)
			// ssd
			if strings.HasPrefix(subContent, "ssd://") {
				subContent = subContent[6:]
				decodeBody, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(subContent)
				if err != nil {
					log.Println("ssd decode err:",err)
					continue
				}

				decodeBodySlice = append(decodeBodySlice, string(decodeBody))
				continue
			}

			decodeBody, err := util.Base64DecodeStripped(subContent)
			if nil != err || (!strings.HasPrefix(string(decodeBody), protoPrefix) && protoCheck) {
				log.Println(err)
				c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
				c.Abort()
				return
			}

			scheme := "http"
			if c.Request.TLS != nil {
				scheme = "https"
			}
			userAgent := c.Request.Header.Get("User-Agent")
			if strings.HasPrefix(userAgent, "Mozilla") &&
				(strings.Contains(userAgent, "Mac OS X") || strings.Contains(userAgent, "Windows")) {
				requestURL := fmt.Sprintf("%s://%s%s", scheme, c.Request.Host, c.Request.URL.String())
				c.Set("request_url", requestURL)
			}

			decodeBodySlice = append(decodeBodySlice, string(decodeBody))
		}

		c.Set("decodebody", decodeBodySlice)
		c.Next()
	}
}
