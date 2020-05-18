package middleware

import (
	"clashconfig/util"
	"context"
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
		rawURI := c.Request.URL.RawQuery
		if !(strings.HasPrefix(rawURI, "sub_link=http") || strings.HasPrefix(rawURI, "lan_link=http")) {
			c.String(http.StatusBadRequest, "sub_link=需要V2ray的订阅链接.")
			c.Abort()
			return
		}
		sublink := rawURI[9:]
		s, err := httpGet(sublink)//s - sub config raw content

		if nil != err {
			c.String(http.StatusBadRequest, "sublink 不能访问")
			c.Abort()
			return
		}
		protoPrefix := "vmess://"
		switch c.Request.URL.Path {
		case "/ssr2clashr":
			protoPrefix = "ssr://"

		}
		decodeBody, err := util.Base64DecodeStripped(string(s))//decodeBody: decoded config
		if nil != err || !strings.HasPrefix(string(decodeBody), protoPrefix) {
			log.Println(err)
			c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
			c.Abort()
			return
		}

		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}

		if strings.HasPrefix(rawURI, "sub_link") {
			requestURL := fmt.Sprintf("%s://%s%s?lan_link=%s", scheme, c.Request.Host, c.Request.URL.Path, sublink)
			c.Set("request_url", requestURL)//lan link
		}

		c.Set("decodebody", string(decodeBody))
		c.Next()
	}
}
