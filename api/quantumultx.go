package api

import (
	"bufio"
	"clashconfig/util"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

/*
;vmess=ws-c.example.com:80, method=chacha20-ietf-poly1305, password= 23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs-host=ws-c.example.com, obfs=ws, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=Sample-H

;vmess=ws-tls-b.example.com:443, method=chacha20-ietf-poly1305, password= 23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs-host=ws-tls-b.example.com, obfs=wss, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=Sample-I

;vmess=vmess-a.example.com:80, method=aes-128-gcm, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, fast-open=false, udp-relay=false, tag=Sample-J

;vmess=vmess-b.example.com:80, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, fast-open=false, udp-relay=false, tag=Sample-K

;vmess=vmess-over-tls.example.com:443, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291,, obfs-host=vmess-over-tls.example.com, obfs=over-tls, fast-open=false, udp-relay=false, tag=Sample-L
*/

type QuantumultXVmess struct {
	Vmess    string `json:"vmess"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	OBFSHost string `json:"obfs-host,omitempty"`
	OBFS     string `json:"obfs,omitempty"`
	OBFSURI  string `json:"obfs-uri,omitempty"`
	FastOpen string `json:"fast-open,omitempty"`
	UDPRelay string `json:"udp-relay,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

func (q *QuantumultXVmess) ToString() string {
	// types := reflect.TypeOf(*q)
	// values := reflect.ValueOf(*q)
	// var s string
	// for i := 0; i < types.NumField(); i++ {
	// 	jsonTag := types.Field(i).Tag.Get("json")
	// 	jsonTags := strings.Split(jsonTag, ",")
	// 	value := values.Field(i).String()
	// 	if len(jsonTags) == 2 && "" == value {
	// 		continue
	// 	}
	// 	s += fmt.Sprintf("%s=%s", jsonTags[0], value)
	// 	if i != types.NumField()-1 {
	// 		s += ","
	// 	}
	// }

	var outs = []string{}
	outs = append(outs, fmt.Sprintf("vmess=%s", q.Vmess))
	outs = append(outs, fmt.Sprintf("method=%s", q.Method))
	outs = append(outs, fmt.Sprintf("password=%s", q.Password))
	if strings.HasPrefix(q.OBFS, "ws") {
		outs = append(outs, fmt.Sprintf("obfs-host=%s", q.OBFSHost))
		outs = append(outs, fmt.Sprintf("obfs=%s", q.OBFS))
		outs = append(outs, fmt.Sprintf("obfs-uri=%s", q.OBFSURI))
	} else if "over-tls" == q.OBFS {
		outs = append(outs, fmt.Sprintf("obfs=%s", q.OBFS))
	}
	outs = append(outs, fmt.Sprintf("fast-open=%s", q.FastOpen))
	outs = append(outs, fmt.Sprintf("udp-relay=%s", q.UDPRelay))
	outs = append(outs, fmt.Sprintf("tag=%s", q.Tag))
	return strings.Join(outs, ",")
}

func V2ray2Quanx(c *gin.Context) {
	decodeBody := c.GetString("decodebody")

	scanner := bufio.NewScanner(strings.NewReader(decodeBody))
	var configs string
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "vmess://") {
			continue
		}
		s := scanner.Text()[8:]
		s = strings.TrimSpace(s)
		vmconfig, err := util.Base64DecodeStripped(s)
		if err != nil {
			continue
		}
		vmess := Vmess{}
		err = json.Unmarshal(vmconfig, &vmess)
		if err != nil {
			log.Fatalln(err)
			continue
		}
		qunx := QuantumultXVmess{}
		qunx.Tag = vmess.PS
		// qunx.Method = "chacha20-ietf-poly1305"
		qunx.Method = vmess.Type
		qunx.Password = vmess.ID
		qunx.UDPRelay = "false"
		qunx.FastOpen = "false"

		port := vmess.Port
		switch port.(type) {
		case string:
			qunx.Vmess = fmt.Sprintf("%s:%s", vmess.Add, port.(string))
		case int:
			qunx.Vmess = fmt.Sprintf("%s:%d", vmess.Add, port.(int))
		case float64:
			qunx.Vmess = fmt.Sprintf("%s:%d", vmess.Add, int(port.(float64)))
		default:
			continue
		}

		if vmess.TLS == "tls" {
			qunx.OBFS = "over-tls"
		}
		if "ws" == vmess.Net {
			if vmess.TLS == "tls" {
				qunx.OBFS = "wss"
			} else {
				qunx.OBFS = "ws"
			}
			qunx.OBFSHost = vmess.Host
			qunx.OBFSURI = vmess.Path
		}

		configs += qunx.ToString() + "\n"
	}

	requestURL := c.GetString("request_url")
	if requestURL != "" {
		quantumultxParams := map[string][]string{
			"server_remote": []string{
				fmt.Sprintf("%s, tag=Convert", requestURL),
			},
		}
		b, err := json.Marshal(quantumultxParams)
		if err != nil {
			c.String(http.StatusBadRequest, "转换错误")
			return
		}
		quantumultx := fmt.Sprintf("quantumult-x:///update-configuration?remote-resource=%s", url.QueryEscape(string(b)))
		c.Redirect(http.StatusMovedPermanently, quantumultx)
	} else {
		// c.String(http.StatusOK, configs)
		c.String(http.StatusOK, util.UnicodeEmojiDecode(configs))
	}

}
