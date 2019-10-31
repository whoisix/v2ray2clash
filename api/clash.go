package api

import (
	"bufio"
	"clashconfig/util"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"

	"gopkg.in/yaml.v2"
)

type Vmess struct {
	Add  string      `json:"add"`
	Aid  int         `json:"aid"`
	Host string      `json:"host"`
	ID   string      `json:"id"`
	Net  string      `json:"net"`
	Path string      `json:"path"`
	Port interface{} `json:"port"`
	PS   string      `json:"ps"`
	TLS  string      `json:"tls"`
	Type string      `json:"type"`
	V    string      `json:"v"`
}

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

type ClashVmess struct {
	Name           string            `json:"name,omitempty"`
	Type           string            `json:"type,omitempty"`
	Server         string            `json:"server,omitempty"`
	Port           interface{}       `json:"port,omitempty"`
	UUID           string            `json:"uuid,omitempty"`
	AlterID        int               `json:"alterId,omitempty"`
	Cipher         string            `json:"cipher,omitempty"`
	TLS            bool              `json:"tls,omitempty"`
	Network        string            `json:"network,omitempty"`
	WSPATH         string            `json:"ws-path,omitempty"`
	WSHeaders      map[string]string `json:"ws-headers,omitempty"`
	SkipCertVerify bool              `json:"skip-cert-verify,omitempty"`
}

type ClashRSSR struct {
	Name          string      `json:"name"`
	Type          string      `json:"type"`
	Server        string      `json:"server"`
	Port          interface{} `json:"port"`
	Password      string      `json:"password"`
	Cipher        string      `json:"cipher"`
	Protocol      string      `json:"protocol"`
	ProtocolParam string      `json:"protocolparam"`
	OBFS          string      `json:"obfs"`
	OBFSParam     string      `json:"obfsparam"`
}

type Clash struct {
	Port      int `yaml:"port"`
	SocksPort int `yaml:"socks-port"`
	// RedirPort          int                      `yaml:"redir-port"`
	// Authentication     []string                 `yaml:"authentication"`
	AllowLan           bool   `yaml:"allow-lan"`
	Mode               string `yaml:"mode"`
	LogLevel           string `yaml:"log-level"`
	ExternalController string `yaml:"external-controller"`
	// ExternalUI         string                   `yaml:"external-ui"`
	// Secret             string                   `yaml:"secret"`
	// Experimental       map[string]interface{} 	`yaml:"experimental"`
	Proxy             []map[string]interface{} `yaml:"Proxy"`
	ProxyGroup        []map[string]interface{} `yaml:"Proxy Group"`
	Rule              []string                 `yaml:"Rule"`
	CFWByPass         []string                 `yaml:"cfw-bypass"`
	CFWLatencyTimeout int                      `yaml:"cfw-latency-timeout"`
}

func (this *Clash) LoadTemplate(path string, protos []interface{}) []byte {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		log.Printf("[%s] template doesn't exist.", path)
		return nil
	}
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("[%s] template open the failure.", path)
		return nil
	}
	err = yaml.Unmarshal(buf, &this)
	if err != nil {
		log.Printf("[%s] Template format error.", path)
	}

	this.Proxy = nil

	var proxys []map[string]interface{}
	var proxies []string

	for _, proto := range protos {
		o := reflect.ValueOf(proto)
		nameField := o.FieldByName("Name")
		proxy := make(map[string]interface{})
		j, _ := json.Marshal(proto)
		json.Unmarshal(j, &proxy)
		proxys = append(proxys, proxy)
		this.Proxy = append(this.Proxy, proxy)
		proxies = append(proxies, nameField.String())
	}

	this.Proxy = proxys

	for _, group := range this.ProxyGroup {
		groupProxies := group["proxies"].([]interface{})
		for i, proxie := range groupProxies {
			if "1" == proxie {
				groupProxies = groupProxies[:i]
				var tmpGroupProxies []string
				for _, s := range groupProxies {
					tmpGroupProxies = append(tmpGroupProxies, s.(string))
				}
				tmpGroupProxies = append(tmpGroupProxies, proxies...)
				group["proxies"] = tmpGroupProxies
				break
			}
		}

	}

	d, err := yaml.Marshal(this)
	if err != nil {
		return nil
	}

	return d
}

func V2ray2Clash(c *gin.Context) {

	decodeBody := c.GetString("decodebody")

	scanner := bufio.NewScanner(strings.NewReader(decodeBody))
	var vmesss []interface{}
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
			log.Println(err)
			continue
		}
		clashVmess := ClashVmess{}
		clashVmess.Name = vmess.PS
		clashVmess.Type = "vmess"
		clashVmess.Server = vmess.Add
		switch vmess.Port.(type) {
		case string:
			clashVmess.Port, _ = vmess.Port.(string)
		case int:
			clashVmess.Port, _ = vmess.Port.(int)
		case float64:
			clashVmess.Port, _ = vmess.Port.(float64)
		default:
			continue
		}
		clashVmess.UUID = vmess.ID
		clashVmess.AlterID = vmess.Aid
		clashVmess.Cipher = vmess.Type
		if "" != vmess.TLS {
			clashVmess.TLS = true
		} else {
			clashVmess.TLS = false
		}
		if "ws" == vmess.Net {
			clashVmess.Network = vmess.Net
			clashVmess.WSPATH = vmess.Path
		}

		vmesss = append(vmesss, clashVmess)
	}
	clash := Clash{}
	r := clash.LoadTemplate("ConnersHua.yaml", vmesss)
	if r == nil {
		c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
		return
	}

	requestURL := c.GetString("request_url")
	if requestURL != "" {
		clashx := fmt.Sprintf("clash://install-config?url=%s", url.PathEscape(requestURL))
		c.Redirect(http.StatusMovedPermanently, clashx)
	} else {
		c.String(http.StatusOK, string(r))
	}
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
		quantumultx := fmt.Sprintf("quantumult-x:///update-configuration?remote-resource=%s", url.PathEscape(string(b)))
		c.Redirect(http.StatusMovedPermanently, quantumultx)
	} else {
		c.String(http.StatusOK, configs)
	}

}

const (
	SSRServer = iota
	SSRPort
	SSRProtocol
	SSRCipher
	SSROBFS
	SSRSuffix
)

func SSR2ClashR(c *gin.Context) {
	decodeBody := c.GetString("decodebody")

	scanner := bufio.NewScanner(strings.NewReader(decodeBody))
	var ssrs []interface{}
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "ssr://") {
			continue
		}
		s := scanner.Text()[6:]
		s = strings.TrimSpace(s)
		rawSSRConfig, err := util.Base64DecodeStripped(s)
		if err != nil {
			continue
		}
		params := strings.Split(string(rawSSRConfig), `:`)
		if 6 != len(params) {
			continue
		}
		ssr := ClashRSSR{}
		ssr.Type = "ssr"
		ssr.Server = params[SSRServer]
		ssr.Port = params[SSRPort]
		ssr.Protocol = params[SSRProtocol]
		ssr.Cipher = params[SSRCipher]
		ssr.OBFS = params[SSROBFS]

		suffix := strings.Split(params[SSRSuffix], "/?")
		if 2 != len(suffix) {
			continue
		}
		passwordBase64 := suffix[0]
		password, err := util.Base64DecodeStripped(passwordBase64)
		if err != nil {
			continue
		}
		ssr.Password = string(password)

		m, err := url.ParseQuery(suffix[1])
		if err != nil {
			continue
		}
		for k, v := range m {
			de, err := util.Base64DecodeStripped(v[0])
			if err != nil {
				continue
			}
			switch k {
			case "obfsparam":
				ssr.OBFSParam = string(de)
				continue
			case "protoparam":
				ssr.ProtocolParam = string(de)
				continue
			case "remarks":
				ssr.Name = string(de)
				continue
			case "group":
				continue
			}
		}

		ssrs = append(ssrs, ssr)
	}
	clash := Clash{}
	r := clash.LoadTemplate("ConnersHua.yaml", ssrs)
	if r == nil {
		c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
		return
	}
	c.String(http.StatusOK, string(r))
}
