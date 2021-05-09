package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"clashconfig/util"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

type Vmess struct {
	Add  string      `json:"add"`
	Aid  interface{} `json:"aid"`
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

type ClashVmess struct {
	Name           string            `json:"name,omitempty"`
	Type           string            `json:"type,omitempty"`
	Server         string            `json:"server,omitempty"`
	Port           interface{}       `json:"port,omitempty"`
	UUID           string            `json:"uuid,omitempty"`
	AlterID        interface{}       `json:"alterId,omitempty"`
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

type ClashSS struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	Server     string      `json:"server"`
	Port       interface{} `json:"port"`
	Password   string      `json:"password"`
	Cipher     string      `json:"cipher"`
	Plugin     string      `json:"plugin"`
	PluginOpts PluginOpts  `json:"plugin-opts"`
}

type PluginOpts struct {
	Mode string `json:"mode"`
	Host string `json:"host"`
}

type SSD struct {
	Airport      string  `json:"airport"`
	Port         int     `json:"port"`
	Encryption   string  `json:"encryption"`
	Password     string  `json:"password"`
	TrafficUsed  float64 `json:"traffic_used"`
	TrafficTotal float64 `json:"traffic_total"`
	Expiry       string  `json:"expiry"`
	URL          string  `json:"url"`
	Servers      []struct {
		ID            int     `json:"id"`
		Server        string  `json:"server"`
		Ratio         float64 `json:"ratio"`
		Remarks       string  `json:"remarks"`
		Port          string  `json:"port"`
		Encryption    string  `json:"encryption"`
		Password      string  `json:"password"`
		Plugin        string  `json:"plugin"`
		PluginOptions string  `json:"plugin_options"`
	} `json:"servers"`
}

type Clash struct {
	Port      int `yaml:"port"`
	SocksPort int `yaml:"socks-port"`
	RedirPort int `yaml:"redir-port"`
	// Authentication     []string                 `yaml:"authentication"`
	AllowLan           bool   `yaml:"allow-lan"`
	Mode               string `yaml:"mode"`
	LogLevel           string `yaml:"log-level"`
	ExternalController string `yaml:"external-controller"`
	Dns               map[string]interface{}   `yaml:"dns"`
	// ExternalUI         string                   `yaml:"external-ui"`
	// Secret             string                   `yaml:"secret"`
	// Experimental       map[string]interface{} 	`yaml:"experimental"`
	Proxy             []map[string]interface{} `yaml:"proxies"`
	ProxyGroup        []map[string]interface{} `yaml:"proxy-groups"`
	Rule              []string                 `yaml:"rules"`
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
	decodeBodyInterface, _ := c.Get("decodebody")

	decodeBodySlice := decodeBodyInterface.([]string)

	var vmesss []interface{}
	filterNodeMap := make(map[string]int)
	FilterSubLinkMap := make(map[string]struct{})
	for _, v := range decodeBodySlice {

		// 过滤重复订阅链接
		if _, ok := FilterSubLinkMap[v]; ok {
			continue
		}
		FilterSubLinkMap[v] = struct{}{}

		scanner := bufio.NewScanner(strings.NewReader(v))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "vmess://") {
				s := scanner.Text()[8:]
				s = strings.TrimSpace(s)
				clashVmess := v2rConf(s, filterNodeMap)
				if clashVmess.Name != "" {
					vmesss = append(vmesss, clashVmess)
				}
			}
		}

	}
	clash := Clash{}
	r := clash.LoadTemplate("ConnersHua.yaml", vmesss)
	if r == nil {
		c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
		return
	}

	requestURL := c.GetString("request_url")
	if requestURL != "" {
		clashx := fmt.Sprintf("clash://install-config?url=%s", url.QueryEscape(requestURL))
		c.Redirect(http.StatusMovedPermanently, clashx)
	} else {
		c.String(http.StatusOK, util.UnicodeEmojiDecode(string(r)))
	}
}

func v2rConf(s string, filterNodeMap map[string]int) ClashVmess {
	vmconfig, err := util.Base64DecodeStripped(s)
	if err != nil {
		return ClashVmess{}
	}
	vmess := Vmess{}
	err = json.Unmarshal(vmconfig, &vmess)
	if err != nil {
		log.Println(err)
		return ClashVmess{}
	}
	clashVmess := ClashVmess{}
	clashVmess.Name = vmess.PS
	if v, ok := filterNodeMap[clashVmess.Name]; ok {
		v++
		filterNodeMap[clashVmess.Name] = v
		clashVmess.Name = clashVmess.Name + strconv.Itoa(v)
	} else {
		filterNodeMap[clashVmess.Name] = 0
	}

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

	return clashVmess
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
	decodeBodyInterface, _ := c.Get("decodebody")

	decodeBodySlice := decodeBodyInterface.([]string)

	var ssrs []interface{}
	filterNodeMap := make(map[string]int)
	FilterSubLinkMap := make(map[string]struct{})
	for _, v := range decodeBodySlice {

		// 过滤重复订阅链接
		if _, ok := FilterSubLinkMap[v]; ok {
			continue
		}
		FilterSubLinkMap[v] = struct{}{}

		scanner := bufio.NewScanner(strings.NewReader(v))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "ssr://") {
				s := scanner.Text()[6:]
				s = strings.TrimSpace(s)
				ssr := ssrConf(s, filterNodeMap)
				if ssr.Name != "" {
					ssrs = append(ssrs, ssr)
				}
			}
		}
	}

	clash := Clash{}
	r := clash.LoadTemplate("ConnersHua.yaml", ssrs)
	if r == nil {
		c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
		return
	}
	c.String(http.StatusOK, util.UnicodeEmojiDecode(string(r)))
}

func ssrConf(s string, filterNodeMap map[string]int) ClashRSSR {
	rawSSRConfig, err := util.Base64DecodeStripped(s)
	if err != nil {
		return ClashRSSR{}
	}
	params := strings.Split(string(rawSSRConfig), `:`)
	if 6 != len(params) {
		return ClashRSSR{}
	}
	ssr := ClashRSSR{}
	ssr.Type = "ssr"
	ssr.Server = params[SSRServer]
	ssr.Port = params[SSRPort]
	ssr.Protocol = params[SSRProtocol]
	ssr.Cipher = params[SSRCipher]
	ssr.OBFS = params[SSROBFS]

	// 如果兼容ss协议，就转换为clash的ss配置
	// https://github.com/Dreamacro/clash
	if "origin" == ssr.Protocol && "plain" == ssr.OBFS {
		switch ssr.Cipher {
		case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
			"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
			"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
			"rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
			"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
			ssr.Type = "ss"
		}
	}
	suffix := strings.Split(params[SSRSuffix], "/?")
	if 2 != len(suffix) {
		return ClashRSSR{}
	}
	passwordBase64 := suffix[0]
	password, err := util.Base64DecodeStripped(passwordBase64)
	if err != nil {
		return ClashRSSR{}
	}
	ssr.Password = string(password)

	m, err := url.ParseQuery(suffix[1])
	if err != nil {
		return ClashRSSR{}
	}

	for k, v := range m {
		de, err := util.Base64DecodeStripped(v[0])
		if err != nil {
			return ClashRSSR{}
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
			ssrName := ssr.Name
			if v, ok := filterNodeMap[ssrName]; ok {
				v++
				filterNodeMap[ssrName] = v
				ssr.Name = ssrName + strconv.Itoa(v)
			} else {
				filterNodeMap[ssrName] = 0
			}
			continue
		case "group":
			continue
		}
	}

	if filterNode(ssr.Name) {
		return ClashRSSR{}
	}

	return ssr
}

func ssConf(s string, filterNodeMap map[string]int) ClashSS {
	sp := strings.Split(s, "@")
	rawSSRConfig, err := util.Base64DecodeStripped(sp[0])
	if err != nil {
		return ClashSS{}
	}
	params := strings.Split(string(rawSSRConfig), `:`)
	if 2 != len(params) {
		return ClashSS{}
	}

	ss := ClashSS{}
	ss.Type = "ss"
	ss.Cipher = params[0]
	ss.Password = params[1]
	unescape, err := url.PathUnescape(sp[1])

	chunk1 := strings.Split(unescape, "?")
	add := strings.Split(chunk1[0], ":")
	ss.Server = add[0]
	ss.Port = add[1]

	chunk2 := strings.Split(chunk1[1], ";")
	ss.Plugin = strings.Split(chunk2[0], "=")[1]
	switch {
	case strings.Contains(ss.Plugin, "obfs"):
		ss.Plugin = "obfs"
	}

	chunk3 := strings.Split(chunk2[1], "#")
	if len(chunk3) < 2 {
		return ClashSS{}
	}

	chunk4 := strings.Split(chunk3[0], ";")
	p := PluginOpts{
		Mode: strings.Split(chunk4[0], "=")[1],
	}
	if len(chunk4) > 1 {
		p.Host = strings.Split(chunk4[1], "=")[1]
	}

	ss.Name = chunk3[1]
	ss.PluginOpts = p
	if v, ok := filterNodeMap[chunk3[1]]; ok {
		v++
		filterNodeMap[chunk3[1]] = v
		ss.Name = chunk3[1] + strconv.Itoa(v)
	} else {
		filterNodeMap[chunk3[1]] = 0
	}

	return ss
}

func ssdConf(ssdJson string) []ClashSS {
	var ssd SSD
	err := json.Unmarshal([]byte(ssdJson), &ssd)
	if err != nil {
		log.Println("ssd json unmarshal err:", err)
		return nil
	}

	var clashSSSlice []ClashSS
	for _, server := range ssd.Servers {

		if filterNode(server.Remarks) {
			continue
		}

		options, err := url.ParseQuery(server.PluginOptions)
		if err != nil {
			continue
		}

		var ss ClashSS
		ss.Type = "ss"
		ss.Name = server.Remarks
		ss.Cipher = server.Encryption
		ss.Password = server.Password
		ss.Server = server.Server
		ss.Port = server.Port
		ss.Plugin = server.Plugin
		ss.PluginOpts = PluginOpts{
			Mode: options["obfs"][0],
			Host: options["obfs-host"][0],
		}

		switch {
		case strings.Contains(ss.Plugin, "obfs"):
			ss.Plugin = "obfs"
		}

		clashSSSlice = append(clashSSSlice, ss)
	}

	return clashSSSlice
}

func All(c *gin.Context) {
	decodeBodyInterface, _ := c.Get("decodebody")

	isClash := c.Query("clash")

	decodeBodySlice := decodeBodyInterface.([]string)

	var proxis []interface{}
	filterNodeMap := make(map[string]int)
	FilterSubLinkMap := make(map[string]struct{})
	for _, v := range decodeBodySlice {

		// 过滤重复订阅链接
		if _, ok := FilterSubLinkMap[v]; ok {
			continue
		}
		FilterSubLinkMap[v] = struct{}{}

		// ssd
		if strings.Contains(v, "airport") {
			ssSlice := ssdConf(v)
			for _, ss := range ssSlice {
				proxis = append(proxis, ss)
			}
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(v))
		for scanner.Scan() {
			switch {
			case strings.HasPrefix(scanner.Text(), "ssr://"):
				if isClash == "1" {
					continue
				}
				s := scanner.Text()[6:]
				s = strings.TrimSpace(s)
				ssr := ssrConf(s, filterNodeMap)
				if ssr.Name != "" {
					proxis = append(proxis, ssr)
				}
			case strings.HasPrefix(scanner.Text(), "vmess://"):
				s := scanner.Text()[8:]
				s = strings.TrimSpace(s)
				clashVmess := v2rConf(s, filterNodeMap)
				if clashVmess.Name != "" && !filterNode(clashVmess.Name) {
					proxis = append(proxis, clashVmess)
				}
			case strings.HasPrefix(scanner.Text(), "ss://"):
				s := scanner.Text()[5:]
				s = strings.TrimSpace(s)
				ss := ssConf(s, filterNodeMap)
				if ss.Name != "" {
					proxis = append(proxis, ss)
				}
			}
		}
	}

	clash := Clash{}
	r := clash.LoadTemplate("ConnersHua.yaml", proxis)
	if r == nil {
		c.String(http.StatusBadRequest, "sublink 返回数据格式不对")
		return
	}
	c.String(http.StatusOK, util.UnicodeEmojiDecode(string(r)))
}

func filterNode(nodeName string) bool {

	if strings.Contains(nodeName, "阿里云上海中转") {
		return true
	}

	if strings.Contains(nodeName, "微信") {
		return true
	}

	// 过滤官网
	if strings.Contains(nodeName, "官网") {
		return true
	}

	// 过滤剩余流量
	if strings.Contains(nodeName, "剩余流量") {
		return true
	}

	if strings.Contains(nodeName, "过期时间") {
		return true
	}

	return false
}
