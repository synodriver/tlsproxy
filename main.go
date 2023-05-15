package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	http "github.com/wangluozhe/fhttp"
	"github.com/wangluozhe/requests"
	"github.com/wangluozhe/requests/models"
	"github.com/wangluozhe/requests/transport"
	"github.com/wangluozhe/requests/url"
	"strings"
	"time"
)

func sessionRequestPatched(session *requests.Session, method, rawurl string, request *url.Request, rawBody []byte) (*models.Response, error) {
	if request == nil {
		request = url.NewRequest()
	}
	// request.Body 0  == ""
	req := &models.Request{
		Method:  strings.ToUpper(method),
		Url:     rawurl,
		Params:  request.Params,
		Headers: request.Headers,
		Cookies: request.Cookies,
		Data:    request.Data,
		Files:   request.Files,
		Json:    request.Json,
		Body:    request.Body,
		Auth:    request.Auth,
	}
	preq, err := session.Prepare_request(req)
	if err != nil {
		return nil, err
	}
	if rawBody != nil {
		//fmt.Println("set Arbitrary body", string(rawBody))
		preq.Body = bytes.NewReader(rawBody) // Arbitrary body
	}
	//fmt.Println("check proxy", request.Proxies)
	resp, err := session.Send(preq, request)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func request(method, rawUrl string, headers map[string]string, headerorder []string, pheaderorder []string, body []byte,
	proxy string, timeout time.Duration, AllowRedirects, verify bool, cert []string, ja3 string,
	SupportedSignatureAlgorithms, CertCompressionAlgo []string, RecordSizeLimit int,
	DelegatedCredentials, SupportedVersions, PSKKeyExchangeModes, KeyShareCurves []string,
	H2Settings map[string]int, H2SettingsOrder []string, H2ConnectionFlow int, H2HeaderPriority map[string]interface{}, H2PriorityFrames []map[string]interface{}) (int, map[string]string, []byte, error) {
	req := &url.Request{}
	if proxy != "" {
		//fmt.Println("set proxy", proxy)
		req.Proxies = proxy
	}
	if headers != nil && len(headers) > 0 {
		reqHeaders := url.NewHeaders()
		for k, v := range headers {
			reqHeaders.Set(k, v)
		}
		if headerorder != nil && len(headerorder) > 0 {
			(*reqHeaders)[http.HeaderOrderKey] = headerorder
		}
		if pheaderorder != nil && len(pheaderorder) > 0 {
			(*reqHeaders)[http.PHeaderOrderKey] = pheaderorder
		}
		req.Headers = reqHeaders
	}
	req.Timeout = timeout
	req.AllowRedirects = AllowRedirects
	req.Verify = verify
	if cert != nil && len(cert) > 0 {
		req.Cert = cert
	}
	if ja3 != "" {
		req.Ja3 = ja3
	}
	// set tls extension
	if SupportedSignatureAlgorithms != nil || CertCompressionAlgo != nil || DelegatedCredentials != nil || SupportedVersions != nil || PSKKeyExchangeModes != nil || KeyShareCurves != nil {
		//fmt.Println("set tls extension")
		es := &transport.Extensions{}
		if SupportedSignatureAlgorithms != nil && len(SupportedSignatureAlgorithms) > 0 {
			es.SupportedSignatureAlgorithms = SupportedSignatureAlgorithms
		}
		if CertCompressionAlgo != nil && len(CertCompressionAlgo) > 0 {
			es.CertCompressionAlgo = CertCompressionAlgo
		}
		es.RecordSizeLimit = RecordSizeLimit
		if DelegatedCredentials != nil && len(DelegatedCredentials) > 0 {
			es.DelegatedCredentials = DelegatedCredentials
		}
		if SupportedVersions != nil && len(SupportedVersions) > 0 {
			es.SupportedVersions = SupportedVersions
		}
		if PSKKeyExchangeModes != nil && len(PSKKeyExchangeModes) > 0 {
			es.PSKKeyExchangeModes = PSKKeyExchangeModes
		}
		if KeyShareCurves != nil && len(KeyShareCurves) > 0 {
			es.KeyShareCurves = KeyShareCurves
		}
		tes := transport.ToTLSExtensions(es)
		req.TLSExtensions = tes
	}
	if H2Settings != nil || H2SettingsOrder != nil || H2HeaderPriority != nil || H2PriorityFrames != nil {
		h2s := &transport.H2Settings{}
		if H2Settings != nil && len(H2Settings) > 0 {
			h2s.Settings = H2Settings
		}
		if H2SettingsOrder != nil && len(H2SettingsOrder) > 0 {
			h2s.SettingsOrder = H2SettingsOrder
		}
		h2s.ConnectionFlow = H2ConnectionFlow
		if H2HeaderPriority != nil && len(H2HeaderPriority) > 0 {
			h2s.HeaderPriority = H2HeaderPriority
		}
		if H2PriorityFrames != nil && len(H2PriorityFrames) > 0 {
			h2s.PriorityFrames = H2PriorityFrames
		}
		h2ss := transport.ToHTTP2Settings(h2s)
		req.HTTP2Settings = h2ss
	}

	session := requests.NewSession()

	r, err := sessionRequestPatched(session, method, rawUrl, req, body)
	//r, err := requests.Request(method, rawUrl, req)
	if err != nil {
		return 0, nil, nil, err
	}
	//fmt.Println(r.Text)
	return r.StatusCode, transferrespheaders(r.Headers), r.Content, nil
}

func joinslice(s []string) string {
	builder := &strings.Builder{}
	for _, v := range s {
		builder.WriteString(v)
	}
	return builder.String()
}

func transferrespheaders(rawheaders http.Header) map[string]string {
	headers := make(map[string]string, len(rawheaders))
	for k, v := range rawheaders {
		headers[k] = joinslice(v)
	}
	return headers
}

func transferheader(rawheaders map[string]gjson.Result) map[string]string {
	headers := make(map[string]string, len(rawheaders))
	for k, v := range rawheaders {
		headers[k] = v.String()
	}
	return headers
}

func transferjsonarray(h []gjson.Result) []string {
	ret := make([]string, 0, len(h))
	for _, v := range h {
		ret = append(ret, v.String())
	}
	return ret
}

func main() {
	r := gin.Default()
	r.POST("/request", func(c *gin.Context) {
		data, err := c.GetRawData()
		if err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}
		jsondata := gjson.ParseBytes(data)
		if !jsondata.Get("method").Exists() {
			c.JSON(500, gin.H{
				"error": "method must be given",
			})
			return
		}
		method := jsondata.Get("method").String()
		if !jsondata.Get("url").Exists() {
			c.JSON(500, gin.H{
				"error": "url must be given",
			})
			return
		}
		url := jsondata.Get("url").String()

		// headerorder, optional
		var headerorder []string
		if headerorder_ := jsondata.Get("header_order"); headerorder_.Exists() && headerorder_.IsArray() {
			headerorder = transferjsonarray(headerorder_.Array())
		} else {
			headerorder = nil
		}
		// PHeaderOrder, optional
		var pheaderorder []string
		if pheaderorder_ := jsondata.Get("pheader_order"); pheaderorder_.Exists() && pheaderorder_.IsArray() {
			pheaderorder = transferjsonarray(pheaderorder_.Array())
		} else {
			pheaderorder = nil
		}

		// headers, optional
		var headers map[string]string
		if headers_ := jsondata.Get("headers"); headers_.Exists() && headers_.IsObject() {
			headers = transferheader(jsondata.Get("headers").Map())
		} else {
			headers = nil
		}
		// body, optional
		var body []byte
		if body_ := jsondata.Get("body"); body_.Exists() && body_.Type == gjson.String {
			rawbody, err := base64.StdEncoding.DecodeString(body_.String())
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			body = rawbody
		} else {
			body = nil
		}
		// proxy, optional
		var proxy string
		if proxy_ := jsondata.Get("proxy"); proxy_.Exists() && proxy_.Type == gjson.String {
			proxy = proxy_.String()
		} else {
			proxy = ""
		}
		// timeout, optional
		var timeout time.Duration
		if timeout_ := jsondata.Get("timeout"); timeout_.Exists() && timeout_.Type == gjson.Number {
			timeout = time.Duration(timeout_.Uint()) * time.Second
		} else {
			timeout = 1 * time.Second
		}
		// AllowRedirects, optional
		var AllowRedirects bool
		if AllowRedirects_ := jsondata.Get("allow_redirects"); AllowRedirects_.Exists() && AllowRedirects_.IsBool() {
			AllowRedirects = AllowRedirects_.Bool()
		} else {
			AllowRedirects = true
		}

		// verify, optional
		var verify bool
		if verify_ := jsondata.Get("verify"); verify_.Exists() && verify_.IsBool() {
			verify = verify_.Bool()
		} else {
			verify = true // default will do verify
		}
		// cert, optional
		var cert []string
		if cert_ := jsondata.Get("cert"); cert_.Exists() && cert_.IsArray() {
			cert = transferjsonarray(jsondata.Get("cert").Array())
		} else {
			cert = nil
		}
		// ja3, optional
		var ja3 string
		if ja3_ := jsondata.Get("ja3"); ja3_.Exists() && ja3_.Type == gjson.String {
			ja3 = ja3_.String()
		} else {
			ja3 = ""
		}
		// tls fingerprint, optional
		var SupportedSignatureAlgorithms []string
		if SupportedSignatureAlgorithms_ := jsondata.Get("supported_signature_algorithms"); SupportedSignatureAlgorithms_.Exists() && SupportedSignatureAlgorithms_.IsArray() {
			SupportedSignatureAlgorithms = transferjsonarray(SupportedSignatureAlgorithms_.Array())
		} else {
			SupportedSignatureAlgorithms = nil
		}
		var CertCompressionAlgo []string
		if CertCompressionAlgo_ := jsondata.Get("cert_compression_algo"); CertCompressionAlgo_.Exists() && CertCompressionAlgo_.IsArray() {
			CertCompressionAlgo = transferjsonarray(CertCompressionAlgo_.Array())
		} else {
			CertCompressionAlgo = nil
		}
		var RecordSizeLimit int
		if RecordSizeLimit_ := jsondata.Get("record_size_limit"); RecordSizeLimit_.Exists() && RecordSizeLimit_.Type == gjson.Number {
			RecordSizeLimit = int(RecordSizeLimit_.Uint())
		} else {
			RecordSizeLimit = 4001
		}
		var DelegatedCredentials []string
		if DelegatedCredentials_ := jsondata.Get("delegated_credentials"); DelegatedCredentials_.Exists() && DelegatedCredentials_.IsArray() {
			DelegatedCredentials = transferjsonarray(DelegatedCredentials_.Array())
		} else {
			DelegatedCredentials = nil
		}
		var SupportedVersions []string
		if SupportedVersions_ := jsondata.Get("supported_versions"); SupportedVersions_.Exists() && SupportedVersions_.IsArray() {
			SupportedVersions = transferjsonarray(SupportedVersions_.Array())
		} else {
			SupportedVersions = nil
		}
		var PSKKeyExchangeModes []string
		if PSKKeyExchangeModes_ := jsondata.Get("pskkey_exchange_modes"); PSKKeyExchangeModes_.Exists() && PSKKeyExchangeModes_.IsArray() {
			PSKKeyExchangeModes = transferjsonarray(PSKKeyExchangeModes_.Array())
		} else {
			PSKKeyExchangeModes = nil
		}
		var KeyShareCurves []string
		if KeyShareCurves_ := jsondata.Get("key_share_curves"); KeyShareCurves_.Exists() && KeyShareCurves_.IsArray() {
			KeyShareCurves = transferjsonarray(KeyShareCurves_.Array())
		} else {
			KeyShareCurves = nil
		}
		// h2 fingerprint, optional
		var H2Settings map[string]int
		if H2Settings_ := jsondata.Get("h2settings"); H2Settings_.Exists() && H2Settings_.IsObject() {
			H2Settings = func(d map[string]gjson.Result) map[string]int {
				ret := make(map[string]int, len(d))
				for k, v := range d {
					ret[k] = int(v.Uint())
				}
				return ret
			}(H2Settings_.Map())
		} else {
			H2Settings = nil
		}
		var H2SettingsOrder []string
		if SettingsOrder_ := jsondata.Get("h2settings_order"); SettingsOrder_.Exists() && SettingsOrder_.IsArray() {
			H2SettingsOrder = transferjsonarray(SettingsOrder_.Array())
		} else {
			H2SettingsOrder = nil
		}
		var H2ConnectionFlow int
		if ConnectionFlow_ := jsondata.Get("h2connectionflow"); ConnectionFlow_.Exists() && ConnectionFlow_.Type == gjson.Number {
			H2ConnectionFlow = int(ConnectionFlow_.Uint())
		} else {
			H2ConnectionFlow = 12517377 // magic
		}
		var H2HeaderPriority map[string]interface{}
		if HeaderPriority_ := jsondata.Get("h2headerpriority"); HeaderPriority_.Exists() && HeaderPriority_.IsObject() {
			H2HeaderPriority = func(d map[string]gjson.Result) map[string]interface{} {
				ret := make(map[string]interface{}, len(d))
				for k, v := range d {
					switch v.Type {
					case gjson.String:
						ret[k] = v.String()
					case gjson.Number:
						ret[k] = int(v.Uint())
					case gjson.False, gjson.True:
						ret[k] = v.Bool()
					}
				}
				return ret
			}(HeaderPriority_.Map())
		} else {
			H2HeaderPriority = nil // magic
		}
		var H2PriorityFrames []map[string]interface{}
		if PriorityFrames_ := jsondata.Get("h2priorityframes"); PriorityFrames_.Exists() && PriorityFrames_.IsArray() {
			tmp := PriorityFrames_.Array()
			H2PriorityFrames = make([]map[string]interface{}, 0, len(tmp))
			for _, v := range tmp {
				tmpele := make(map[string]interface{})
				tmpele["streamID"] = int(v.Map()["streamID"].Uint())
				tmpele["priorityParam"] = map[string]interface{}{
					"weight":    int(v.Map()["priorityParam"].Map()["weight"].Uint()),
					"streamDep": int(v.Map()["priorityParam"].Map()["streamDep"].Uint()),
					"exclusive": v.Map()["priorityParam"].Map()["exclusive"].Bool(),
				}
				H2PriorityFrames = append(H2PriorityFrames, tmpele)
			}
		} else {
			H2PriorityFrames = nil
		}
		//h2s := &transport.H2Settings{}
		//fmt.Println(method, len(method))
		// do request
		status, respheaders, respody, err := request(method, url, headers, headerorder, pheaderorder, body, proxy, timeout, AllowRedirects, verify, cert, ja3,
			SupportedSignatureAlgorithms, CertCompressionAlgo, RecordSizeLimit, DelegatedCredentials, SupportedVersions, PSKKeyExchangeModes, KeyShareCurves,
			H2Settings, H2SettingsOrder, H2ConnectionFlow, H2HeaderPriority, H2PriorityFrames)
		if err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}
		// return
		//fmt.Println(string(respody))
		c.JSON(200, gin.H{
			"status":  status,
			"headers": respheaders,
			"body":    base64.StdEncoding.EncodeToString(respody),
		})
	})
	var host string
	flag.StringVar(&host, "host", "127.0.0.1:11000", "host and port to listen")
	flag.Parse()
	r.Run(host) // 监听并在 0.0.0.0:8080 上启动服务
}
