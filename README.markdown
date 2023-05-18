# tlsproxy

### 一次完整的请求
```bash
POST http://127.0.0.1:8080/request

{
  "method": "GET",
  "url": "https://httpbin.org/get",
  "header_order": ["user-agent",
        "path",
        "accept-language",
        "scheme",
        "connection",
        "accept-encoding",
        "content-length",
        "host",
        "accept"],
  "pheader_order": [":method",
			":path",
			":authority",
			":scheme"],
  "headers": {"key": "v"},
  "body": "hex编码",
  "proxy": "http://xxx"
  "timeout": 10,
  "allow_redirects": true,
  "verify": false,
  "cert": [key, cert, rootca],
  "ja3": "xxxx",
  "supported_signature_algorithms": ["ECDSAWithP256AndSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithP521AndSHA512",
			"PSSWithSHA256",
			"PSSWithSHA384",
			"PSSWithSHA512",
			"PKCS1WithSHA256",
			"PKCS1WithSHA384",
			"PKCS1WithSHA512",
			"ECDSAWithSHA1",
			"PKCS1WithSHA1"],
  "cert_compression_algo": ["brotli"],
  "record_size_limit": 4001,
  "delegated_credentials": ["ECDSAWithP256AndSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithP521AndSHA512",
			"ECDSAWithSHA1"],
  "supported_versions": ["1.3",
			"1.2"],
  "pskkey_exchange_modes": ["PskModeDHE"],
  "signature_algorithms_cert": ["PKCS1WithSHA256"],
  "key_share_curves": ["X25519",
			"P256"],
  "h2settings": {"HEADER_TABLE_SIZE": 65536,
                 "INITIAL_WINDOW_SIZE": 131072,
                  "MAX_FRAME_SIZE":      16384},
  "h2settings_order": ["HEADER_TABLE_SIZE",
			"INITIAL_WINDOW_SIZE",
			"MAX_FRAME_SIZE"],
  "h2connectionflow": 12517377,
  "h2headerpriority": {"weight":    42,
			"streamDep": 13,
			"exclusive": false,},
  "h2priorityframes": [{
				"streamID": 3,
				"priorityParam": {
					"weight":    201,
					"streamDep": 0,
					"exclusive": false,
				},
			},
			{
				"streamID": 5,
				"priorityParam": {
					"weight":    101,
					"streamDep": 0,
					"exclusive": false,
				},
			},
			{
				"streamID": 7,
				"priorityParam": {
					"weight":    1,
					"streamDep": 0,
					"exclusive": false,
				},
			},
			{
				"streamID": 9,
				"priorityParam": {
					"weight":    1,
					"streamDep": 7,
					"exclusive": false,
				},
			},
			{
				"streamID": 11,
				"priorityParam": {
					"weight":    1,
					"streamDep": 3,
					"exclusive": false,
				},
			},
			{
				"streamID": 13,
				"priorityParam": {
					"weight":    241,
					"streamDep": 0,
					"exclusive": false,
				},
			}]
}

```