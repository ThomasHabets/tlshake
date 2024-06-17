# tlshake

Show TLS handshake details, for initial connection and resumptions.

https://github.com/ThomasHabets/tlshake

## Example

```
$ tlshake --tls12 www.google.com
Connection: initial
  Connect time:       59.588954ms
  Handshake time:     70.139692ms
  Handshake kind:     Full
  Protocol version:   TLSv1_2
  Cipher suite:       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  ALPN protocol       None
  Total time:         129.960573ms

Connection: resume
  Connect time:       57.133576ms
  Handshake time:     39.528537ms
  Handshake kind:     Resumed
  Protocol version:   TLSv1_2
  Cipher suite:       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  ALPN protocol       None
  Total time:         96.911947ms
```

## Why doesn't it resume TLS 1.3?

Unlike previous versions, TLS 1.3 resumptions by default don't save a
roundtrip. In order to save a roundtrip, the client has to provide
"early data".

Early data should never be used for things that are dangerous to
replay, like HTTP `POST` requests. Indeed, browsers don't do that.

`tlshake` by default doesn't provide any early data, since it doesn't
know what protocol is on the other side. But you can provide
`--http-get /` to make it send an HTTP GET request.

```
$ tlshake --http-get / www.google.com
Connection: initial
  Connect time:       67.48784ms
  Handshake time:     39.743272ms
  Handshake kind:     Full
  Protocol version:   TLSv1_3
  Cipher suite:       TLS13_AES_256_GCM_SHA384
  ALPN protocol       None
  HTTP first line:    HTTP/1.1 200 OK
  Request time:       96.245487ms
  Total time:         203.6481ms

Connection: resume
  Attempting early data
  Connect time:       65.618797ms
  Handshake time:     38.251564ms
  Handshake kind:     Resumed
  Protocol version:   TLSv1_3
  Cipher suite:       TLS13_AES_256_GCM_SHA384
  ALPN protocol       None
  Early data:         accepted
  HTTP first line:    HTTP/1.1 200 OK
  Request time:       69.220143ms
  Total time:         173.238986ms
```
