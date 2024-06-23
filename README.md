# tlshake

Show TLS handshake details, for initial connection and resumptions.

https://github.com/ThomasHabets/tlshake

## Building

First install Rust compiler. The easiest way is to follow https://rustup.rs/

Then just run `cargo build --release`. The binary is now
`./target/release/tlshake`.

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
roundtrip, so it's already pretty good. But it can save CPU cycles,
and provides the opportunity to use "early data", saving another
roundtrip.

Early data should never be used for things that are dangerous to
replay, like HTTP `POST` requests. Indeed, browsers don't do that.

`tlshake` by default doesn't provide any early data, since it doesn't
know what protocol is on the other side. But you can provide
`--http-get /` to make it send an HTTP GET request.

See [this blog post][blog] for more details.

[blog]: https://blog.habets.se/2024/06/Is-your-TLS-resuming.html

```
$ tlshake --http-get / www.google.com
Connection: initial
  Target:           www.google.com
  Endpoint:         www.google.com:443
  Connect time:     66.925ms
  Handshake time:   39.772ms
  Handshake kind:   Full
  Protocol version: TLSv1_3
  Cipher suite:     TLS13_AES_256_GCM_SHA384
  ALPN protocol:    None
  Early data:       Not attempted
  Request time:     95.896ms
  Reply first line: HTTP/1.1 200 OK
  Total time:       202.626ms

Connection: resume
  Target:           www.google.com
  Endpoint:         www.google.com:443
  Connect time:     55.783ms
  Handshake time:   39.370ms
  Handshake kind:   Resumed
  Protocol version: TLSv1_3
  Cipher suite:     TLS13_AES_256_GCM_SHA384
  ALPN protocol:    None
  Early data:       accepted
  Request time:     57.119ms
  Reply first line: HTTP/1.1 200 OK
  Total time:       152.301ms
```
