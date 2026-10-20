# Wutong SDK for Go · 梧桐 Go SDK

[![CI](https://github.com/project-wutong/wutong-sdk-go/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-sdk-go/actions/workflows/ci.yml)
Go ≥ 1.22 · pure Go (no cgo) · `AGPL-3.0-only`

## 中文

梧桐协议（WTP `wutong/0.1`，规范修订 v0.1.2）的**原生 Go 实现**。按文档要求避免强制 cgo，
因此这里独立实现线格式层，并以 `wutong-protocol` 发布的跨语言向量保证与 Rust 核心逐字节一致：

- 严格 JSON 解析（重复键、浮点、NaN、前导零、孤立代理、超范围整数、非 ASCII 成员名、深度与大小限制）
- RFC 8785 JCS（UTF-16 键序）与确定性 CBOR（RFC 8949 §4.2.1）
- `sha256:` 摘要；Ed25519 信封签名/验签（`WUTONG-SIG-V0.1\0` / `WUTONG-CBOR-SIG-V0.1\0` 域分隔，拒绝小阶公钥与非规范 S）
- Task 状态机；Document 配置的可移植相对路径规则

Schema 校验、能力链与重放账本将在后续里程碑加入（见 Issues）。

```go
import "github.com/project-wutong/wutong-sdk-go/wtp"

v, err := wtp.Parse(raw)         // strict application/wtp+json
canon, _ := wtp.JCS(v)
signed, _ := wtp.Sign(v.(map[string]any), key, wtp.Auth{...}, wtp.EncodingJCS)
err = wtp.Verify(signed, pub)
```

## English

Native Go implementation of the Wutong Protocol wire layer (strict JSON, JCS, dCBOR, SHA-256,
Ed25519 envelope signatures, Task state machine, portable paths), pinned to the cross-language
vectors in [`wutong-protocol`](https://github.com/project-wutong/wutong-protocol). `testdata/` is a verbatim
copy of those vectors and CI fails if it drifts.
