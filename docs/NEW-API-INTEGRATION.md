# 交接文档：把 Umagic v1.12.0（Hardstone）接入 new-api

> **给谁看**：接手 new-api 对接的另一个会话 / 另一位工程师。
> 本文自包含——不需要读逆向过程，照做完就能验收。协议细节见同目录 `PROTOCOL.md`。

---

## 0. ⚠️ 先读这一段：当前状态

| 项 | 状态 |
|---|---|
| 上游协议 | ✅ 100% 还原，用真机抓包逐字节比对一致 |
| 四段信封（rv/ki/data） | ✅ 上游接受（不再报 `aes error`） |
| `token` 头 | ⚠️ 算法未还原，只能靠设备侧铸造（一次性消耗） |
| **`ai/art/*` 出图** | ❌ **被 Play Integrity 拦截：`status=114`** |

**因此：现在接进 new-api 只会得到 114。** 接入工作可以先做完（渠道骨架、错误映射、
配置项、验收脚本），但不能通过「真实出图」这条验收。真正放开需要上游侧打通 integrity。

如果只是想先跑通链路，可以照 §2 挂本地网关，用 `/health` 与错误码验证接线是否正确。

---

## 1. 上游协议速查（接渠道只需这 6 条）

```
base       = https://ah.dailyjoypro.com          # AI 后端（u9/f.c）
base_pay   = https://gp.dailyjoypro.com/         # 支付/内购（u9/f.d），不托管 ai/art
```

**① 请求头（一个都不能少）**

```
uid:            <UUID v4，带横线>
versionCode:    112002
version:        112002
pkg:            umagic.ai.aiart.aiartgenrator
Content-Type:   application/json
Accept-Version: v1
platform:       Android
project:        Umagic
token:          <paramsToken(uid)，96 位 hex，服务端一次性>
X-Integrity-Token: <Play Integrity，当前拿不到 → 一律 114>
```

**② 请求体（AES + RSA 双段信封）**

```jsonc
// uid32 = 上面 uid 去掉横线后的 32 位 hex
// key = uid32[0:16]（UTF-8 16 字节），iv = uid32[16:32]
ki   = Base64( RSA_PKCS1v15( pub, uid32 ) )
data = Base64( AES-128-CBC-PKCS5( json.Marshal(payload), key, iv ) )
body = {"rv":1,"ki":ki,"data":data}
```

RSA 公钥（2048-bit，X509/SPKI，392 字符）见 `proto.py:RSA_PUB_B64`，从
`libtk.so` 的 `publicKey()` 完整提取（**与旧 Umagic / Alura 的 aperogroup 公钥无关**）。

**③ 响应（明文，不加密）**

```jsonc
{"error":"","message":"","next":"","response":"ok|fail","status":"200","data":{"image_url":["https://..."]}}
```

`image_url` 可能是字符串也可能是数组，两种都要处理。

**④ 三条主链 body**

```jsonc
// 文生图（同步）
POST /ai/art/txt2img/v2/
{"nb":"stn2_dailyjoy_us","ratio":"1:1","prompt":"...",
 "style_id":"...","inspiration_id":"...","is_first":true,"is_translate":1,"xId":1}
// nb 恒为 "stn2_dailyjoy_us"；其余可选

// 扩图 / 局部重绘 / 线稿 / 图生文 / 增强
POST /ai/art/expand/v2/ | /ai/art/inpaint/v2/ | /ai/art/lineart/v2/
     /ai/art/interrogate/v2/ | /snap/enhance/v2/

// 图生视频（提交 + 轮询）
POST /ai/art/video_generation/v3/        -> data 里拿任务 id
POST /ai/art/query/video_generation/v2/  -> 轮询
```

完整 19 个端点见 `docs/PROTOCOL.md` §3。

**⑤ 状态码映射（渠道层必须区分，别当 5xx 重试）**

| upstream status | 含义 | new-api 侧建议 |
|---|---|---|
| `200` | 成功 | 正常返回 |
| `103` | 缺 `package_name` | 400 参数错 |
| `107` | token 校验失败（`aes error` / `repeat error`） | 401 凭证失效，**不重试** |
| `114` | 缺 Play Integrity | 403 `upstream_integrity_required`，**不重试** |
| HTTP 405 (Flask) | 打到了 `gp` 而非 `ah` | 配置错误，503 并告警 |
| 连接重置 / SSL EOF | 上游并发上限极低（实测 8 并发 7 条被掐） | 降并发 + 退避重试 |

**⑥ 一次性 token 池**

`token` 是 `paramsToken(uid)` 的原生输出，服务端**用一次就作废**（复用报 `repeat error`）。
所以每个上游请求都必须弹一对全新的 `(uid, token)`。

- 算法未还原（AES-CBC/ECB + 6738 个设备 rodata 静态密钥候选、SHA-384、HMAC-SHA384 均已排除）
- 现成方案：`python frida_mint.py <app_pid> 200 tokens.jsonl` 在设备上批量铸造（原生调用，秒级百条）
- 渠道若走这条路，必须带一个 **池耗尽 → 503 + 告警** 的分支，不能静默重试

---

## 2. 路线 A：零 Go 代码，挂现成 Python 网关（30 分钟，推荐先落地）

`demo_server.py` 已经是 OpenAI 形态：

```bash
pip install requests cryptography
python frida_mint.py <app_pid> 200 tokens.jsonl
PORT=8945 python demo_server.py      # 浏览器 http://127.0.0.1:8945/
```

| new-api 配置项 | 值 |
|---|---|
| 类型 | `58` AdvancedCustom（或 `1` OpenAI） |
| Base URL | `http://127.0.0.1:8945` |
| 密钥 | 任意非空（如 `sk-umagic`）——上游 uid/token 由网关侧 `tokens.jsonl` 管 |
| 模型 | `umagic-txt2img` |
| 端点 | `POST /v1/images/generations` |
| 探活 | `GET /health`（含 `token_pool`、`stats`、`blocker`） |

`/v1/images/generations` 的 `size` 字段直接映射成上游 `ratio`，传 `1:1` / `3:4` 这类值。

**局限**：视频链（`/ai/art/video_generation/v3/`）没有 OpenAI 对应语义，走这条路线要么
自己在网关侧加 `model=umagic-i2v` 的伪 `/v1/chat/completions`，要么走路线 B。

---

## 3. 路线 B：原生渠道 `ChannelTypeUmagic = 74`

### 3.1 已核实的仓库事实（直接可用）

- 模块路径：`github.com/lza6/new-api-Max`
- 2API 渠道占 **62–73**，`ChannelTypeDuck = 73`（`constant/channel.go`）→ **74 是下一个可用号**
- 模板渠道：`relay/channel/aivm/`（type 72，`adaptor.go` + `do_request.go` 两个文件搞定）
- 注册点：`relay/relay_adaptor.go`（`case constant.ChannelTypeAIVM: return &aivm.Adaptor{}` 附近）

### 3.2 改动清单（共 6 处）

| # | 文件 | 改什么 |
|---|---|---|
| 1 | `constant/channel.go` | 加 `ChannelTypeUmagic = 74`；`ChannelBaseURLs` 追加 `"https://ah.dailyjoypro.com"`；渠道名映射加 `ChannelTypeUmagic: "Umagic"` |
| 2 | `constant/twoapi_channel.go` | 把 `ChannelTypeUmagic` 加进 `TwoAPIChannelTypes` —— **漏了会漏计费 + 出站压缩不豁免**（Duck / AIVM 都踩过） |
| 3 | `constant/api_type.go` + `common/api_type.go` | 追加 `APITypeUmagic` / `lnUmagic` 映射 |
| 4 | `controller/twoapi_panel.go` | 面板加一行统计（可选但建议） |
| 5 | `relay/channel/umagic/{adaptor.go,sign.go,image.go,video.go}` | 新建，见 §3.3 |
| 6 | `relay/relay_adaptor.go` | `case constant.ChannelTypeUmagic: return &umagic.Adaptor{}` |

### 3.3 Adaptor 必须实现的方法（照 `aivm` 抄签名）

```
Init(info *relaycommon.RelayInfo)
GetRequestURL(info) (string, error)
SetupRequestHeader(c, req *http.Header, info) error
GetModelList() []string
GetChannelName() string
ConvertOpenAIRequest / ConvertClaudeRequest / ConvertOpenAIResponsesRequest /
ConvertGeminiRequest / ConvertEmbeddingRequest / ConvertRerankRequest / ...
DoRequest / DoResponse
```

### 3.4 签名模块 `sign.go` 骨架（Go 侧要做的 4 件事）

```go
// 1) uid：每请求新生成 v4 UUID
uid      := uuid.NewString()               // 带横线，放 header
uid32    := strings.ReplaceAll(uid, "-", "") // 去横线，参与加密

// 2) ki：RSA/ECB/PKCS1v15 加密 uid32，再 Base64（标准、无换行）
ki := base64.StdEncoding.EncodeToString(rsaEncryptPKCS1v15(pubKey, []byte(uid32)))

// 3) data：AES-128-CBC + PKCS5，key=uid32[0:16]，iv=uid32[16:32]
data := base64.StdEncoding.EncodeToString(aesCBCPkcs5(payloadJSON, uid32[0:16], uid32[16:32]))

// 4) body = {"rv":1,"ki":..,"data":..}，Content-Type: application/json
```

注意点：
- Go 里 `AES/CBC/PKCS5Padding` 就是标准的 PKCS#7（块 16 字节），手写 padding 即可
- `base64.StdEncoding`（不是 URL-safe、不换行），对应 Java 的 `Base64.NO_WRAP`
- **不要把 RSA 私钥/公钥写死进仓库**，公钥放 `constant` 或渠道配置项；公钥本来就公开，但保持习惯
- `token` 头是死结：Go 侧没有 native，**只能通过网关或旁挂的铸造服务拿**。若走原生渠道，
  建议渠道配置里加一个 `TokenPoolPath`，从 `tokens.jsonl` 弹一对；池空直接 503

---

## 4. 验收清单

| # | 验收项 | 通过标准 | 当前能否通过 |
|---|---|---|---|
| 1 | 渠道能创建、探活 | `GET /health` 返回 `status: ok` | ✅ |
| 2 | 请求能到达上游 | 上游回 `107`/`114` 而不是 `aes error` | ✅（回 114） |
| 3 | 错误码映射正确 | 114 → 403 `upstream_integrity_required`，不重试 | ✅ |
| 4 | 出图 | `data[0].url` 能在浏览器打开 | ❌ 阻塞于 integrity |
| 5 | 并发 | 3 并发全通，p50 ≈ 1.6s | ⚠️ 3 并发可达；8 并发上游掐连接 |
| 6 | 计费 | `TwoAPIChannelTypes` 含新 type，用量不丢 | 待实现 |

---

## 5. 风险与限制

1. **P0**：`ai/art/*` 全部要求 Play Integrity（`status 114`）。已排除的绕过：`android_package_name` /
   `package_name` 放 header / query / 加密 body，伪造 `X-Integrity-Token`，换 `gp` 实例，
   子域枚举（`api/us/eu/ai/gw/prod.dailyjoypro.com` 全 NXDOMAIN）。纯协议侧无解。
2. **token 单点**：只能设备铸造、一次性消耗。渠道路径上必须有池耗尽告警。
3. **并发上限极低**：实测 8 并发 7/8 连接被重置；单渠道建议并发 ≤ 3 并加退避。
4. **`gp` 不是 AI 上游**：`gp.dailyjoypro.com` 只服务 `api/v1/android/query`（支付），
   POST `ai/art/*` 一律 Flask 405。Base URL 必须配 `ah`。
5. **本包是 Mod 包**：签名与 Play 版不同，Play Integrity 必然失败；这不是我们构造错误。

---

## 6. 现成参考实现

| 文件 | 用途 |
|---|---|
| `proto.py` | Python 版完整协议内核（可当 Go 移植的对照实现） |
| `demo_server.py` | OpenAI 兼容网关 + demo 页，路线 A 直接可用 |
| `stress_test.py` | 并发压测，`python stress_test.py 3` |
| `frida_mint.py` | 设备侧批量铸 `(uid, token)` |
| `docs/PROTOCOL.md` | 协议还原全过程（签名链 / 配置解密 / 端点 / 状态码） |
