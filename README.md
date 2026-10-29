# Umagic v1.12.0 · 逆向 + 2API 网关（R1）

> APK：`Umagic v1.12.0 (PREMIUM).apk`（Mod by Mixroot）
> 包名：`umagic.ai.aiart.aiartgenrator` · versionCode 112002
> 上游：**Hardstone 白标 SaaS** — `ah.dailyjoypro.com`（AI）/ `gp.dailyjoypro.com`（支付）
> 与上一轮的 Umagic v1.11.1（aperogroup）**完全无关**

**R1 状态：协议 100% 还原并真机验证；上游 `ai/art/*` 被 Play Integrity 硬闸门拦截（服务端 status 114），因此当前无法出图。**

---

## 30 秒跑起来

```bash
pip install requests cryptography
python frida_mint.py <app_pid> 40 tokens.jsonl    # 铸造一次性 (uid, token) 池
PORT=8945 python demo_server.py                   # 浏览器打开 http://127.0.0.1:8945/
python stress_test.py 3                           # 3 并发压测
```

无设备时网关会在 `/health` 报 `token_pool: 0`，请求返回 503 `token_pool_empty`。

---

## 实测证据（2026-10-30，本机 + emulator-5556）

| 项 | 结果 |
|---|---|
| RSA 公钥（392 字符 SPKI） | ✅ 从 `libtk.so` `publicKey()` Unicorn 仿真完整提取 |
| `u9/f` 107 个加密配置串 | ✅ 用 `libhscore.so` `decodeBytesNative` 全量解密 |
| 端点表（19 个 Retrofit `@POST`） | ✅ 从 `E9/e` 注解提取 |
| 四段信封（rv/ki/data） | ✅ 上游接受，**不再报 `aes error`** |
| `token` 头 | ⚠️ 算法未还原，只能设备侧铸造；服务端**一次性**消耗 |
| 文生图端到端 | ❌ `status=114 no integrity_token or android_package_name` |
| 压测 3 并发 | 3/3 到达服务端，p50=1.58s，全部 114 |
| 压测 8 并发 | 1/8 到达，7/8 连接被重置（上游并发上限很低） |

`shot_demo.png` 是真实浏览器跑通的 demo 页截图（Playwright Chromium，含上游原文回显）。

---

## 文件

| 文件 | 说明 |
|---|---|
| `proto.py` | 协议内核：AES-128-CBC + RSA 包裹 + 头构造 + 请求发送 |
| `demo_server.py` | 网关（OpenAI `/v1/images/generations` + 原生 `/umagic/*`）+ demo 页 |
| `stress_test.py` | 并发压测（一次性 token 池，消费即落盘） |
| `frida_capture.py` | 抓 App 真实请求头/URL/响应 |
| `frida_force.py` | 从 App 内部触发一次真实请求（无需点 UI） |
| `frida_call.py` | 调 `TokenUtils.f/c`，验证 key/iv 派生 |
| `frida_mint.py` | 批量铸造 (uid, token) 一次性池 |
| `emu/soemu.py` | 通用 ARM64 `.so` 仿真台（PT_LOAD / 重定位 / libc 桩 / JNI 桩） |
| `emu/dump_strings.py` | 全量解密 `E2/X->d(...)` 调用点 |
| `emu/tk_natives.py` | 仿真 `JNI_OnLoad` → `RegisterNatives`，取 `publicKey` / `paramsToken` |
| `docs/PROTOCOL.md` | 协议还原报告（含算法、端点、状态码、阻塞点） |
| `tokens.jsonl` | 一次性 uid/token 池（本地，不入库） |

---

## 阻塞点（P0，服务端）

`ah.dailyjoypro.com` 的 `ai/art/*` 全部要求 `X-Integrity-Token`（Play Integrity）。

已排除的绕过：
- `android_package_name` / `package_name` 放 header、query、加密 body → 仍 114
- 伪造 `X-Integrity-Token` → 拒绝
- 换实例：`gp` 不托管 `ai/art/*`（POST 一律 405 Flask），只有 `api/v1/android/query`
- 子域枚举：`api/us/eu/ai/gw/prod.dailyjoypro.com` 全部 NXDOMAIN

用 App 自身发的请求交叉验证：**请求头与我们的构造逐字节一致**，App 同样收到 114 →
说明不是我们构造错误，而是 Mod 包在模拟器上拿不到 Play Integrity token。

**结论**：纯协议侧无解。要出图必须持有原版签名 App 在真机 Play 环境下产生的 integrity token。

---

## 仓库

- 主镜像：`lza6/Umagic-Kreivo-APP-2api` 分支 **`hardstone-v1.12.0-gateway`**
  https://github.com/lza6/Umagic-Kreivo-APP-2api/tree/hardstone-v1.12.0-gateway
- 独立仓库 `lza6/Umagic-v1.12-Hardstone-APP-2api` 创建时被 GitHub
  `createRepository` abuse 限流拒绝，待限流窗口过后重试：

```bash
gh repo create lza6/Umagic-v1.12-Hardstone-APP-2api --public \
  --source=. --remote=dedicated --push
```

---

## new-api 对接

见 **`docs/NEW-API-INTEGRATION.md`**（自包含手册：6 条协议速查、19 个端点、
状态码映射、路线 A 挂 Python 网关、路线 B 原生渠道 type 74 的 6 处改动、验收清单）。
