# Umagic v1.12.0 · 协议还原报告

> 样本：`Umagic v1.12.0 (PREMIUM).apk`（23 MB，2026-07-14 构建，Mod by Mixroot）
> 包名：`umagic.ai.aiart.aiartgenrator`，versionCode **112002**
> 结论级别：签名链 / 配置 / 端点 = **已验证**（真机复现）；token 算法 = **未还原**（仅设备侧可产出）；上游放行 = **被 Play Integrity 拦截**

---

## 0. 与旧 Umagic 的唯一关系：没有关系

上一轮逆向的 Umagic v1.11.1 包名是 `com.ai.art.aiimagegenerator.aivideogenerator.aiphoto.aiart`，
上游是 **aperogroup**（Alura 同集团），签名是 `x-api-signature = RSA(ts@@@key@@@nonce)`。
本包两者都换了：

| 维度 | v1.11.1（旧） | v1.12.0（本包） |
|---|---|---|
| 包名 | `com.ai.art.…aiart` | `umagic.ai.aiart.aiartgenrator` |
| 上游 | `api-img-gen-wrapper.aperogroup.ai` | `ah.dailyjoypro.com` / `gp.dailyjoypro.com` |
| 厂商 | aperogroup | **Hardstone 白标 SaaS**（`dev.hardstone.*`） |
| 鉴权 | RSA 签名头 | **AES 信封 + RSA 密钥交换 + 每请求一次性 token** |
| Firebase 项目 | `umagic-9e9a9`(新) / apero 系 | `umagic-9e9a9` |

`strings` 全量落地后 `aperogroup` 出现 0 次 → 确认是另一条链。

---

## 1. 传输层：四段信封

### 1.1 请求头（逐个还原自 `E9/i.smali` 拦截器）

```
uid:            <UUID v4，带横线>
versionCode:    112002
version:        112002
pkg:            umagic.ai.aiart.aiartgenrator
Content-Type:   application/json
Accept-Version: v1
platform:       Android
project:        Umagic
token:          <paramsToken(uid) 的原生输出，96 位 hex>
X-Integrity-Token: <Play Integrity token，仅当非空才加>
```

### 1.2 请求体

```json
{"rv":1,"ki":"<Base64(RSA_PKCS1v15(pub, uid32))>","data":"<Base64(AES-128-CBC-PKCS5(payload,key,iv))>"}
```

- `uid32` = 上面 `uid` 去掉横线的 32 位 hex
- `key = uid32[0:16]`，`iv = uid32[16:32]`（**真机 hook 实测确认**：
  `TokenUtils.d(payload,"123f32c02bd14118","a83e367a7b5f39c2")`）
- RSA 公钥：X509/SPKI，2048-bit，392 字符（见 `proto.py:RSA_PUB_B64`）

### 1.3 响应体（**明文**，不加密）

```json
{"error":"","message":"","next":"","response":"ok|fail","status":"<code>","data":{"image_url":[...]}}
```

### 1.4 状态码语义（实测）

| status | 含义 |
|---|---|
| 103 | 缺 `package_name` |
| 107 | token 校验失败（`aes error` / `repeat error` / 空） |
| 114 | **缺 Play Integrity**（`no integrity_token or android_package_name`） |
| 200 | 正常 |

---

## 2. 配置层：被 libhscore.so 加密的 `u9/f`

`u9/f` 里 107 个常量全部是 `Decoder.decodeBytesNative(cipher, key)` 的产物，
实现在 `libhscore.so`（21 KB，JNI 导出未混淆）。已用 Unicorn 还原算法并全量解密。

**算法**（从反汇编 `Java_dev_hardstone_decode_Decoder_decodeBytesNative` 读出）：

1. 读 `/proc/<pid>/cmdline`，`strstr` 命中 `umagic.ai.aiart.aiartgenrator` 才走解密分支（反调试/包名校验）
2. 标准 base64 解码密文
3. 按 key 的内容选 3 个 12 字节盐之一：
   `KgYPE01BuMXe` / `DWHJEhgknpNR` / `wQUw1ViMIDqv`（rodata `0x1fd3/0x1fe0/0x1fed`）
4. 拼出 16 字节 XOR key = `盐(12) + key[0:4] 或 key[2:6] 或 key[4:8]`
5. `data[i] ^= keybuf[i & 0xF]`

解出来的关键配置：

| 字段 | 明文 | 用途 |
|---|---|---|
| `u9/f.c` | `https://ah.dailyjoypro.com` | **AI 后端**（`RetrofitUtil(false)`） |
| `u9/f.d` | `https://gp.dailyjoypro.com/` | 支付/网关（`RetrofitUtil(true)`，仅 AiVideoAddActivity） |
| `u9/f.g` | `gs://stn2_dailyjoy_us` | 请求体里的 `nb` 字段（去掉 `gs://`） |
| `u9/f.h` | `https://dailyjoypro.com/dj-us/` | CDN |
| `u9/f.b` | `https://hardstonepte.ltd/` | 官网/素材站 |

---

## 3. 端点全表（Retrofit `@POST`，来自 `E9/e` 接口注解）

| 路径 | 方法名 | 用途 |
|---|---|---|
| `ai/art/txt2img/v2/` | `l` | **文生图** |
| `ai/art/video_generation/v3/` | `i` | 图生视频（提交） |
| `ai/art/query/video_generation/v2/` | `k` | 视频轮询 |
| `ai/art/inpaint/v2/` | `x` | 局部重绘 |
| `ai/art/expand/v2/` | `t` | 扩图 |
| `ai/art/lineart/v2/` | `d` | 线稿上色 |
| `ai/art/interrogate/v2/` | `r` | 图生文 |
| `ai/art/yearbook/predict/v2/` | `j` | yearbook 风格 |
| `snap/enhance/v2/` | `n` | 增强 |
| `nsfw/predict/v2/` | `h` | 内容审核 |
| `common/code/verify/v2/` | `w` | 校验 |
| `task/revoke/v2/` | `s` | 撤销任务 |
| `ai/art/except/tel/v2/` | `q` | 异常上报 |
| `ai/art/video_num/{get,add,create,handle}/v3/`、`mig/v2/` | `b e m o u` | 视频额度 |
| `api/v1/android/query` | `g` | 订阅/内购查询（走 gp） |

### txt2img payload（`BaseViewModel$h` 反编译）

```json
{"nb":"stn2_dailyjoy_us","ratio":"1:1","prompt":"...",
 "style_id":"...","inspiration_id":"...","is_first":true,"is_translate":1,"xId":1}
```
除 `nb`/`ratio`/`prompt` 外均可选。

---

## 4. `token` 头：只能靠设备产出

- `TokenUtils.f(ctx, uid)` → 调用 native `paramsToken(jstring)`（`libtk.so` 0xd1e0 / PLT 0x14fb0）
- 输入 36 位 UUID，输出 **96 位 hex（48 字节）**，对同一 uid **确定性**
- 服务端**一次性**：用过即 `repeat error` → 每个请求必须换 uid
- 已排除：AES-128-CBC/ECB（uid 派生密钥、设备 rodata 里 6738 个候选静态密钥）、
  SHA-384、HMAC-SHA384 等简单构造 → 算法仍未还原
- 可用替代：**设备侧批量铸造 (uid, token) 池**（`frida_mint.py`），实测 5–12 条/秒级

`libtk.so` 的 `publicKey()` 也没有被截断：rodata 里 368 字符 + 跳转表补 24 字符 = 完整 392 字符，
Unicorn 仿真 `JNI_OnLoad → RegisterNatives` 后直接调用即可拿到。

---

## 5. 阻塞点：Play Integrity（P0）

`ah.dailyjoypro.com` 的所有 `ai/art/*` 端点强制要求 `X-Integrity-Token`：

```
{"status":"114","message":"no integrity_token or android_package_name"}
```

- 用真实 App 自己发的请求验证过：App 请求头与我们构造的**完全一致**，无 integrity 头 → 同样 114
- 已排除的绕过尝试：`android_package_name` 放 header / query / 加密 body、`package_name` 同法、
  伪造 `X-Integrity-Token` → 全部仍是 114 / 107
- **结论**：Mod 包在模拟器上取不到 Play Integrity token（需 Play 签名 + 真机 Play 服务），
  因此**本包无法直接作为可用出图渠道**。这条闸门在服务端，纯协议侧无解。
- `gp.dailyjoypro.com` 不托管 `ai/art/*`（POST 一律 Flask 405），只有 `api/v1/android/query`。
