# Umagic (Kreivo AI) APP 2API

Reverse-engineered **Umagic / Kreivo AI** (`com.ai.art.aiimagegenerator.aivideogenerator.aiphoto.aiart` v1.11.1) image-editing API into an OpenAI-compatible local gateway.

## Upstream
`api-img-gen-wrapper.aperogroup.ai` — same aperogroup backend as Alura (qwen-editing pipeline).

## Protocol
```
x-api-signature = Base64( RSA-PKCS1v15(pub, "{ms_ts}@@@{api_key}@@@{6-digit-nonce}") )
```
- Same server-wide RSA public key as Alura's `img_pub_key`
- Flow: `presigned-link` → S3 PUT → `POST /api/v5.1/qwen-editing` `{files, mode:IMAGE_EDITING, positivePrompt}` → sync output URL (~15-20s)

## Usage
```bash
pip install cryptography
python demo_server.py          # :8911
python stress_test.py 10       # concurrency test
```

### Endpoints
| Endpoint | Description |
|---|---|
| `POST /v1/images/edits` | OpenAI-compatible multipart image edit |
| `POST /umagic/image/generate` | JSON `{image_base64, prompt}` |
| `GET /health` | health check |

## Stress test (2026-10-28)
- 6 concurrency: **6/6 success**, p50 = 16.3s
- 10 concurrency: **10/10 success**, p50 = 19.1s, zero rate-limit

## Sample
`demo_result.jpg` — real output: input photo → "van gogh starry night style" (1120x1120)

> For educational / research purposes only.
