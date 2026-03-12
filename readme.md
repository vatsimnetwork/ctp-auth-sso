# ctp-auth-sso

VATSIM OAuth SSO service for CTP. Handles login, session management, and provides an internal session validation endpoint for downstream services.

## Development

### Tailwind CSS

```
./tailwindcss -i themes.css -o static/tailwind.css --content "templates/**/*.html" --minify --watch
```

Binary: https://github.com/tailwindlabs/tailwindcss/releases

### Configuration

| Variable | Default | Description |
|---|---|---|
| `APP_URL` | — | Public base URL (e.g. `https://sso.example.com`) |
| `APP_ENV` | `development` | Set to `production` to enable secure cookies and HSTS |
| `DATABASE_DSN` | — | Postgres DSN |
| `VATSIM_CLIENT_ID` | — | VATSIM OAuth client ID |
| `VATSIM_CLIENT_SECRET` | — | VATSIM OAuth client secret |
| `VATSIM_BASE_URL` | — | VATSIM OAuth base URL |
| `INTERNAL_API_KEY` | — | Secret for downstream service authentication |
| `INTERNAL_ALLOWLIST` | `""` | CSV of IPs/CIDRs allowed to call the validate endpoint. Empty = no restriction |
| `COOKIE_DOMAIN` | `""` | Cookie domain attribute. Set to `.example.com` to share across subdomains |
| `SESSION_LIFETIME_DAYS` | `14` | Maximum session age |
| `IDLE_TIMEOUT_HOURS` | `4` | Session idle timeout |

---

## Session Validation for Downstream Services

Other services authenticate users by forwarding the user's `session_id` cookie to the internal validate endpoint. The SSO service checks the session and returns the user's VATSIM CID and assigned roles.

### Endpoint

```
GET /internal/session/validate
```

**Required headers:**

| Header | Value |
|---|---|
| `X-Internal-Key` | Shared secret (`INTERNAL_API_KEY`) |
| `Cookie` | The user's `session_id` cookie, forwarded as-is |
| `User-Agent` | The user's actual User-Agent string — used for fingerprint verification |

**Success response — `200 OK`:**

```json
{
  "cid": "1234567",
  "roles": ["administrator", "some_role"]
}
```

**Error responses:**

| Status | `error` field | Meaning |
|---|---|---|
| `401` | `unauthorized` | Missing or wrong `X-Internal-Key`, or no `session_id` cookie |
| `401` | `invalid_session` | Session not found or revoked |
| `401` | `session_expired` | Session exceeded `SESSION_LIFETIME_DAYS` |
| `401` | `session_idle` | Session exceeded `IDLE_TIMEOUT_HOURS` of inactivity |
| `401` | `session_hijack_detected` | User-Agent changed since session was created |
| `403` | `forbidden` | Caller IP not in `INTERNAL_ALLOWLIST` |

All error responses have the shape:

```json
{
  "error": "error_code",
  "message": "human readable description"
}
```

---

### Code Samples

The pattern is the same in every language: read the `session_id` cookie from the incoming request, then proxy it along with the user's `User-Agent` to the validate endpoint.

#### Go

```go
import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

type SessionResponse struct {
    CID   string   `json:"cid"`
    Roles []string `json:"roles"`
}

type SessionError struct {
    Error   string `json:"error"`
    Message string `json:"message"`
}

func validateSession(r *http.Request) (*SessionResponse, error) {
    sessionCookie, err := r.Cookie("session_id")
    if err != nil {
        return nil, fmt.Errorf("no session_id cookie")
    }

    req, err := http.NewRequest(http.MethodGet, "https://sso.example.com/internal/session/validate", nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("X-Internal-Key", "your-internal-api-key")
    req.Header.Set("Cookie", "session_id="+sessionCookie.Value)
    req.Header.Set("User-Agent", r.Header.Get("User-Agent"))

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    if resp.StatusCode != http.StatusOK {
        var ssoErr SessionError
        json.Unmarshal(body, &ssoErr)
        return nil, fmt.Errorf("session invalid: %s", ssoErr.Error)
    }

    var session SessionResponse
    if err := json.Unmarshal(body, &session); err != nil {
        return nil, err
    }

    return &session, nil
}
```

#### Python

```python
import httpx
from fastapi import Request, HTTPException

SSO_URL = "https://sso.example.com/internal/session/validate"
INTERNAL_API_KEY = "your-internal-api-key"

def validate_session(request: Request) -> dict:
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="no session_id cookie")

    resp = httpx.get(
        SSO_URL,
        headers={
            "X-Internal-Key": INTERNAL_API_KEY,
            "Cookie": f"session_id={session_id}",
            "User-Agent": request.headers.get("user-agent", ""),
        },
    )

    if resp.status_code != 200:
        error = resp.json().get("error", "unknown")
        raise HTTPException(status_code=401, detail=f"session invalid: {error}")

    return resp.json()  # {"cid": "1234567", "roles": ["administrator"]}
```

#### JavaScript (Node.js / Express)

```js
const fetch = require('node-fetch')

const SSO_URL = 'https://sso.example.com/internal/session/validate'
const INTERNAL_API_KEY = 'your-internal-api-key'

async function validateSession(req) {
  const sessionId = req.cookies?.session_id
  if (!sessionId) {
    throw new Error('no session_id cookie')
  }

  const resp = await fetch(SSO_URL, {
    method: 'GET',
    headers: {
      'X-Internal-Key': INTERNAL_API_KEY,
      'Cookie': `session_id=${sessionId}`,
      'User-Agent': req.headers['user-agent'] ?? '',
    },
  })

  const body = await resp.json()

  if (!resp.ok) {
    throw new Error(`session invalid: ${body.error}`)
  }

  return body // { cid: '1234567', roles: ['administrator'] }
}
```

### IP Allowlisting

If `INTERNAL_ALLOWLIST` is set, only requests from listed IPs reach the endpoint. All others receive `403` before the API key is checked. Configure it as a comma-separated list:

```
INTERNAL_ALLOWLIST=10.0.0.0/8,192.168.1.50,172.16.*
```

Supported formats: exact IP, CIDR notation, and wildcard octets (`10.0.*` is treated as `10.0.0.0/16`).

### User-Agent forwarding

The `User-Agent` header **must** be forwarded from the original user request. The SSO service stores a fingerprint of the UA at session creation time and compares it on every validate call. Sending a different or empty UA will result in a `session_hijack_detected` error and the session will not validate.
