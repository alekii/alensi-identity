"""Development helper: signs in through the real browser flow and prints an access token.

Does what a browser would: Authorization Code + PKCE against alensi-web, the password form, then
the second factor, reading email codes from Mailpit and SMS codes from the Keycloak container log
(ALENSI_SMS_PROVIDER=log). Authenticator-app (TOTP) users need --totp-secret.

    python3 scripts/dev_login.py alice alice [--org jub] [--factor email|sms] [--totp-secret BASE32]
"""
import argparse
import base64
import hashlib
import hmac
import html
import http.cookiejar
import json
import re
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8180/realms/alensi/protocol/openid-connect"
MAILPIT = "http://localhost:8025/api/v1"
REDIRECT = "http://localhost:3000/callback"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


jar = http.cookiejar.CookieJar()
browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def fetch(url, form=None):
    # Keycloak marks its cookies Secure; browsers still send them to http://localhost, cookiejar does not.
    for cookie in jar:
        cookie.secure = False
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
        with browser.open(url, data) as res:
            return res.status, res.read().decode(), None
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303):
            return e.code, "", e.headers["Location"]
        return e.code, e.read().decode(), None


def follow(status, page, location):
    while location and not location.startswith(REDIRECT):
        status, page, location = fetch(location)
    return status, page, location


def form_action(page):
    match = re.search(r'<form[^>]*id="(kc-form-login|kc-otp-login-form|kc-select-credential-form)"[^>]*action="([^"]+)"', page) \
        or re.search(r'<form[^>]*action="([^"]+)"', page)
    return html.unescape(match.groups()[-1])


def totp(secret, raw=False):
    """A 6-digit TOTP. {@code secret} is base32 as shown by authenticator apps, or Keycloak's raw secret."""
    key = secret.encode() if raw else base64.b32decode(secret.replace(" ", "").upper() + "=" * (-len(secret.replace(" ", "")) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def latest_email_code(since):
    for _ in range(20):
        messages = json.load(urllib.request.urlopen(f"{MAILPIT}/messages?limit=5"))["messages"]
        for message in messages:
            if message["Created"] >= since and "verification code" in message["Subject"]:
                text = json.load(urllib.request.urlopen(f"{MAILPIT}/message/{message['ID']}"))["Text"]
                return re.search(r"\b(\d{6})\b", text).group(1)
        time.sleep(0.5)
    raise SystemExit("no verification email in Mailpit")


def latest_sms_code():
    for _ in range(20):
        log = subprocess.run(["docker", "compose", "logs", "--since", "30s", "keycloak"],
                             capture_output=True, text=True).stdout
        codes = re.findall(r"\[DEV SMS\] to \S+: (\d{6}) ", log)
        if codes:
            return codes[-1]
        time.sleep(0.5)
    raise SystemExit("no SMS code in the Keycloak log")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("--org", help="organization alias, e.g. jub, to select the tenant")
    parser.add_argument("--factor", choices=["email", "sms"], help="switch to this factor via 'Try another way'")
    parser.add_argument("--totp-secret")
    args = parser.parse_args()

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    scope = "openid" + (f" organization:{args.org}" if args.org else "")
    status, page, location = follow(*fetch(f"{KC}/auth?" + urllib.parse.urlencode({
        "client_id": "alensi-web", "redirect_uri": REDIRECT, "response_type": "code", "scope": scope,
        "code_challenge": challenge, "code_challenge_method": "S256"})))
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    status, page, location = follow(*fetch(form_action(page), {"username": args.username, "password": args.password}))

    if args.factor:
        another = re.search(r'<form[^>]*id="kc-select-try-another-way-form"[^>]*action="([^"]+)"', page)
        status, page, location = follow(*fetch(html.unescape(another.group(1)), {"tryAnotherWay": "on"}))
        options = re.findall(r'action="([^"]+)"[^>]*>\s*<input[^>]*name="authenticationExecution" value="([^"]+)".*?'
                             r'select-auth-box-headline">\s*([^<]+?)\s*<', page, re.S)
        wanted = "Email code" if args.factor == "email" else "SMS code"
        action, execution = next((a, e) for a, e, label in options if label == wanted)
        status, page, location = follow(*fetch(html.unescape(action), {"authenticationExecution": execution}))

    if not location:
        if 'id="alensi-code-sent"' in page:
            sent = re.search(r'id="alensi-code-sent">([^<]+)', page).group(1).strip()
            print("second factor:", html.unescape(sent), file=sys.stderr)
            code = latest_sms_code() if "SMS" in sent else latest_email_code(since)
            status, page, location = follow(*fetch(form_action(page), {"code": code}))
        elif 'name="otp"' in page:
            if not args.totp_secret:
                raise SystemExit("authenticator app required: pass --totp-secret")
            status, page, location = follow(*fetch(form_action(page), {"otp": totp(args.totp_secret)}))
    if not location:
        title = re.search(r"<title>([^<]*)", page)
        raise SystemExit(f"login did not complete (HTTP {status}, page: {title.group(1) if title else '?'})")

    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    tokens = json.load(urllib.request.urlopen(f"{KC}/token", urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": "alensi-web", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier}).encode()))
    print(tokens["access_token"])


if __name__ == "__main__":
    main()
