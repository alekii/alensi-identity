"""Idempotent Keycloak configuration that the realm import cannot hold safely.

A realm import that defines any authentication flow replaces all built-in ones, so flows, the
user profile and identity providers are applied here through the Admin API instead.

Configures, in realm KC_REALM:
  * user profile attribute phoneNumber (E.164; admins edit, users view) for SMS codes
  * "alensi browser" login flow, bound as the browser flow: password, then a mandatory
    second factor: authenticator app, SMS code, email code or a recovery code
  * "alensi first broker login": a Google login only links to an existing (onboarded) account,
    never creates one
  * "alensi post broker mfa": the same second factor after Google sign-in
  * identity provider "google" when GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set

Existing flows are left as they are; delete one in the admin console to have it recreated.
Standard library only, so it runs in a bare python image.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC = os.environ.get("KC_URL", "http://localhost:8180").rstrip("/")
REALM = os.environ.get("KC_REALM", "alensi")
ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "admin")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

BROWSER = "alensi browser"
FIRST_BROKER = "alensi first broker login"
POST_BROKER = "alensi post broker mfa"

# Second factors, in the order offered. The first one the user has set up is used by default;
# "Try another way" offers the rest. Email works for everyone, so MFA is always possible.
SECOND_FACTORS = ["auth-otp-form", "alensi-sms-code", "alensi-email-code", "auth-recovery-authn-code-form"]

token = None


def request(method, path, body=None, expect=(200, 201, 204)):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(KC + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as res:
            raw = res.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        if e.code in expect:
            return None
        raise SystemExit(f"{method} {path} failed: {e.code} {e.read().decode()}")


def admin(path):
    return f"/admin/realms/{REALM}{path}"


def flow_path(alias):
    return admin("/authentication/flows/" + urllib.parse.quote(alias, safe=""))


def login():
    global token
    body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                   "username": ADMIN_USER, "password": ADMIN_PASSWORD}).encode()
    for attempt in range(60):
        try:
            with urllib.request.urlopen(KC + "/realms/master/protocol/openid-connect/token", body) as res:
                token = json.loads(res.read())["access_token"]
            if request("GET", admin("")):
                return
        except (urllib.error.URLError, ConnectionError, SystemExit):
            pass
        print(f"waiting for Keycloak ({attempt + 1})", flush=True)
        time.sleep(5)
    raise SystemExit("Keycloak did not become ready")


def ensure_phone_attribute():
    profile = request("GET", admin("/users/profile"))
    if any(a["name"] == "phoneNumber" for a in profile["attributes"]):
        return
    profile["attributes"].append({
        "name": "phoneNumber",
        "displayName": "Phone number",
        "validations": {"pattern": {"pattern": r"^\+[1-9][0-9]{7,14}$",
                                    "error-message": "Use international format, e.g. +254712345678"}},
        "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
        "multivalued": False,
    })
    request("PUT", admin("/users/profile"), profile)
    print("added user profile attribute phoneNumber")


def flow_exists(alias):
    return any(f["alias"] == alias for f in request("GET", admin("/authentication/flows")))


def executions(top_alias):
    return request("GET", flow_path(top_alias) + "/executions")


def add_execution(top_alias, parent_alias, provider, requirement):
    """Adds an authenticator to a (sub)flow. Each provider appears once per top-level flow here."""
    request("POST", flow_path(parent_alias) + "/executions/execution", {"provider": provider})
    set_requirement(top_alias, lambda e: e.get("providerId") == provider, requirement)


def add_subflow(top_alias, parent_alias, alias, requirement):
    request("POST", flow_path(parent_alias) + "/executions/flow",
            {"alias": alias, "type": "basic-flow", "description": alias})
    set_requirement(top_alias, lambda e: e.get("authenticationFlow") and e["displayName"] == alias, requirement)


def set_requirement(top_alias, predicate, requirement):
    execution = next(e for e in executions(top_alias) if predicate(e))
    execution["requirement"] = requirement
    request("PUT", flow_path(top_alias) + "/executions", execution)


def create_flow(alias, description):
    request("POST", admin("/authentication/flows"),
            {"alias": alias, "description": description, "providerId": "basic-flow", "topLevel": True, "builtIn": False})


def ensure_browser_flow():
    if not flow_exists(BROWSER):
        create_flow(BROWSER, "Password, then a mandatory second factor")
        add_execution(BROWSER, BROWSER, "auth-cookie", "ALTERNATIVE")
        add_execution(BROWSER, BROWSER, "identity-provider-redirector", "ALTERNATIVE")
        add_subflow(BROWSER, BROWSER, "alensi browser forms", "ALTERNATIVE")
        add_execution(BROWSER, "alensi browser forms", "auth-username-password-form", "REQUIRED")
        add_subflow(BROWSER, "alensi browser forms", "alensi browser second factor", "REQUIRED")
        for provider in SECOND_FACTORS:
            add_execution(BROWSER, "alensi browser second factor", provider, "ALTERNATIVE")
        print(f"created flow '{BROWSER}'")
    realm = request("GET", admin(""))
    if realm.get("browserFlow") != BROWSER:
        request("PUT", admin(""), {"browserFlow": BROWSER})
        print(f"bound '{BROWSER}' as the browser flow")


def ensure_broker_flows():
    if not flow_exists(FIRST_BROKER):
        create_flow(FIRST_BROKER, "Link an external login to an existing account only; never create accounts")
        add_execution(FIRST_BROKER, FIRST_BROKER, "idp-detect-existing-broker-user", "REQUIRED")
        add_execution(FIRST_BROKER, FIRST_BROKER, "idp-auto-link", "REQUIRED")
        print(f"created flow '{FIRST_BROKER}'")
    if not flow_exists(POST_BROKER):
        create_flow(POST_BROKER, "Second factor after an external login")
        for provider in SECOND_FACTORS:
            add_execution(POST_BROKER, POST_BROKER, provider, "ALTERNATIVE")
        print(f"created flow '{POST_BROKER}'")


def ensure_google():
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        print("GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET not set: skipping Sign in with Google")
        return
    google = {
        "alias": "google",
        "displayName": "Google",
        "providerId": "google",
        "enabled": True,
        "trustEmail": True,
        "firstBrokerLoginFlowAlias": FIRST_BROKER,
        "postBrokerLoginFlowAlias": POST_BROKER,
        "config": {"clientId": GOOGLE_CLIENT_ID, "clientSecret": GOOGLE_CLIENT_SECRET, "syncMode": "IMPORT",
                   "defaultScope": "openid email profile"},
    }
    existing = request("GET", admin("/identity-provider/instances/google"), expect=(404,))
    if existing:
        request("PUT", admin("/identity-provider/instances/google"), {**existing, **google})
        print("updated identity provider google")
    else:
        request("POST", admin("/identity-provider/instances"), google)
        print("created identity provider google")


def main():
    login()
    ensure_phone_attribute()
    ensure_broker_flows()
    ensure_browser_flow()
    ensure_google()
    print("keycloak configuration applied")


if __name__ == "__main__":
    sys.exit(main())
