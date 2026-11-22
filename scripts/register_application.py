"""Registers an application from its manifest (e.g. catalog/alensi-insure.json), idempotently:

  1. Keycloak clients (manifest "keycloak.clients"), configured the way alensi-identity needs:
     lightweight access tokens carrying sub, the organization, and the listed audiences;
     Authorization Code + PKCE for public clients; never the password grant (it bypasses MFA).
  2. Roles for the confidential clients' service accounts (manifest "keycloak.serviceAccountRoles"),
     granted on all targets through the identity API.
  3. The application's catalog: PUT /api/applications/{app}/catalog.

    python3 scripts/register_application.py catalog/alensi-insure.json [--show-secrets]

Development defaults: Keycloak master admin admin/admin, and a platform admin token obtained by
signing in as admin/admin (scripts/dev_login.py). Elsewhere pass --kc-admin-user/--kc-admin-password
and --token.
"""
import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import dev_login  # noqa: E402

LIGHTWEIGHT = {"access.token.claim": "true", "introspection.token.claim": "true", "lightweight.claim": "true"}


def call(base, token, method, path, body=None, ok=(200, 201, 204)):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as res:
            raw = res.read()
            return res.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        if e.code in ok:
            return e.code, None
        raise SystemExit(f"{method} {path} failed: {e.code} {e.read().decode()}")


def mappers(spec):
    result = [
        {"name": "sub", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper", "config": dict(LIGHTWEIGHT)},
        {"name": "organization", "protocol": "openid-connect", "protocolMapper": "oidc-organization-membership-mapper",
         "config": {**LIGHTWEIGHT, "claim.name": "organization", "multivalued": "true", "jsonType.label": "String"}},
    ]
    for audience in spec.get("audiences", []):
        result.append({"name": f"audience {audience}", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                       "config": {**LIGHTWEIGHT, "included.client.audience": audience, "id.token.claim": "false"}})
    return result


def client_representation(spec):
    public = spec.get("publicClient", False)
    attributes = {"client.use.lightweight.access.token.enabled": "true"}
    if public:
        attributes["pkce.code.challenge.method"] = "S256"
        attributes["post.logout.redirect.uris"] = "##".join(spec.get("redirectUris", []))
    return {
        "clientId": spec["clientId"], "name": spec.get("name"), "description": spec.get("description"),
        "enabled": True, "protocol": "openid-connect", "publicClient": public,
        "standardFlowEnabled": public, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": bool(spec.get("serviceAccount")) and not public,
        "redirectUris": spec.get("redirectUris", []), "webOrigins": spec.get("webOrigins", []),
        "attributes": attributes,
    }


def register_clients(kc, realm, kc_token, manifest, show_secrets):
    admin = f"/admin/realms/{realm}"
    scopes = {s["name"]: s["id"] for s in call(kc, kc_token, "GET", f"{admin}/client-scopes")[1]}
    for spec in manifest.get("keycloak", {}).get("clients", []):
        wanted = client_representation(spec)
        existing = call(kc, kc_token, "GET", f"{admin}/clients?clientId={urllib.parse.quote(spec['clientId'])}")[1]
        if existing:
            internal_id = existing[0]["id"]
            call(kc, kc_token, "PUT", f"{admin}/clients/{internal_id}", {**existing[0], **wanted,
                                                                        "attributes": {**existing[0].get("attributes", {}), **wanted["attributes"]}})
            print(f"keycloak: updated client {spec['clientId']}")
        else:
            call(kc, kc_token, "POST", f"{admin}/clients", wanted)
            internal_id = call(kc, kc_token, "GET", f"{admin}/clients?clientId={urllib.parse.quote(spec['clientId'])}")[1][0]["id"]
            print(f"keycloak: created client {spec['clientId']}")
        present = {m["name"] for m in call(kc, kc_token, "GET", f"{admin}/clients/{internal_id}/protocol-mappers/models")[1]}
        for mapper in mappers(spec):
            if mapper["name"] not in present:
                call(kc, kc_token, "POST", f"{admin}/clients/{internal_id}/protocol-mappers/models", mapper)
                print(f"keycloak:   + mapper {mapper['name']}")
        if "organization" in scopes:
            call(kc, kc_token, "PUT", f"{admin}/clients/{internal_id}/optional-client-scopes/{scopes['organization']}")
        if not spec.get("publicClient", False):
            secret = call(kc, kc_token, "GET", f"{admin}/clients/{internal_id}/client-secret")[1]["value"]
            shown = secret if show_secrets else secret[:4] + "…"
            print(f"keycloak:   client secret for {spec['clientId']}: {shown}"
                  + ("" if show_secrets else " (--show-secrets to print it)"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--application", help="application code (default: manifest file name)")
    parser.add_argument("--kc-url", default="http://localhost:8180")
    parser.add_argument("--realm", default="alensi")
    parser.add_argument("--kc-admin-user", default="admin")
    parser.add_argument("--kc-admin-password", default="admin")
    parser.add_argument("--identity-url", default="http://localhost:8090")
    parser.add_argument("--token", help="platform admin access token (default: sign in as admin/admin)")
    parser.add_argument("--show-secrets", action="store_true")
    args = parser.parse_args()

    manifest_path = pathlib.Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())
    application = args.application or manifest_path.stem

    kc_token = json.load(urllib.request.urlopen(f"{args.kc_url}/realms/master/protocol/openid-connect/token",
                                                urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                                                        "username": args.kc_admin_user,
                                                                        "password": args.kc_admin_password}).encode()))["access_token"]
    register_clients(args.kc_url, args.realm, kc_token, manifest, args.show_secrets)

    token = args.token or dev_login.login("admin", "admin")
    status, changes = call(args.identity_url, token, "PUT", f"/api/applications/{application}/catalog", manifest)
    print(f"catalog: {len(changes)} change(s)")
    for change in changes:
        print(f"catalog:   {change}")

    for client in manifest.get("keycloak", {}).get("clients", []):
        if client.get("serviceAccount"):
            for role_ref in manifest["keycloak"].get("serviceAccountRoles", []):
                role_app, role = role_ref.split("/", 1)
                status, _ = call(args.identity_url, token, "POST",
                                 f"/api/users/service-account-{client['clientId']}/grants",
                                 {"application": role_app, "role": role}, ok=(200, 201, 409))
                print(f"identity: service-account-{client['clientId']} {role_ref} on *: "
                      + ("granted" if status == 201 else "already granted"))


if __name__ == "__main__":
    main()
