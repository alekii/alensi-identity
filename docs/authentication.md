# Sign-in, MFA and staff onboarding

Keycloak (realm `alensi`) authenticates; alensi-identity onboards people and decides what they
can do. Everything below was verified against Keycloak 26.8 in the local stack.

## Signing in

Staff sign in with **email and password** or **Sign in with Google**. Either way, a **second
factor is mandatory**:

| Second factor | When it is the default | Setup |
|---|---|---|
| Authenticator app (TOTP: Google/Microsoft Authenticator, FreeOTP) | Once enrolled | At first sign-in if onboarded with `requireAuthenticatorApp`, or any time from the account console |
| SMS code | The user has a `phoneNumber` and no app | Phone number set at onboarding (E.164, e.g. `+254712345678`) |
| Email code | Neither of the above | Nothing to set up: every account has an email, so MFA is always possible |
| Recovery code | — | Optional, from the account console |

The default is the strongest factor the user has set up. **"Try another way"** offers the
others, e.g. an email code when the phone with the authenticator app is lost.

Codes are 6 digits and valid for 5 minutes. Each code allows 5 attempts; a new one can be
requested after 30 seconds. Failures count towards Keycloak's brute-force lockout. All four
values can be changed per execution in the admin console.

**The password grant is disabled** on `alensi-web`, because it would bypass MFA. Clients use
Authorization Code + PKCE. Backend services use the client-credentials grant; service accounts
have no MFA.

## Sign in with Google

- **It links to existing staff only.** The first Google sign-in finds the onboarded account
  with the same (verified) email and links it. An unknown Google account is refused and **no
  account is created** (flow `alensi first broker login`).
- **MFA still applies** after Google (flow `alensi post broker mfa`), so security doesn't depend
  on each person's Google settings.
- To enable it, set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` (an OAuth client from Google
  Cloud Console, with redirect URI `http://localhost:8180/realms/alensi/broker/google/endpoint`
  locally) and run `docker compose up keycloak-config`.

## Onboarding staff

`POST /api/tenants/{tenant}/staff`

```json
{
  "email": "nina@jubilee.example",
  "firstName": "Nina",
  "lastName": "Achieng",
  "phoneNumber": "+254711000111",
  "requireAuthenticatorApp": false,
  "grants": [{ "application": "alensi-insure", "role": "agent", "target": "JUB-KE-NRB-NWS-T1" }]
}
```

1. **Authorize everything first.** The caller must be able to assign every requested role on
   its target, so a branch manager can onboard agents into their own branch only. Onboarding
   without grants is for tenant admins. Nothing is created in Keycloak if any check fails.
2. **Find or create the account.** A person who already works for another tenant keeps their
   single account (`newAccount: false`).
3. **Membership and grants** in the tenant, which also adds the person to the Keycloak
   organization. Grants they already hold are skipped, so onboarding twice is harmless.
4. **Invite email** (new accounts): one link to set a password, which also verifies the email
   address, plus authenticator-app enrolment if `requireAuthenticatorApp`. Valid for 72 hours.
   `POST /api/tenants/{tenant}/staff/{username}/invite` re-sends it while setup is pending.

## Keycloak pieces

| Piece | Where |
|---|---|
| Email and SMS code authenticators | `keycloak/extensions` (Java, built into `keycloak/providers`) |
| Flows, `phoneNumber` user profile attribute, Google | `keycloak/configure.py`, run by the `keycloak-config` compose service |
| SMTP, OTP policy, clients | `keycloak/import/alensi-realm.json` |

Flows can't live in the realm import, because an import that defines any flow replaces all
built-in ones.

**SMS providers** are set on the Keycloak container:
- `ALENSI_SMS_PROVIDER=log` (default) writes codes to the Keycloak log. Development only.
- `africastalking` needs `ALENSI_SMS_AT_USERNAME`, `ALENSI_SMS_AT_API_KEY`, optionally
  `ALENSI_SMS_AT_SENDER_ID`, and `ALENSI_SMS_AT_SANDBOX=true` for the sandbox.
- `twilio` needs `ALENSI_SMS_TWILIO_ACCOUNT_SID`, `ALENSI_SMS_TWILIO_AUTH_TOKEN` and
  `ALENSI_SMS_TWILIO_FROM`.

The identity service account holds `manage-users` (needed to create users and send invites)
and `manage-organizations`.
