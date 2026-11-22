# Access model for alensi-insure

How Kenyan insurers organise their staff, and how that maps onto alensi-identity's
roles, targets and grants. Research date: November 2026. Branch lists below come from
job postings and third-party directories and are illustrative, not authoritative.

## 1. How Kenyan insurers are organised

| Insurer | What public sources show |
|---|---|
| **Jubilee Insurance** | Head office in Upper Hill, Nairobi. Job postings place staff "at our branches within **Nairobi, Central, Rift Valley, Western and Coast Regions**". It has *Regional Head – Retail* and *Regional Bancassurance Manager* roles, and branch managers per branch (e.g. *Branch Manager – Nairobi West*, reporting into Retail Distribution). Also operates in Uganda, so there is a country layer above regions. |
| **Madison General** | Head office on Upper Hill Close, Nairobi, with about 23 branches (company figure) grouped under **four regional offices: Nairobi, Western, Coast, Central** (third-party figure). Has a *Regional Business Development Manager – Western Region*. Named branches include Thika, Kisii, Kisumu and Westlands. |
| **Directline Assurance** | Head office at Hazina Towers, Nairobi. Branches in Tom Mboya St and a second Nairobi branch, plus Thika, Kiambu, Kitengela, Ongata Rongai, Machakos, Embu, Meru, Kerugoya, Nyeri, Nakuru, Eldoret, Kisumu, Kisii and Mombasa. Announced closure in June 2024, but the IRA says it remains licensed and liable for policies. |
| **CIC Insurance** | Branch managers report to a *Regional Manager – Metropolitan*, so CIC also has a regional layer. Has branches such as Town Office and Machakos. |

**Pattern:** `Head office → Region → Branch`, with a country level for groups
operating across East Africa. Distribution runs through several **channels**: branch
retail, agency force, bancassurance (staff inside partner banks) and brokers.
Underwriting, claims and finance are usually central functions working across all
branches.

## 2. Target hierarchy

Each insurer is a **company** target at the top of its own subtree. This also gives
tenant isolation: a grant inside Jubilee's subtree can never reach Madison's data.

```
* (platform)
├── company: JUB  Jubilee Insurance
│   ├── country: JUB-KE  Kenya
│   │   ├── region: JUB-KE-NRB  Nairobi Metro
│   │   │   ├── branch: JUB-KE-NRB-UPH  Upper Hill (head office)
│   │   │   ├── branch: JUB-KE-NRB-NWS  Nairobi West
│   │   │   └── branch: JUB-KE-NRB-WLD  Westlands
│   │   ├── region: JUB-KE-CEN  Central        → Thika, Kiambu, Nyeri, Embu, Meru, Kerugoya
│   │   ├── region: JUB-KE-RFT  Rift Valley    → Nakuru, Eldoret
│   │   ├── region: JUB-KE-WST  Western        → Kisumu, Kisii, Kakamega
│   │   └── region: JUB-KE-CST  Coast          → Mombasa, Malindi
│   └── country: JUB-UG  Uganda
│       └── ...
└── company: MAD  Madison General
    └── country: MAD-KE
        ├── region: MAD-KE-NRB, MAD-KE-CEN, MAD-KE-WST, MAD-KE-CST
        └── ...
```

Branches can be split into sales **teams**, each led by a team lead:

```
branch: JUB-KE-NRB-NWS  Nairobi West
├── team: JUB-KE-NRB-NWS-T1  (team lead + agents)
└── team: JUB-KE-NRB-NWS-T2
```

Target types: `company > country > region > branch > team`. Regions are defined per company,
because Madison's four regions differ from Jubilee's five.

Every insure record (customer, policy, claim, payment) carries the code of the most
specific unit that owns it: the agent's **team** if they have one, otherwise the **branch**. A grant on a region or country covers all branches beneath it.

## 3. Role catalogue

Two kinds of role, kept deliberately separate:

- **Administrative roles** (application `alensi-identity`) manage **people and access**.
  They give no access to insurance data.
- **Business roles** (application `alensi-insure`) give access to **insurance data and
  actions**. They give no ability to manage users.

A branch manager normally holds one of each, both granted on their branch.

### Administrative roles (`alensi-identity`)

| Role | Granted on | Manages users in | Can assign |
|---|---|---|---|
| `platform-admin` | `*` | Everything | `company-admin`, any business role. Also manages the catalog (applications, roles, target types). |
| `company-admin` | company (`JUB`) | Its company | `regional-admin`, `branch-admin`, any business role |
| `regional-admin` | region (`JUB-KE-CEN`) | Branches in its region | `branch-admin`, business roles up to `branch-manager` |
| `branch-admin` | branch (`JUB-KE-NRB-NWS`) | Its branch | `team-admin`, `team-lead`, agent ranks |
| `team-admin` *(optional)* | team (`JUB-KE-NRB-NWS-T1`) | Its team | `agent` only, so team leads can onboard agents |

The four levels down to `branch-admin` are seeded. Extra levels such as `team-admin` are
ordinary roles a platform admin creates in `alensi-identity` with `identity.users.manage`.

### Business roles (`alensi-insure`)

| Role | Typical grant | Key permissions | Approval limit |
|---|---|---|---|
| `agent` | team or branch | `customers.create`, `policies.quote`, `policies.sell`, `policies.view` (own records) | Discount ≤ 5% |
| `senior-agent` | team or branch | `agent` + `policies.view` (team) | Discount ≤ 10% |
| `team-lead` | team | `senior-agent` + `team.reports`, `policies.approve-discount` | Discount ≤ 15% |
| `customer-service` | branch | `customers.view`, `policies.view`, `claims.submit`, `claims.view` | — |
| `underwriter` | country (central) | `policies.underwrite`, `policies.issue` | Sum insured ≤ policy limit |
| `claims-adjuster` | region or country | `claims.view`, `claims.assess` | Recommend only |
| `claims-officer` | country | `claims.approve` | ≤ KES 500,000 |
| `branch-manager` | branch | Branch staff's permissions plus `claims.approve`, `reports.branch` | ≤ KES 1,000,000 |
| `regional-manager` | region | `reports.region`, `claims.approve`, `claims.escalate` | ≤ KES 5,000,000 |
| `head-of-claims` | country | `claims.approve`, `claims.override` | Unlimited |
| `bancassurance-officer` | branch (or partner bank) | `policies.quote`, `customers.create` | — |
| `auditor` | company | Read-only across everything, `audit.read` | — |

Limits are illustrative; each insurer configures its own (see below).

### Per-insurer roles

Platform-wide roles (above) are the shared defaults. Each insurer can add **its own roles**,
owned by its company target, e.g. Jubilee's `senior-agent` next to Madison's `senior-agent`:

- Company roles are created and configured by holders of `identity.roles.manage` on the
  company (`company-admin`). They can only be granted **inside that company**, and
  company admins may assign them anywhere in their company.
- The same code resolves per company. Granting `senior-agent` on a `JUB-…` target gives
  Jubilee's role; on a `MAD-…` target, Madison's.
- Company roles can't reuse a platform-wide role's code. They can't carry platform-only
  permissions (`identity.platform.manage`, `identity.audit.read`), and they can only
  assign platform-wide roles or their own company's roles.
- Each insurer only sees platform roles, its own roles and its own targets.

### Approval limits

Permissions such as `claims.approve` are flagged **limited**. Each role carries a limit
per currency for each limited permission:

| Role (example) | `claims.approve` limit |
|---|---|
| `branch-manager` (platform default) | KES 1,000,000 |
| `claims-officer` (Jubilee-owned) | KES 500,000 |
| `head-of-claims` | KES unlimited |
| `agent` | none, so no authority |

- No limit for a currency means **no authority** in that currency (fail closed). An
  explicit `maxAmount: null` means unlimited.
- A user's effective limit on a target is the **highest** limit among their grants
  covering that target.
- Insure asks `GET /api/users/{user}/applications/alensi-insure/permissions/claims.approve/targets/{branch}?amount=3000000&currency=KES`.
  The answer is `{"allowed": false, "limits": [{"currency": "KES", "maxAmount": 1000000}]}`,
  which tells insure to route the claim up the chain.
- Platform admins set limits on platform roles; company admins set limits on their own
  company's roles.

### Agent ranks

Agent ranks are business roles granted on the same team target. They differ in
**permissions and limits, not scope**. An agent and their team lead both hold grants on
`JUB-KE-NRB-NWS-T1`, but only the team lead has `team.reports`. "Agents see only their own
customers" is an ownership rule in insure (`policy.agent_id = caller`). The rank decides
whether the caller can also see the rest of the team's records.

## 4. Rules for managing other users

Holding an admin role does not, on its own, let someone change another person's
access. Five rules decide what they can do:

1. **Scope.** An admin can only grant, revoke or view grants on targets inside the
   target their admin role was granted on. A Nairobi West `branch-admin` can't touch
   Mombasa.
2. **Assignable roles.** Each admin role lists exactly which roles it may assign. A
   `branch-admin` can't create another `branch-admin` or a `branch-manager`; only
   the regional level above can.
3. **No self-service.** Nobody can change their own grants. Promotions are done by
   the level above.
4. **Account-wide actions need full coverage.** Suspending a user, setting their
   expiry or resetting MFA affects the whole account. These are allowed only if
   every grant the user holds is inside the admin's scope. A staff member covering
   two regions can only be suspended by someone who covers both, e.g. `company-admin`.
5. **Wildcard is platform-only.** Only a holder of `platform-admin` on `*` can create
   grants on `*`, change the catalog, or create company targets.

Resulting chain of command:

```
platform-admin (Alensi operations)
  └─ manages company-admins
       company-admin (insurer's IT / HR)
         └─ manages regional-admins, branch-admins, any business role in the company
              regional-admin (e.g. Central region)
                └─ manages branch-admins and branch managers in Central
                     branch-admin (e.g. Thika branch)
                       └─ manages team leads, agents, customer service in Thika
                            team-admin (optional, a team lead)
                              └─ onboards agents into their own team
```

`platform-admin` is held by very few people, requires MFA (passkey) at the Keycloak
level, and has no business-data access by default. Seeing claims requires a separate,
audited business grant.

## 5. Scenarios

| Scenario | Outcome |
|---|---|
| Nairobi West branch manager lists claims | Insure asks identity for `claims.view` targets and gets `[JUB-KE-NRB-NWS]`. The query is filtered to that branch. |
| Same manager opens a Mombasa claim by URL | `claims.view` on `JUB-KE-CST-MSA` is denied, so insure returns 403. |
| Central regional manager reviews Thika and Nyeri claims | The grant on `JUB-KE-CEN` covers both branches. |
| Head of claims approves a KES 3M claim from Kisumu | Grant on `JUB-KE` with no approval limit, so allowed. |
| Branch manager tries to approve a KES 3M claim | The KES 1M limit is exceeded. Insure escalates to the regional manager. |
| Thika `branch-admin` onboards a new agent | Allowed: `agent` is assignable, and Thika is inside scope. |
| Thika `branch-admin` makes a colleague a branch manager | Denied: `branch-manager` is not assignable by `branch-admin`. |
| Central `regional-admin` grants someone access in Western | Denied: the target is outside scope. |
| Jubilee `company-admin` touches a Madison user | Denied: different company subtree. |
| Branch manager approves a claim they submitted | Denied by insure's domain rule (segregation of duties), not by identity. |

## 6. Gaps in alensi-identity today

| # | Gap | Status |
|---|---|---|
| 1 | Admin permissions were checked "on any target", so scoped admins acted globally. | **Fixed** (V3, `AccessGuard`). Covered by `MultiInsurerAccessIntegrationTest`. |
| 2 | Assignable roles per admin role; no self-grants. | **Done** |
| 3 | Platform, company, regional and branch admin roles; company targets and `team` level. | **Done** |
| 4 | Approval limits on roles, per currency. | **Done** (V4) |
| 5 | Grants have no `valid_from` / `valid_until` (acting cover during leave). | Missing |
| 6 | Admins can't onboard staff (create the Keycloak user and send the invite). | Missing |
| 7 | No "list users in my scope" endpoint for managers. | Missing |
| 9 | Per-insurer roles and limits. | **Done** (V4) |
| 11 | Platform-wide admin roles' assignable lists are shared. A company that wants its regional admins to assign its own roles creates a company-owned admin role (e.g. a Jubilee regional admin) instead. | By design |
| 10 | The audit log is platform-only; company admins can't yet see their own company's audit trail. | Missing |
| 8 | Customers and policyholders logging in need ownership-based access (their own policies). That belongs in insure, but customer accounts need a separate Keycloak realm or group so they never receive staff roles. | Design decision |

## Sources

- [Jubilee – Regional Bancassurance Managers (regions)](https://jubileeinsurance.com/ke/wp-content/uploads/2024/02/JHIL107-REGIONAL-BANCASSURANCE-MANAGERS.pdf)
- [Jubilee – Regional Head Retail](https://jubileeinsurance.com/ke/wp-content/uploads/2026/03/JHL037-REGIONAL-HEAD-RETAIL.pdf)
- [Jubilee – Branch Manager Nairobi West](https://www.myjobmag.co.ke/job/branch-manager-nairobi-west-jubilee-insurance)
- [Jubilee – leadership / HQ](https://jubileeinsurance.com/ke/leadership)
- [Madison – Regional BDM Western Region](https://www.madison.co.ke/careers/regional-business-development-manager-western-region/)
- [Madison Group profile (four regional offices)](https://www.developmentaid.org/organizations/view/251600/madison-group)
- [Madison branches (third-party, ~2018)](https://victormatara.com/list-of-madison-insurance-branches-in-kenya/)
- [Directline branches (third-party)](https://victormatara.com/list-of-directline-assurance-products-and-branches-in-kenya/)
- [Directline jobs listing (branch towns)](https://www.fuzu.com/company/directline-assurance-company-limited)
- [IRA – Directline still operational (The Star)](https://www.the-star.co.ke/news/africa/2024-06-11-directline-assurance-is-still-operational-says-insurance-regulatory-authority)
- [CIC – Branch Manager reporting to Regional Manager Metropolitan](https://www.corporatestaffing.co.ke/job/branch-manager-job-cic-insurance-nairobi-kenya/)
