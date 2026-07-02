# Amazon Quick on Desktop — Cognito OIDC Provider with automated IAM Identity Center sync

[Amazon Quick on desktop](https://docs.aws.amazon.com/quick/latest/userguide/amazon-quick-desktop.html)
for enterprise sign-in requires an
[OIDC-compatible identity provider](https://docs.aws.amazon.com/quick/latest/userguide/desktop-enterprise-setup.html)
(Entra ID, Okta, Auth0, PingOne, …). This CDK project lets you use **Amazon
Cognito as that OIDC provider** — no external IdP required — and **keeps the
Cognito user pool in sync with an IAM Identity Center group automatically**.

IAM Identity Center stays the single source of truth for *who* is a Quick
desktop user. Add a person to the watched group and they get a Cognito
invitation email; remove them and their Cognito user is disabled (or deleted).

## Architecture

```
IAM Identity Center (user management — single source of truth)
    │  AddMemberToGroup / RemoveMemberFromGroup  (CloudTrail → EventBridge)
    ▼
EventBridge Rule  (filtered to the watched group ID)
    ▼
Lambda: idc-sync  (creates / disables / deletes Cognito users)
    ▼
Amazon Cognito User Pool  (OIDC provider for Quick desktop)
    ▲
Quick Desktop App → API Gateway + Lambda proxy (strips offline_access) → Cognito
    ▼
Amazon Quick account
```

Two CDK constructs implement this:

| Construct | File | Responsibility |
|-----------|------|----------------|
| `CognitoOidcProxy` | `lib/constructs/cognito-oidc-proxy.ts` | Cognito User Pool + hosted-UI domain + public app client, and an API Gateway REST API with a Lambda proxy that strips the `offline_access` scope. |
| `IdcSyncAutomation` | `lib/constructs/idc-sync-automation.ts` | Deploy-time custom resource that resolves the IDC instance + group ID, an EventBridge rule filtered to that group (membership changes) plus a second rule for `DeleteUser`, and the sync Lambda. |

### Why the proxy strips `offline_access`

Amazon Quick sends an `offline_access` scope on every OAuth request, but Cognito
does not support that scope and rejects the request. The proxy
(`lambda/auth-proxy/index.py`) removes `offline_access` from the `scope`
parameter on `GET /oauth2/authorize` (302 redirect) and `POST /oauth2/token`
(server-side forward) before reaching Cognito.

### Why a deploy-time custom resource

The EventBridge event payload for group membership carries **IDs, not names**.
You configure the group by *name* (`idcGroupName`), so at deploy time a custom
resource (`lambda/idc-sync/custom_resource.py`) calls `sso:ListInstances` and
`identitystore:ListGroups` to resolve the IDC instance / Identity Store ID and
the group's ID. If no group with that name exists, the resolver creates it
(`identitystore:CreateGroup`) and returns the new ID. The group ID becomes the
EventBridge filter; the Identity Store ID becomes a sync-Lambda environment
variable.

On stack delete the group is intentionally left in place (never deleted), since
users may be assigned to it and deleting it would orphan those assignments.

## CloudTrail requirement

IAM Identity Center emits its directory changes as **"AWS API Call via
CloudTrail"** events. EventBridge only receives these events in a region where a
**CloudTrail trail capturing management events** exists. Without such a trail the
sync rules never fire.

By default this stack **creates a trail for you** (`createTrail=true`): a
single-region trail with management events enabled, writing to a dedicated S3
bucket whose logs expire after 90 days (the bucket is retained when you deploy
with `-c retain=true`, otherwise it is emptied and deleted with the stack).

If your account **already has** a management-event trail in the deploy region,
skip the extra trail to avoid duplicate logging and cost:

```bash
cdk deploy -c idcGroupName=QuickDesktopUsers -c createTrail=false
```

## Prerequisites

- An AWS account with an active Amazon Quick subscription.
- **IAM Identity Center enabled in the deploy region.** The group you want to
  watch (e.g. `QuickDesktopUsers`) may already exist; if it does not, the deploy
  creates it for you.
- Node.js 18+, the AWS CDK CLI, and configured AWS credentials.
- Python 3.12 (Lambda runtime — used by AWS, not required locally).

> **Region.** Deploy into the **same region as IAM Identity Center**, because the
> membership CloudTrail events are emitted there. Cognito itself does not need
> to be in `us-east-1`; Quick validates tokens over HTTPS region-agnostically.
> The stack reads the account/region from your ambient CLI credentials and
> hardcodes neither.

## Context parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `idcGroupName` | **yes** | Name of the IAM Identity Center group to watch (e.g. `QuickDesktopUsers`). |
| `allowedCidrs` | no | JSON array of CIDRs allowed to reach the API Gateway. Omit to leave it open. |
| `mfaRequired` | no | `true` to enforce TOTP (authenticator-app) MFA for all users. |
| `retain` | no | `true` to retain the Cognito User Pool (and the CloudTrail log bucket) when the stack is destroyed. |
| `onRemove` | no | `disable` (default) or `delete` — what to do to the Cognito user when someone leaves the group. |
| `createTrail` | no | `true` (default) to create a CloudTrail trail capturing management events. Set `false` if the account already has a management-event trail in this region (see [CloudTrail requirement](#cloudtrail-requirement)). |

## Deploy

```bash
npm install
npm run build           # optional type-check
cdk deploy -c idcGroupName=QuickDesktopUsers
```

With options:

```bash
cdk deploy \
  -c idcGroupName=QuickDesktopUsers \
  -c allowedCidrs='["203.0.113.0/24","198.51.100.0/24"]' \
  -c mfaRequired=true \
  -c onRemove=delete \
  -c retain=true
```

## Stack outputs

After deploy, retrieve the outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name QuickDesktopCognitoIdcStack \
  --query "Stacks[0].Outputs" --output table
```

| Output | Description |
|--------|-------------|
| `PoolId` | Cognito User Pool ID |
| `ClientId` | App client ID (also the `aud` claim) |
| `IssuerUrl` | OIDC issuer URL |
| `AuthEndpoint` | Authorization endpoint (points to the proxy) |
| `TokenEndpoint` | Token endpoint (points to the proxy) |
| `JwksUri` | JSON Web Key Set URI |

## Configure Amazon Quick

In the Amazon Quick management console, create the desktop extension using the
outputs above:

| Amazon Quick field | Stack output |
|--------------------|--------------|
| Client ID / Aud claim | `ClientId` |
| Issuer URL | `IssuerUrl` |
| Authorization endpoint | `AuthEndpoint` |
| Token endpoint | `TokenEndpoint` |
| JWKS URI | `JwksUri` |

Follow [Step 2 in the enterprise setup guide](https://docs.aws.amazon.com/quick/latest/userguide/desktop-enterprise-setup.html)
for the complete instructions.

## How sync works at runtime

1. An admin adds a user to the watched IDC group.
2. CloudTrail emits `AddMemberToGroup` (source `aws.sso-directory`); EventBridge
   matches it against the resolved group ID and invokes the sync Lambda.
3. The Lambda calls `identitystore:DescribeUser` to get the member's email, then
   `cognito-idp:AdminCreateUser` with that email. Cognito sends an invitation
   email with a one-time temporary password; the user sets their own password
   on first sign-in.
4. On `RemoveMemberFromGroup`, the Lambda finds the Cognito user by email
   (`ListUsers`) and disables (`AdminDisableUser`) or deletes
   (`AdminDeleteUser`) it, per `onRemove`.
5. On `DeleteUser` (a user removed from IDC entirely), the email is unknowable
   from the event and `DescribeUser` would fail, so the Lambda correlates via
   the `custom:idc_user_id` attribute it stamps on each Cognito user at
   creation. Because Cognito `ListUsers` cannot server-side filter on custom
   attributes, the Lambda paginates the pool and matches that attribute
   client-side, then disables/deletes per `onRemove`. A second EventBridge rule
   (no group filter, since `DeleteUser` carries no group ID) routes these
   events; deletion of a never-synced user is a safe no-op.

> The email on each Cognito user must exactly match the user's email in Amazon
> Quick. Because the User Pool has email as a sign-in alias, the Cognito
> *username* is set to the IDC user ID (a UUID) — an email-format username is
> rejected — while the email is stored as a standard user attribute that the
> sync Lambda filters on to locate the user.

> **Email delivery.** By default the User Pool uses Cognito's built-in email,
> which is rate-limited and intended for testing. For production, configure
> Amazon SES on the User Pool.

## IAM permissions (least privilege)

| Principal | Permissions |
|-----------|-------------|
| Custom-resource Lambda | `sso:ListInstances`, `identitystore:ListGroups`, `identitystore:CreateGroup` (creates the watched group if absent) |
| Sync Lambda | `identitystore:DescribeUser` (scoped by action to the identitystore service in this account/region), `cognito-idp:AdminCreateUser`, `cognito-idp:AdminDisableUser`, `cognito-idp:AdminDeleteUser`, `cognito-idp:ListUsers` (scoped to the User Pool ARN) |

## Security considerations

- **API Gateway is public by default.** The proxy only forwards OAuth requests
  to Cognito and exposes no sensitive data, but you should restrict access with
  `allowedCidrs` (corporate NAT/VPN egress ranges) and/or a regional AWS WAF web
  ACL on the `prod` stage.
- **MFA.** Deploy with `-c mfaRequired=true` to require authenticator-app MFA.
- **User Pool hardening.** Review the pool configuration in
  `lib/constructs/cognito-oidc-proxy.ts` (password policy, token validity,
  threat protection) against your organization's policies before production use.

## Project structure

```
quick-desktop-cognito-idc/
├── README.md
├── package.json
├── tsconfig.json
├── cdk.json
├── lib/
│   ├── app.ts
│   ├── stacks/
│   │   └── quick-desktop-auth-stack.ts
│   └── constructs/
│       ├── cognito-oidc-proxy.ts       # Cognito + API GW + proxy Lambda
│       └── idc-sync-automation.ts      # EventBridge + sync Lambda + custom resource
├── lambda/
│   ├── auth-proxy/
│   │   └── index.py                    # Strips offline_access from OAuth requests
│   └── idc-sync/
│       ├── handler.py                  # EventBridge handler (create/delete Cognito users)
│       └── custom_resource.py          # Resolves IDC instance + group ID at deploy time
└── .gitignore
```

## Cleanup

```bash
cdk destroy
```

Then manually delete the extension access and extension from the Amazon Quick
management console. (If you deployed with `-c retain=true`, delete the Cognito
User Pool manually.)
