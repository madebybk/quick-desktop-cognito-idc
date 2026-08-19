#!/usr/bin/env node
import 'source-map-support/register';
import { App, Tags } from 'aws-cdk-lib';
import { QuickDesktopAuthStack } from './stacks/quick-desktop-auth-stack';

const app = new App();

// --- Context parameters -----------------------------------------------------
// useIdc       (optional): "false" to deploy Cognito + the API Gateway proxy
//              only, skipping all IAM Identity Center automation (default true).
// idcGroupName (required when useIdc=true): name of the IAM Identity Center
//              group to watch.
// allowedCidrs (optional): JSON array of CIDRs allowed to reach the API Gateway.
// mfaRequired  (optional): "true" to enforce TOTP MFA on the Cognito pool.
// retain       (optional): "true" to retain the User Pool on stack delete.
// createTrail  (optional): "false" to skip creating a CloudTrail trail (default
//              true) — set false if the account already has a management-event
//              trail in this region. Ignored when useIdc=false.
// `-c` values always arrive as strings, so accept the usual spellings of
// true/false in any case ("True", "FALSE", "no", "off", …) rather than silently
// treating an unrecognised value as the default. cdk.json entries arrive as real
// booleans and pass through unchanged.
const FALSEY = ['false', '0', 'no', 'off'];
const TRUTHY = ['true', '1', 'yes', 'on'];
const boolContext = (name: string, fallback: boolean): boolean => {
  const raw = app.node.tryGetContext(name);
  if (raw === undefined || raw === null || raw === '') return fallback;
  const value = String(raw).trim().toLowerCase();
  if (FALSEY.includes(value)) return false;
  if (TRUTHY.includes(value)) return true;
  throw new Error(
    `Context parameter '${name}' must be a boolean; got '${raw}'. ` +
      `Use one of: ${[...TRUTHY, ...FALSEY].join(', ')}`,
  );
};

const useIdc = boolContext('useIdc', true);
const idcGroupName = app.node.tryGetContext('idcGroupName') as string | undefined;
// The CDK CLI hands `-c allowedCidrs='["1.2.3.0/24"]'` over as a string, while
// cdk.json / cdk.context.json entries arrive as a real array. Accept both.
const allowedCidrsRaw = app.node.tryGetContext('allowedCidrs');
let allowedCidrs: string[] | undefined;
if (allowedCidrsRaw) {
  if (typeof allowedCidrsRaw === 'string') {
    try {
      allowedCidrs = JSON.parse(allowedCidrsRaw);
    } catch {
      throw new Error(
        `Context parameter 'allowedCidrs' is not valid JSON: ${allowedCidrsRaw}. ` +
          `Pass a JSON array, e.g. -c allowedCidrs='["203.0.113.0/24"]'`,
      );
    }
  } else {
    allowedCidrs = allowedCidrsRaw as string[];
  }
  if (!Array.isArray(allowedCidrs) || allowedCidrs.some((c) => typeof c !== 'string')) {
    throw new Error(
      "Context parameter 'allowedCidrs' must be an array of CIDR strings, " +
        `e.g. -c allowedCidrs='["203.0.113.0/24"]'`,
    );
  }
}
const mfaRequired = boolContext('mfaRequired', false);
const retain = boolContext('retain', false);
// Validate at synth time — an unknown value would otherwise only surface as a
// no-op in the sync Lambda, long after deploy.
const onRemoveRaw = app.node.tryGetContext('onRemove') as string | undefined;
const VALID_ON_REMOVE = ['delete', 'disable'];
if (onRemoveRaw && !VALID_ON_REMOVE.includes(onRemoveRaw)) {
  throw new Error(
    `Invalid onRemove value '${onRemoveRaw}'. ` +
      `Must be one of: ${VALID_ON_REMOVE.join(', ')}`,
  );
}
const onRemove = onRemoveRaw ?? 'delete';
const createTrail = boolContext('createTrail', true);

// Only the IDC-backed deployment needs a group to watch.
if (useIdc && !idcGroupName) {
  throw new Error(
    "Context parameter 'idcGroupName' is required when useIdc=true. " +
      'Deploy with: cdk deploy -c idcGroupName=QuickDesktopUsers, ' +
      'or deploy Cognito only with: cdk deploy -c useIdc=false',
  );
}

const stack = new QuickDesktopAuthStack(app, 'QuickDesktopCognitoIdcStack', {
  description: useIdc
    ? 'Amazon Cognito OIDC provider for Amazon Quick on desktop, with automated ' +
      'user sync from IAM Identity Center (qs-quick-desktop-cognito-idc)'
    : 'Amazon Cognito OIDC provider for Amazon Quick on desktop ' +
      '(qs-quick-desktop-cognito-idc)',
  useIdc,
  idcGroupName,
  allowedCidrs,
  mfaRequired,
  retain,
  onRemove,
  createTrail,
  // Deploy into the region IAM Identity Center emits its events in — which is
  // the account/region resolved from the ambient CLI credentials/profile.
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});

Tags.of(stack).add('project', 'quick-desktop-cognito-idc');
Tags.of(stack).add('managed-by', 'cdk');

app.synth();
