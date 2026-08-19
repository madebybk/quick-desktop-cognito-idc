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
// Defaults to true; only an explicit "false" (or boolean false) disables it.
const useIdcCtx = app.node.tryGetContext('useIdc');
const useIdc = !(useIdcCtx === false || useIdcCtx === 'false');
const idcGroupName = app.node.tryGetContext('idcGroupName') as string | undefined;
const allowedCidrs = app.node.tryGetContext('allowedCidrs') as string[] | undefined;
const mfaRequired = app.node.tryGetContext('mfaRequired') === true ||
  app.node.tryGetContext('mfaRequired') === 'true';
const retain = app.node.tryGetContext('retain') === true ||
  app.node.tryGetContext('retain') === 'true';
const onRemove = (app.node.tryGetContext('onRemove') as string | undefined) ?? 'delete';
// Defaults to true; only an explicit "false" (or boolean false) disables it.
const createTrailCtx = app.node.tryGetContext('createTrail');
const createTrail = !(createTrailCtx === false || createTrailCtx === 'false');

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
