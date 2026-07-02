import { CustomResource, Duration } from 'aws-cdk-lib';
import { Function as LambdaFunction, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import { Provider } from 'aws-cdk-lib/custom-resources';
import { Rule } from 'aws-cdk-lib/aws-events';
import { LambdaFunction as LambdaTarget } from 'aws-cdk-lib/aws-events-targets';
import { PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';
import { Queue } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { join } from 'path';
import { UserPool } from 'aws-cdk-lib/aws-cognito';

// Files excluded from the Lambda asset bundles: local Python build artifacts
// that would otherwise change the asset hash and bloat the deployment package.
const LAMBDA_ASSET_EXCLUDE = ['__pycache__', '*.pyc', '__pycache__/**'];

export interface IdcSyncAutomationProps {
  /** Name of the IAM Identity Center group to watch (resolved to an ID at deploy). */
  readonly idcGroupName: string;
  /** Cognito User Pool that users are synced into. */
  readonly userPool: UserPool;
  /** Action on member removal: 'disable' (default) or 'delete'. */
  readonly onRemove?: string;
}

/**
 * Automated user sync from IAM Identity Center to Cognito.
 *
 *  - A deploy-time custom resource resolves the IDC instance + Identity Store ID
 *    and the watched group's ID from its name, creating the group if it does
 *    not already exist.
 *  - An EventBridge rule captures `AddMemberToGroup` / `RemoveMemberFromGroup`
 *    CloudTrail events, filtered to that group ID.
 *  - A second EventBridge rule captures `DeleteUser` events (user-level, so no
 *    group ID is present in the payload) and routes them to the same Lambda.
 *  - A sync Lambda creates/disables/deletes the corresponding Cognito user.
 */
export class IdcSyncAutomation extends Construct {
  public readonly syncFunction: LambdaFunction;
  public readonly groupId: string;
  public readonly identityStoreId: string;

  constructor(scope: Construct, id: string, props: IdcSyncAutomationProps) {
    super(scope, id);

    const { idcGroupName, userPool, onRemove } = props;

    // --- Deploy-time resolver custom resource --------------------------------
    const resolverFn = new LambdaFunction(this, 'IdcResolverFunction', {
      functionName: 'QuickDesktopIdcResolver',
      runtime: Runtime.PYTHON_3_12,
      handler: 'custom_resource.handler',
      code: Code.fromAsset(join(__dirname, '..', '..', 'lambda', 'idc-sync'), {
        exclude: LAMBDA_ASSET_EXCLUDE,
      }),
      timeout: Duration.seconds(30),
      description: 'Resolves IDC instance ARN and group ID at deploy time',
    });
    // Least privilege: the read APIs needed to resolve the instance + group,
    // plus CreateGroup so the resolver can create the watched group when it does
    // not yet exist. These APIs do not support resource-level scoping.
    resolverFn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'sso:ListInstances',
          'identitystore:ListGroups',
          'identitystore:CreateGroup',
        ],
        resources: ['*'],
      }),
    );

    const provider = new Provider(this, 'IdcResolverProvider', {
      onEventHandler: resolverFn,
    });

    const resolved = new CustomResource(this, 'IdcResolved', {
      serviceToken: provider.serviceToken,
      properties: {
        // Force a re-resolve whenever the watched group name changes.
        GroupName: idcGroupName,
      },
    });

    this.identityStoreId = resolved.getAttString('IdentityStoreId');
    this.groupId = resolved.getAttString('GroupId');

    // --- Sync Lambda ---------------------------------------------------------
    this.syncFunction = new LambdaFunction(this, 'IdcSyncFunction', {
      functionName: 'QuickDesktopIdcSync',
      runtime: Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: Code.fromAsset(join(__dirname, '..', '..', 'lambda', 'idc-sync'), {
        exclude: LAMBDA_ASSET_EXCLUDE,
      }),
      timeout: Duration.seconds(30),
      environment: {
        USER_POOL_ID: userPool.userPoolId,
        IDENTITY_STORE_ID: this.identityStoreId,
        ON_REMOVE: onRemove ?? 'disable',
        // Safety-net group re-check in the handler (see handler.py W1 note).
        WATCHED_GROUP_ID: this.groupId,
      },
      description: 'Syncs IDC group membership changes into the Cognito pool',
    });

    // Least privilege: read IDC user details + manage users in this pool only.
    this.syncFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['identitystore:DescribeUser'],
        // Scoped to '*': Identity Store resource ARNs are not regionalized in a
        // standard way — real ARNs carry an empty region (and users an empty
        // account too), e.g. `arn:aws:identitystore:::user/<id>`, so a
        // region/account-qualified ARN never matches and the call is denied.
        // The grant stays least-privilege via the single action (DescribeUser).
        resources: ['*'],
      }),
    );
    this.syncFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'cognito-idp:AdminCreateUser',
          'cognito-idp:AdminEnableUser',
          'cognito-idp:AdminDisableUser',
          'cognito-idp:AdminDeleteUser',
          'cognito-idp:ListUsers',
        ],
        resources: [userPool.userPoolArn],
      }),
    );

    // --- Dead-letter queue for failed event deliveries -----------------------
    // Events that the sync Lambda fails to process (after target retries) land
    // here instead of being silently dropped, so they can be inspected/replayed.
    const deadLetterQueue = new Queue(this, 'IdcSyncDlq', {
      queueName: 'QuickDesktopIdcSyncDlq',
      retentionPeriod: Duration.days(14),
    });

    // --- EventBridge rule (filtered to the resolved group ID) ----------------
    // IAM Identity Center directory events arrive via CloudTrail with
    // source `aws.sso-directory`. We filter on the specific group ID because
    // the event payload carries IDs, not group names.
    const rule = new Rule(this, 'IdcMembershipRule', {
      ruleName: 'QuickDesktopIdcMembershipSync',
      description: `Sync Cognito on membership changes for IDC group ${idcGroupName}`,
      eventPattern: {
        source: ['aws.sso-directory'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['sso-directory.amazonaws.com'],
          eventName: ['AddMemberToGroup', 'RemoveMemberFromGroup'],
          requestParameters: {
            groupId: [this.groupId],
          },
        },
      },
    });

    rule.addTarget(
      new LambdaTarget(this.syncFunction, { retryAttempts: 2, deadLetterQueue }),
    );

    // --- EventBridge rule for user deletion (no group filter) ----------------
    // `DeleteUser` is a user-level event and carries no `groupId`, so it cannot
    // be filtered by group. We route every IDC user deletion to the Lambda; the
    // handler correlates by the `custom:idc_user_id` attribute it stamps on each
    // Cognito user at creation, and is a safe no-op when no Cognito user matches.
    const deleteRule = new Rule(this, 'IdcUserDeleteRule', {
      ruleName: 'QuickDesktopIdcUserDeleteSync',
      description: 'Sync Cognito when an IDC user is deleted',
      eventPattern: {
        source: ['aws.sso-directory'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['sso-directory.amazonaws.com'],
          eventName: ['DeleteUser'],
        },
      },
    });

    deleteRule.addTarget(
      new LambdaTarget(this.syncFunction, { retryAttempts: 2, deadLetterQueue }),
    );
  }
}
