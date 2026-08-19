import { CfnOutput, Duration, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Trail } from 'aws-cdk-lib/aws-cloudtrail';
import {
  BlockPublicAccess,
  Bucket,
  BucketEncryption,
} from 'aws-cdk-lib/aws-s3';
import { CognitoOidcProxy } from '../constructs/cognito-oidc-proxy';
import { IdcSyncAutomation } from '../constructs/idc-sync-automation';

export interface QuickDesktopAuthStackProps extends StackProps {
  /**
   * Deploy the IAM Identity Center sync automation (default true). When false,
   * only Cognito + the API Gateway proxy are created and users are managed
   * directly in the Cognito console.
   */
  readonly useIdc?: boolean;
  /** Name of the IAM Identity Center group to watch (required when useIdc). */
  readonly idcGroupName?: string;
  /** Optional CIDR allowlist for the API Gateway. */
  readonly allowedCidrs?: string[];
  /** Enforce TOTP MFA on the Cognito pool. */
  readonly mfaRequired?: boolean;
  /** Retain the User Pool on stack delete. */
  readonly retain?: boolean;
  /** Action on IDC member removal: 'delete' (default) or 'disable'. */
  readonly onRemove?: string;
  /**
   * Create a CloudTrail trail capturing management events (default true).
   * The IAM Identity Center "AWS API Call via CloudTrail" events that drive
   * the sync are only delivered to EventBridge when such a trail exists in the
   * region. Set to false if the account already has a management-event trail.
   * Ignored when useIdc is false — the trail only exists to drive the sync.
   */
  readonly createTrail?: boolean;
}

/**
 * Deploys Amazon Cognito as an OIDC provider for Amazon Quick on desktop, plus
 * — when useIdc is true — automated user provisioning driven by IAM Identity
 * Center group membership.
 */
export class QuickDesktopAuthStack extends Stack {
  constructor(scope: Construct, id: string, props: QuickDesktopAuthStackProps) {
    super(scope, id, props);

    const { idcGroupName, allowedCidrs, mfaRequired, retain, onRemove } = props;
    const useIdc = props.useIdc ?? true;
    const createTrail = props.createTrail ?? true;
    const removalPolicy = retain ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;

    if (useIdc && !idcGroupName) {
      throw new Error('idcGroupName is required when useIdc is true.');
    }

    // CloudTrail trail (management events) — required so IAM Identity Center's
    // "AWS API Call via CloudTrail" events reach EventBridge in this region.
    // Conditional: skip when the account already has a management-event trail,
    // and entirely unnecessary when the IDC sync is not deployed.
    if (useIdc && createTrail) {
      const trailBucket = new Bucket(this, 'CloudTrailBucket', {
        encryption: BucketEncryption.S3_MANAGED,
        blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
        enforceSSL: true,
        // Expire trail logs after 90 days to bound storage cost.
        lifecycleRules: [{ expiration: Duration.days(90) }],
        removalPolicy,
        // Only allow CDK to empty + delete the bucket when it isn't retained.
        autoDeleteObjects: !retain,
      });

      new Trail(this, 'ManagementEventsTrail', {
        trailName: 'QuickDesktopIdcManagementEvents',
        bucket: trailBucket,
        // Just this region — IDC directory events are emitted here.
        isMultiRegionTrail: false,
        // Management events are captured by default; that is what carries the
        // IAM Identity Center AddMemberToGroup/RemoveMemberFromGroup/DeleteUser
        // events into EventBridge.
        includeGlobalServiceEvents: false,
      });
    }

    // Cognito + API Gateway + auth proxy Lambda.
    const oidc = new CognitoOidcProxy(this, 'Oidc', {
      mfaRequired,
      removalPolicy,
      allowedCidrs,
    });

    // EventBridge + sync Lambda + deploy-time IDC resolver custom resource.
    // Skipped with useIdc=false: users are then managed in the Cognito console.
    if (useIdc) {
      new IdcSyncAutomation(this, 'IdcSync', {
        idcGroupName: idcGroupName!,
        userPool: oidc.userPool,
        onRemove,
      });
    }

    // --- Outputs (used to configure the Amazon Quick extension) --------------
    new CfnOutput(this, 'PoolId', {
      value: oidc.userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });
    new CfnOutput(this, 'ClientId', {
      value: oidc.userPoolClient.userPoolClientId,
      description: 'App client ID (aud claim)',
    });
    new CfnOutput(this, 'IssuerUrl', {
      value: oidc.issuerUrl,
      description: 'OIDC issuer URL',
    });
    new CfnOutput(this, 'AuthEndpoint', {
      value: oidc.authEndpoint,
      description: 'Authorization endpoint (via proxy)',
    });
    new CfnOutput(this, 'TokenEndpoint', {
      value: oidc.tokenEndpoint,
      description: 'Token endpoint (via proxy)',
    });
    new CfnOutput(this, 'JwksUri', {
      value: oidc.jwksUri,
      description: 'JSON Web Key Set URI',
    });
  }
}
