import { Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import {
  UserPool,
  UserPoolClient,
  UserPoolDomain,
  Mfa,
  OAuthScope,
  AccountRecovery,
  StringAttribute,
} from 'aws-cdk-lib/aws-cognito';
import {
  RestApi,
  LambdaIntegration,
  EndpointType,
  MethodLoggingLevel,
} from 'aws-cdk-lib/aws-apigateway';
import { Function as LambdaFunction, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import {
  PolicyDocument,
  PolicyStatement,
  Effect,
  AnyPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { join } from 'path';

export interface CognitoOidcProxyProps {
  /** Enforce TOTP (authenticator-app) MFA on all users. */
  readonly mfaRequired?: boolean;
  /** Retain the User Pool when the stack is destroyed. */
  readonly removalPolicy: RemovalPolicy;
  /** Optional IP allowlist (CIDRs) applied as an API Gateway resource policy. */
  readonly allowedCidrs?: string[];
}

/**
 * Amazon Cognito configured as an OIDC provider for Amazon Quick on desktop,
 * fronted by an API Gateway + Lambda proxy that strips the `offline_access`
 * scope (which Quick sends but Cognito does not support) from OAuth requests.
 */
export class CognitoOidcProxy extends Construct {
  public readonly userPool: UserPool;
  public readonly userPoolClient: UserPoolClient;
  public readonly api: RestApi;
  public readonly issuerUrl: string;
  public readonly authEndpoint: string;
  public readonly tokenEndpoint: string;
  public readonly jwksUri: string;

  constructor(scope: Construct, id: string, props: CognitoOidcProxyProps) {
    super(scope, id);

    const { account, region } = Stack.of(this);
    const { mfaRequired, removalPolicy, allowedCidrs } = props;

    // --- Cognito User Pool ---------------------------------------------------
    this.userPool = new UserPool(this, 'UserPool', {
      userPoolName: 'QuickDesktopUserPool',
      selfSignUpEnabled: false,
      signInAliases: { username: true, email: true },
      autoVerify: { email: true },
      userInvitation: {
        emailSubject: 'Amazon Quick Desktop 초대',
        emailBody: `Amazon Quick Desktop에 초대되었습니다.\n\n이메일 주소로 로그인하세요.\n임시 비밀번호: {####}\n\n첫 로그인 시 새 비밀번호를 설정하게 됩니다.`,
      },
      standardAttributes: { email: { required: true, mutable: true } },
      // Correlates each Cognito user back to its IAM Identity Center user ID, so
      // the sync Lambda can find the right user on a `DeleteUser` event (which
      // carries only the IDC userId, not an email).
      customAttributes: {
        idc_user_id: new StringAttribute({ minLen: 1, maxLen: 256, mutable: true }),
      },
      mfa: mfaRequired ? Mfa.REQUIRED : Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      accountRecovery: AccountRecovery.EMAIL_ONLY,
      removalPolicy,
    });

    // Hosted-UI domain. The prefix is account+region scoped to stay globally
    // unique without hardcoding any account or region.
    const domainPrefix = `quick-desktop-${account}-${region}`;
    new UserPoolDomain(this, 'UserPoolDomain', {
      userPool: this.userPool,
      cognitoDomain: { domainPrefix },
    });

    // Public app client (no secret) — Quick desktop is a public OAuth client
    // using the authorization-code grant.
    this.userPoolClient = this.userPool.addClient('AppClient', {
      userPoolClientName: 'QuickDesktopAppClient',
      generateSecret: false,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [OAuthScope.OPENID, OAuthScope.EMAIL, OAuthScope.PROFILE],
        callbackUrls: ['http://localhost:18080'],
      },
      // No explicit authFlows: Quick uses only the OAuth authorization-code
      // grant via the hosted UI, so the SRP/USER_PASSWORD auth flows are
      // unnecessary and enabling them only widens the attack surface.
    });

    const cognitoDomain = `https://${domainPrefix}.auth.${region}.amazoncognito.com`;
    this.issuerUrl = `https://cognito-idp.${region}.amazonaws.com/${this.userPool.userPoolId}`;
    this.jwksUri = `${this.issuerUrl}/.well-known/jwks.json`;

    // --- Auth proxy Lambda ---------------------------------------------------
    const proxyFn = new LambdaFunction(this, 'AuthProxyFunction', {
      functionName: 'QuickDesktopAuthProxy',
      runtime: Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: Code.fromAsset(join(__dirname, '..', '..', 'lambda', 'auth-proxy')),
      timeout: Duration.seconds(10),
      environment: { COGNITO_DOMAIN: cognitoDomain },
      description: 'Strips offline_access scope from Quick desktop OAuth requests',
    });

    const integration = new LambdaIntegration(proxyFn);
    const policy = allowedCidrs ? this.createResourcePolicy(allowedCidrs) : undefined;

    this.api = new RestApi(this, 'AuthProxyApi', {
      restApiName: 'QuickDesktopAuthProxy',
      description: 'OAuth proxy in front of the Cognito hosted UI',
      endpointTypes: [EndpointType.REGIONAL],
      deployOptions: {
        stageName: 'prod',
        loggingLevel: MethodLoggingLevel.ERROR,
      },
      ...(policy && { policy }),
    });

    const oauth2 = this.api.root.addResource('oauth2');
    oauth2.addResource('authorize').addMethod('GET', integration);
    oauth2.addResource('token').addMethod('POST', integration);

    this.authEndpoint = `${this.api.url}oauth2/authorize`;
    this.tokenEndpoint = `${this.api.url}oauth2/token`;
  }

  /**
   * Resource policy that allows `execute-api:Invoke` only from the supplied
   * CIDRs and denies everything else (returns 403 to other source IPs).
   */
  private createResourcePolicy(allowedCidrs: string[]): PolicyDocument {
    return new PolicyDocument({
      statements: [
        new PolicyStatement({
          effect: Effect.ALLOW,
          principals: [new AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*/*/*'],
        }),
        new PolicyStatement({
          effect: Effect.DENY,
          principals: [new AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*/*/*'],
          conditions: { NotIpAddress: { 'aws:SourceIp': allowedCidrs } },
        }),
      ],
    });
  }
}
