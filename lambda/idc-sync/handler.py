"""EventBridge handler that syncs IAM Identity Center group membership to Cognito.

Triggered by CloudTrail-delivered IAM Identity Center directory events
(source ``aws.sso-directory``) for the watched group:

  - ``AddMemberToGroup``      -> resolve the user's email from the Identity Store
                                 and create a Cognito user (Cognito emails an
                                 invitation with a one-time temporary password).
                                 The IDC user ID is used as the Cognito Username
                                 and also stamped as ``custom:idc_user_id`` (kept
                                 for auditing).
  - ``RemoveMemberFromGroup`` -> disable or delete the matching Cognito user.
  - ``DeleteUser``            -> the user no longer exists in IDC, so its email
                                 is unknowable from the event and ``DescribeUser``
                                 will fail. No lookup is needed: the Cognito
                                 Username is the IDC user ID, so the user is
                                 disabled or deleted directly by that ID.

The group-membership rule already filters to the target group, so this handler
does not re-check the group. The ``DeleteUser`` rule is not group-filtered (the
event carries no group ID), so a deletion of a user that was never synced is a
safe no-op.

Environment variables (set by the CDK stack):
  USER_POOL_ID       Cognito User Pool ID
  IDENTITY_STORE_ID  IAM Identity Center Identity Store ID
  ON_REMOVE          "disable" (default) or "delete" — action on member removal
  WATCHED_GROUP_ID   IDC group ID the EventBridge rule filters on; used as a
                     handler-side safety-net re-check (see W1 note below).
"""

import os
from dataclasses import dataclass
from enum import StrEnum

import boto3
from botocore.exceptions import ClientError


class EventName(StrEnum):
    ADD = "AddMemberToGroup"
    REMOVE = "RemoveMemberFromGroup"
    DELETE_USER = "DeleteUser"


# Custom Cognito attribute that stores the originating IDC user ID. The Cognito
# Username is already set to this ID, so the attribute is kept for auditing /
# explicit correlation rather than as the lookup key.
IDC_USER_ID_ATTR = "custom:idc_user_id"


class RemoveAction(StrEnum):
    DISABLE = "disable"
    DELETE = "delete"


USER_POOL_ID = os.environ["USER_POOL_ID"]
IDENTITY_STORE_ID = os.environ["IDENTITY_STORE_ID"]
ON_REMOVE = RemoveAction(os.environ.get("ON_REMOVE", RemoveAction.DISABLE))
# The membership EventBridge rule already filters to this group, but we re-check
# it in the handler as a safety net (see `_extract_group_id`). Empty string means
# "no group configured" — the safety-net check is then skipped.
WATCHED_GROUP_ID = os.environ.get("WATCHED_GROUP_ID", "")

_identitystore = boto3.client("identitystore")
_cognito = boto3.client("cognito-idp")


class SyncError(Exception):
    """Raised when an event cannot be processed."""


@dataclass(frozen=True)
class IdcUser:
    user_id: str
    username: str
    email: str


def _extract_member_id(detail: dict) -> str:
    """Pulls the Identity Store user ID out of the CloudTrail requestParameters.

    The ``member`` field shape can vary across event versions, so we accept the
    common forms: {"member": {"memberId": "<id>"}} or {"member": {"userId": ...}}
    or a bare ``memberId``.
    """
    params = detail.get("requestParameters") or {}
    member = params.get("member") or {}
    member_id = (
        member.get("memberId")
        or member.get("userId")
        or params.get("memberId")
    )
    if not member_id:
        raise SyncError(f"Could not find member id in requestParameters: {params}")
    return member_id


def _extract_group_id(detail: dict) -> str | None:
    """Pulls the IDC group ID out of the CloudTrail requestParameters, if present.

    ASSUMPTION: the group ID lives at ``detail.requestParameters.groupId``. This
    field name has NOT been verified against a real ``AddMemberToGroup`` /
    ``RemoveMemberFromGroup`` CloudTrail event — the EventBridge rule filters on
    the same path, so if the true shape differs, both the rule and this check
    must be updated together. Returns None when the field is absent so the
    caller can decide whether to treat that as a match failure.
    """
    params = detail.get("requestParameters") or {}
    return params.get("groupId")


def _describe_idc_user(user_id: str) -> IdcUser:
    """Resolves an Identity Store user's username and primary email."""
    try:
        resp = _identitystore.describe_user(
            IdentityStoreId=IDENTITY_STORE_ID, UserId=user_id
        )
    except ClientError as e:
        raise SyncError(f"DescribeUser failed for {user_id}: {e}") from e

    username = resp.get("UserName") or user_id
    emails = [e["Value"] for e in resp.get("Emails", []) if e.get("Value")]
    # Prefer the primary email if one is flagged, else the first present.
    primary = next(
        (e["Value"] for e in resp.get("Emails", []) if e.get("Primary") and e.get("Value")),
        None,
    )
    email = primary or (emails[0] if emails else "")
    if not email:
        raise SyncError(f"IDC user {username} ({user_id}) has no email address")
    return IdcUser(user_id=user_id, username=username, email=email)


def _extract_user_id(detail: dict) -> str:
    """Pulls the Identity Store user ID from a `DeleteUser` event's params."""
    params = detail.get("requestParameters") or {}
    user_id = params.get("userId") or params.get("userIdentifier")
    if not user_id:
        raise SyncError(f"Could not find userId in requestParameters: {params}")
    return user_id


def _find_cognito_username_by_email(email: str) -> str | None:
    """Returns the Cognito username whose email matches, or None.

    `email` is a standard attribute, so this uses server-side `ListUsers`
    filtering (which supports standard attributes only).
    """
    try:
        resp = _cognito.list_users(
            UserPoolId=USER_POOL_ID,
            Filter=f'email = "{email}"',
            Limit=1,
        )
    except ClientError as e:
        raise SyncError(f"ListUsers failed for {email}: {e}") from e
    users = resp.get("Users", [])
    return users[0]["Username"] if users else None


def _disable_or_delete_cognito_user(username: str, label: str) -> None:
    """Disables or deletes a Cognito user per the configured ON_REMOVE action."""
    try:
        if ON_REMOVE is RemoveAction.DELETE:
            _cognito.admin_delete_user(UserPoolId=USER_POOL_ID, Username=username)
            print(f"DELETED: {username} ({label})")
        else:
            _cognito.admin_disable_user(UserPoolId=USER_POOL_ID, Username=username)
            print(f"DISABLED: {username} ({label})")
    except _cognito.exceptions.UserNotFoundException:
        print(f"NOT FOUND: {username} already gone — no action")
    except ClientError as e:
        raise SyncError(f"Remove ({ON_REMOVE}) failed for {username}: {e}") from e


def _create_cognito_user(user: IdcUser) -> None:
    """Creates a Cognito user; Cognito emails an invitation with a temp password.

    The User Pool has email configured as a sign-in alias, which forbids a
    Username in email format (Cognito raises InvalidParameterException). So the
    IDC user ID (a UUID) is used as the Username and the email is carried as a
    standard attribute; `_find_cognito_username_by_email` still resolves the
    real Username (the UUID) by filtering on that email attribute.

    Idempotent: if the user already exists, ensure they are enabled. A user
    who was previously removed (RemoveMemberFromGroup / DeleteUser) with
    ON_REMOVE=disable stays in the pool but disabled, so re-adding them must
    re-enable them or they still cannot log in. AdminEnableUser is a no-op when
    the user is already enabled.
    """
    try:
        _cognito.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=user.user_id,
            UserAttributes=[
                {"Name": "email", "Value": user.email},
                {"Name": "email_verified", "Value": "true"},
                {"Name": IDC_USER_ID_ATTR, "Value": user.user_id},
            ],
            DesiredDeliveryMediums=["EMAIL"],
        )
        print(f"CREATED: {user.email} (idc user {user.username}/{user.user_id})")
    except _cognito.exceptions.UsernameExistsException:
        # Already in the pool — re-enable in case a prior removal disabled them.
        try:
            _cognito.admin_enable_user(UserPoolId=USER_POOL_ID, Username=user.user_id)
            print(f"ENABLED: {user.email} already in pool — ensured enabled")
        except _cognito.exceptions.UserNotFoundException:
            # Raced with a deletion between create and enable — nothing to do.
            print(f"NOT FOUND: {user.email} vanished before enable — no action")
        except ClientError as e:
            raise SyncError(f"AdminEnableUser failed for {user.email}: {e}") from e
    except ClientError as e:
        raise SyncError(f"AdminCreateUser failed for {user.email}: {e}") from e


def _remove_cognito_user_by_email(email: str) -> None:
    """Disables or deletes the Cognito user matching the email."""
    username = _find_cognito_username_by_email(email)
    if not username:
        print(f"NOT FOUND: no Cognito user for {email} — no action")
        return
    _disable_or_delete_cognito_user(username, email)


def handler(event: dict, _context: object) -> dict:
    detail = event.get("detail") or {}
    event_name = detail.get("eventName", "")
    print(f"EVENT: {event_name}")

    try:
        match event_name:
            case EventName.ADD | EventName.REMOVE:
                # Safety net: the EventBridge rule should already have filtered
                # to WATCHED_GROUP_ID, but re-check here in case the rule's
                # `requestParameters.groupId` filter path is wrong (see W1 /
                # `_extract_group_id`). Skip the check when no group is
                # configured or the event carries no group ID.
                if WATCHED_GROUP_ID:
                    group_id = _extract_group_id(detail)
                    if group_id is not None and group_id != WATCHED_GROUP_ID:
                        print(
                            f"IGNORED: {event_name} for group {group_id!r} "
                            f"!= watched {WATCHED_GROUP_ID!r}"
                        )
                        return {"status": "ignored", "eventName": event_name}
                member_id = _extract_member_id(detail)
                user = _describe_idc_user(member_id)
                if event_name == EventName.ADD:
                    _create_cognito_user(user)
                else:
                    _remove_cognito_user_by_email(user.email)
            case EventName.DELETE_USER:
                # The IDC user is being deleted, so DescribeUser is unreliable
                # (it will fail once the user is gone). No lookup is needed: the
                # Cognito Username IS the IDC user ID (set in _create_cognito_user),
                # so address the user directly. _disable_or_delete_cognito_user
                # treats a missing user as a safe no-op (UserNotFoundException).
                user_id = _extract_user_id(detail)
                _disable_or_delete_cognito_user(user_id, f"idc_user_id={user_id}")
            case _:
                print(f"IGNORED: unsupported event {event_name!r}")
                return {"status": "ignored", "eventName": event_name}
    except SyncError as e:
        # Log and re-raise so EventBridge records the failure (and can retry).
        print(f"ERROR: {e}")
        raise

    return {"status": "ok", "eventName": event_name}
