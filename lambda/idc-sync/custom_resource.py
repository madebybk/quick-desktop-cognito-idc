"""Deploy-time custom resource: resolves the IAM Identity Center instance and group.

Backed by the CDK ``custom_resources.Provider`` framework, so the handler only
returns ``Data`` / ``PhysicalResourceId`` — the framework sends the
CloudFormation response.

On Create/Update it resolves, from the group name passed in:
  - the IAM Identity Center instance ARN and Identity Store ID (``ListInstances``)
  - the group ID for the named group (``ListGroups`` filtered by DisplayName)

These values are read back by the stack and injected as environment variables on
the sync Lambda and as the group-ID filter on the EventBridge rule.

On Delete it is a no-op (nothing is created by this resource).
"""

import os

import boto3
from botocore.exceptions import ClientError

_sso_admin = boto3.client("sso-admin")
_identitystore = boto3.client("identitystore")


class ResolveError(Exception):
    """Raised when the IDC instance or group cannot be resolved."""


def _resolve_instance() -> tuple[str, str]:
    """Returns (instance_arn, identity_store_id) for the account's IDC instance."""
    try:
        resp = _sso_admin.list_instances()
    except ClientError as e:
        raise ResolveError(f"ListInstances failed: {e}") from e

    instances = resp.get("Instances", [])
    if not instances:
        raise ResolveError(
            "No IAM Identity Center instance found in this account/region. "
            "Enable IAM Identity Center in the deploy region first."
        )
    instance = instances[0]
    return instance["InstanceArn"], instance["IdentityStoreId"]


def _resolve_group_id(identity_store_id: str, group_name: str) -> str:
    """Returns the group ID for the named group within the identity store."""
    try:
        resp = _identitystore.list_groups(
            IdentityStoreId=identity_store_id,
            Filters=[{"AttributePath": "DisplayName", "AttributeValue": group_name}],
        )
    except ClientError as e:
        raise ResolveError(f"ListGroups failed for '{group_name}': {e}") from e

    groups = resp.get("Groups", [])
    if not groups:
        raise ResolveError(
            f"No IAM Identity Center group named '{group_name}' found in "
            f"identity store {identity_store_id}."
        )
    return groups[0]["GroupId"]


def handler(event: dict, _context: object) -> dict:
    request_type = event.get("RequestType")
    print(f"REQUEST: {request_type}")

    if request_type == "Delete":
        return {"PhysicalResourceId": event.get("PhysicalResourceId", "idc-resolver")}

    props = event.get("ResourceProperties") or {}
    group_name = props.get("GroupName")
    if not group_name:
        raise ResolveError("GroupName resource property is required")

    instance_arn, identity_store_id = _resolve_instance()
    group_id = _resolve_group_id(identity_store_id, group_name)

    print(
        f"RESOLVED: instance={instance_arn} "
        f"identityStore={identity_store_id} group={group_name} -> {group_id}"
    )

    # PhysicalResourceId is stable per (group name) so updates don't replace the
    # resource unnecessarily.
    return {
        "PhysicalResourceId": f"idc-resolver-{group_name}",
        "Data": {
            "InstanceArn": instance_arn,
            "IdentityStoreId": identity_store_id,
            "GroupId": group_id,
        },
    }
