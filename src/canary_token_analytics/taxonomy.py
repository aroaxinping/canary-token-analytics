"""Intent taxonomy for canary-token AWS API events.

Maps each observed ``event_name`` to an attack-lifecycle ``phase`` and a
human-readable description. This mapping is authoritative for the project:
it is derived from what each AWS API call reveals about the operator's
intent, not from any external framework.
"""

# event_name -> (phase, description)
INTENT_TAXONOMY = {
    "GetCallerIdentity": (
        "validation",
        "Confirms the stolen key is live and reveals which account/identity "
        "it belongs to",
    ),
    "GetUser": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetAccount": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "ListRoles": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "ListAttachedUserPolicies": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetRegions": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "DescribeSeverityLevels": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetServiceQuota": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetSendQuota": (
        "abuse-prep",
        "Checks the SES email sending quota - precursor to spam/phishing "
        "from the account",
    ),
    "ListUserPolicies": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "ListSecrets": (
        "reconnaissance",
        "Enumerates AWS Secrets Manager entries, hunting for further stored "
        "credentials to escalate with",
    ),
    "ListBuckets": (
        "reconnaissance",
        "Enumerates the account's S3 buckets, hunting for accessible or "
        "exfiltratable data stores",
    ),
    "ListUsers": (
        "reconnaissance",
        "Enumerates the account's IAM users, mapping identities and escalation "
        "targets",
    ),
    "ListStacks": (
        "reconnaissance",
        "Enumerates CloudFormation stacks, hunting for infrastructure "
        "definitions and embedded parameters",
    ),
    "ListTopics": (
        "reconnaissance",
        "Enumerates SNS topics — messaging infrastructure that can be abused "
        "for spam or pivoting",
    ),
    "ListAccountAliases": (
        "reconnaissance",
        "Enumerates the account's IAM alias — cheap account fingerprinting",
    ),
    "DescribeInstances": (
        "reconnaissance",
        "Enumerates EC2 instances, mapping running compute to hijack or abuse",
    ),
    "PutUserPolicy": (
        "persistence",
        "Attaches an inline policy to an IAM user - privilege escalation, an "
        "attempt to grant itself durable permissions",
    ),
    "ListFunctions20150331": (
        "reconnaissance",
        "Enumerates the account's Lambda functions (the 20150331 API version "
        "of ListFunctions)",
    ),
    "ListFoundationModels": (
        "abuse-prep",
        "Enumerates which Bedrock foundation models the account can reach - "
        "precursor to LLMjacking",
    ),
    "ListInferenceProfiles": (
        "abuse-prep",
        "Enumerates Bedrock inference profiles - Bedrock recon that precedes "
        "LLMjacking",
    ),
    "GetSMSAttributes": (
        "abuse-prep",
        "Checks the SNS SMS sending settings - precursor to SMS spam/smishing "
        "from the account",
    ),
    "ListEmailIdentities": (
        "abuse-prep",
        "Enumerates SES verified email identities - precursor to phishing from "
        "the account",
    ),
    "GetAccountPasswordPolicy": (
        "reconnaissance",
        "Reads the account's IAM password policy - account-wide fingerprinting",
    ),
    "ListNotebookInstances": (
        "reconnaissance",
        "Enumerates SageMaker notebook instances - hunting for compute to hijack",
    ),
    "ListPolicies": (
        "reconnaissance",
        "Enumerates IAM policies to map permissions and escalation paths",
    ),
    "Converse": (
        "resource-abuse",
        "Attempts to run AI models on AWS Bedrock at the victim's expense "
        "(LLMjacking), via the Bedrock Converse chat API",
    ),
    "CreateUser": (
        "persistence",
        "Attempts to create a new IAM user to retain access even if the "
        "leaked key is revoked",
    ),
    "InvokeModel": (
        "resource-abuse",
        "Attempts to run AI models on AWS Bedrock at the victim's expense "
        "(LLMjacking)",
    ),
    "AttachUserPolicy": (
        "defense",
        "AWS's own automated quarantine attaching a restrictive policy to "
        "the leaked key",
    ),
    "SNS": (
        "defense",
        "AWS-side fraud/leak detection flagging the key",
    ),
    "AWSFRAUDGITHUBKEYCLUTCHPROD": (
        "defense",
        "AWS-side fraud/leak detection flagging the key",
    ),
}

_UNKNOWN = ("unknown", "No intent mapping defined for this event")


def classify_intent(event_name, source_ip=None):
    """Return ``(phase, description)`` for an ``event_name``.

    ``source_ip`` is accepted for the special ``AttachUserPolicy`` case,
    which is only classified as AWS's own defensive quarantine when the
    source is AWS-internal (which is the only way it appears in this data).
    """
    if event_name not in INTENT_TAXONOMY:
        return _UNKNOWN
    return INTENT_TAXONOMY[event_name]
