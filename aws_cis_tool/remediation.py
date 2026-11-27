"""Severity ratings and remediation guidance for each CIS check."""

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_PA = ("BlockPublicAcls=true,IgnorePublicAcls=true,"
       "BlockPublicPolicy=true,RestrictPublicBuckets=true")


def _metric_filter(num, name, pattern):
    return (
        f"aws logs put-metric-filter --log-group-name <cloudtrail-log-group> \\\n"
        f"  --filter-name {name} \\\n"
        f"  --metric-transformations metricName={name},metricNamespace=CISBenchmark,metricValue=1 \\\n"
        f"  --filter-pattern '{pattern}'\n\n"
        f"aws cloudwatch put-metric-alarm --alarm-name {name} \\\n"
        f"  --metric-name {name} --namespace CISBenchmark --statistic Sum --period 300 \\\n"
        f"  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \\\n"
        f"  --evaluation-periods 1 --alarm-actions <sns-topic-arn>"
    )


def _monitor(num, name, sev, what, pattern):
    return num, {
        "severity": sev,
        "recommendation": (f"Create a CloudWatch Logs metric filter and alarm on the CloudTrail log group "
                           f"that detects {what}, and notify the security team through SNS. "
                           "Without it these events can go unnoticed."),
        "command": _metric_filter(num, name, pattern),
    }


_IAM_PW = ("aws iam update-account-password-policy --minimum-password-length 14 \\\n"
           "  --require-symbols --require-numbers --require-uppercase-characters \\\n"
           "  --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24")

REMEDIATION = dict([
    ("1.1", {"severity": "CRITICAL",
             "recommendation": "Delete every access key belonging to the root user and use IAM roles / least-privilege users for programmatic access. Root keys give unrestricted access to the whole account.",
             "command": "# Console only: sign in as root > Security credentials > Access keys > Delete\n# Verify afterwards:\naws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'"}),
    ("1.4", {"severity": "CRITICAL",
             "recommendation": "Enable MFA on the root user, preferably a hardware or FIDO2 key, and store the device securely. A stolen root password without MFA means full account takeover.",
             "command": "# Console only: sign in as root > Security credentials > Assign MFA device\n# Verify afterwards:\naws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'"}),
    ("1.5", {"severity": "HIGH",
             "recommendation": "Enable MFA for every IAM user with a console password, and enforce it with an IAM policy that denies actions unless aws:MultiFactorAuthPresent is true.",
             "command": "aws iam create-virtual-mfa-device --virtual-mfa-device-name <user> \\\n  --outfile qr.png --bootstrap-method QRCodePNG\n\naws iam enable-mfa-device --user-name <user> --serial-number <mfa-device-arn> \\\n  --authentication-code1 <code1> --authentication-code2 <code2>"}),
    ("1.8", {"severity": "MEDIUM",
             "recommendation": "Set an account password policy requiring at least 14 characters (plus complexity and rotation). This command sets the full policy, since the API replaces it as a whole.",
             "command": _IAM_PW}),
    ("1.9", {"severity": "MEDIUM",
             "recommendation": "Prevent reuse of the last 24 passwords. The API replaces the whole policy, so keep the other settings in the same call.",
             "command": _IAM_PW}),
    ("1.12", {"severity": "MEDIUM",
              "recommendation": "Disable or delete credentials that have not been used for 90 days. Unused keys and passwords are an unmonitored attack path.",
              "command": "aws iam update-access-key --user-name <user> --access-key-id <key-id> --status Inactive\naws iam delete-login-profile --user-name <user>   # if the console password is unused"}),
    ("1.13", {"severity": "MEDIUM",
              "recommendation": "Rotate access keys at least every 90 days: create a second key, move workloads to it, deactivate and then delete the old key. Prefer IAM roles or SSO so long-lived keys are not needed.",
              "command": "aws iam create-access-key --user-name <user>\naws iam update-access-key --user-name <user> --access-key-id <old-key-id> --status Inactive\naws iam delete-access-key --user-name <user> --access-key-id <old-key-id>"}),
    ("1.15", {"severity": "MEDIUM",
              "recommendation": "Manual: confirm EC2 workloads use IAM instance profiles instead of embedded access keys, and attach a role where missing.",
              "command": "aws ec2 describe-instances --query 'Reservations[].Instances[?!IamInstanceProfile].InstanceId'\naws ec2 associate-iam-instance-profile --instance-id <instance-id> \\\n  --iam-instance-profile Name=<profile-name>"}),
    ("1.16", {"severity": "MEDIUM",
              "recommendation": "Attach policies to groups or roles, never directly to users. Create a group, attach the policy to it, add the user, then detach the direct attachment.",
              "command": "aws iam create-group --group-name <group>\naws iam attach-group-policy --group-name <group> --policy-arn <policy-arn>\naws iam add-user-to-group --group-name <group> --user-name <user>\naws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>"}),
    ("1.17", {"severity": "LOW",
              "recommendation": "Manual: create a dedicated IAM role with the AWSSupportAccess managed policy so incidents can be raised with AWS Support without using admin credentials.",
              "command": "aws iam create-role --role-name AWSSupportAccess --assume-role-policy-document file://trust.json\naws iam attach-role-policy --role-name AWSSupportAccess \\\n  --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess"}),
    ("1.22", {"severity": "CRITICAL",
              "recommendation": "Remove policies that grant Action:* on Resource:* and replace them with least-privilege permissions. Review who has the policy attached first.",
              "command": "aws iam list-entities-for-policy --policy-arn <policy-arn>\naws iam detach-user-policy  --user-name <user>  --policy-arn <policy-arn>\naws iam detach-role-policy  --role-name <role>  --policy-arn <policy-arn>\naws iam detach-group-policy --group-name <group> --policy-arn <policy-arn>"}),
    ("2.1.1", {"severity": "MEDIUM",
               "recommendation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) on every bucket so data is encrypted at rest.",
               "command": "aws s3api put-bucket-encryption --bucket <bucket> \\\n  --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"}),
    ("2.1.2", {"severity": "MEDIUM",
               "recommendation": "Add a bucket policy statement that denies all requests where aws:SecureTransport is false, so data is only transferred over HTTPS.",
               "command": "aws s3api put-bucket-policy --bucket <bucket> --policy '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyHTTP\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::<bucket>\",\"arn:aws:s3:::<bucket>/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}'"}),
    ("2.1.3", {"severity": "LOW",
               "recommendation": "Enable MFA Delete on versioned buckets that hold critical data so objects cannot be permanently deleted without MFA. Must be run with root credentials.",
               "command": "aws s3api put-bucket-versioning --bucket <bucket> \\\n  --versioning-configuration Status=Enabled,MFADelete=Enabled \\\n  --mfa \"arn:aws:iam::<account-id>:mfa/root-account-mfa-device <mfa-code>\""}),
    ("2.1.5", {"severity": "HIGH",
               "recommendation": "Turn on all four Block Public Access settings for each bucket (unless it is intentionally public) to prevent accidental data exposure.",
               "command": f"aws s3api put-public-access-block --bucket <bucket> \\\n  --public-access-block-configuration {_PA}"}),
    ("3.1", {"severity": "HIGH",
             "recommendation": "Create a multi-region CloudTrail trail that records management events and start logging. Without it there is no audit trail of API activity.",
             "command": "aws cloudtrail create-trail --name <trail> --s3-bucket-name <log-bucket> \\\n  --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name <trail>"}),
    ("3.2", {"severity": "MEDIUM",
             "recommendation": "Enable log file validation so tampering with CloudTrail logs can be detected.",
             "command": "aws cloudtrail update-trail --name <trail> --enable-log-file-validation"}),
    ("3.3", {"severity": "CRITICAL",
             "recommendation": "Remove public access from the CloudTrail log bucket: block public access and remove any ACL or bucket policy granting access to everyone.",
             "command": f"aws s3api put-public-access-block --bucket <cloudtrail-bucket> \\\n  --public-access-block-configuration {_PA}\naws s3api get-bucket-policy --bucket <cloudtrail-bucket>   # review and remove public statements"}),
    ("3.4", {"severity": "MEDIUM",
             "recommendation": "Send CloudTrail events to a CloudWatch Logs group to allow real-time alarms and searches.",
             "command": "aws cloudtrail update-trail --name <trail> \\\n  --cloud-watch-logs-log-group-arn <log-group-arn> \\\n  --cloud-watch-logs-role-arn <role-arn>"}),
    ("3.5", {"severity": "MEDIUM",
             "recommendation": "Enable AWS Config recording of all resources (including global resources) in every region to keep a configuration history.",
             "command": "aws configservice put-configuration-recorder \\\n  --configuration-recorder name=default,roleARN=<role-arn> \\\n  --recording-group allSupported=true,includeGlobalResourceTypes=true\naws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=<bucket>\naws configservice start-configuration-recorder --configuration-recorder-name default"}),
    ("3.6", {"severity": "LOW",
             "recommendation": "Enable server access logging on the CloudTrail bucket to record who accesses the audit logs.",
             "command": "aws s3api put-bucket-logging --bucket <cloudtrail-bucket> --bucket-logging-status \\\n  '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-target-bucket>\",\"TargetPrefix\":\"cloudtrail-access/\"}}'"}),
    ("3.7", {"severity": "MEDIUM",
             "recommendation": "Encrypt CloudTrail logs with a customer managed KMS key for stronger access control over the audit data.",
             "command": "aws cloudtrail update-trail --name <trail> --kms-key-id <kms-key-arn>"}),
    ("3.8", {"severity": "MEDIUM",
             "recommendation": "Enable automatic annual rotation for each customer-managed symmetric KMS key.",
             "command": "aws kms enable-key-rotation --key-id <key-id>"}),
    ("3.9", {"severity": "MEDIUM",
             "recommendation": "Enable VPC Flow Logs (ALL traffic) on every VPC to capture network activity for investigations.",
             "command": "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL \\\n  --log-destination-type cloud-watch-logs --log-group-name <log-group> \\\n  --deliver-logs-permission-arn <role-arn>"}),
    _monitor("4.1", "UnauthorizedApiCalls", "MEDIUM", "unauthorized API calls",
             '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'),
    _monitor("4.2", "ConsoleSignInWithoutMfa", "MEDIUM", "console sign-ins without MFA",
             '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }'),
    _monitor("4.3", "RootAccountUsage", "HIGH", "use of the root account",
             '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'),
    _monitor("4.4", "IamPolicyChanges", "MEDIUM", "IAM policy changes",
             '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}'),
    _monitor("4.5", "CloudTrailConfigChanges", "MEDIUM", "CloudTrail configuration changes",
             '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'),
    _monitor("4.6", "ConsoleAuthFailures", "LOW", "failed console authentication attempts",
             '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'),
    _monitor("4.7", "CmkDisableOrDeletion", "MEDIUM", "disabling or scheduled deletion of customer managed KMS keys",
             '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }'),
    _monitor("4.8", "S3BucketPolicyChanges", "MEDIUM", "S3 bucket policy changes",
             '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'),
    _monitor("4.9", "AwsConfigChanges", "LOW", "AWS Config configuration changes",
             '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }'),
    _monitor("4.10", "SecurityGroupChanges", "MEDIUM", "security group changes",
             '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'),
    _monitor("4.11", "NaclChanges", "LOW", "network ACL changes",
             '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'),
    _monitor("4.12", "NetworkGatewayChanges", "LOW", "network gateway changes",
             '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'),
    _monitor("4.13", "RouteTableChanges", "LOW", "route table changes",
             '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'),
    _monitor("4.14", "VpcChanges", "LOW", "VPC changes",
             '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'),
    ("5.1", {"severity": "CRITICAL",
             "recommendation": "Remove security group rules that allow SSH (22) from 0.0.0.0/0. Restrict to known admin IPs/VPN or use SSM Session Manager and remove inbound SSH entirely.",
             "command": "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0"}),
    ("5.2", {"severity": "CRITICAL",
             "recommendation": "Remove security group rules that allow RDP (3389) from 0.0.0.0/0. Restrict to known admin IPs/VPN or use SSM Session Manager / Fleet Manager.",
             "command": "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0"}),
    ("5.3", {"severity": "HIGH",
             "recommendation": "Delete Network ACL ingress entries that allow 0.0.0.0/0 to administrative ports (22, 3389) and allow only trusted ranges.",
             "command": "aws ec2 delete-network-acl-entry --network-acl-id <acl-id> --rule-number <rule-number> --ingress"}),
    ("5.4", {"severity": "MEDIUM",
             "recommendation": "Remove all inbound and outbound rules from each VPC's default security group and use purpose-built groups instead.",
             "command": "aws ec2 revoke-security-group-ingress --group-id <default-sg-id> \\\n  --ip-permissions \"$(aws ec2 describe-security-groups --group-ids <default-sg-id> --query 'SecurityGroups[0].IpPermissions')\"\naws ec2 revoke-security-group-egress --group-id <default-sg-id> \\\n  --ip-permissions \"$(aws ec2 describe-security-groups --group-ids <default-sg-id> --query 'SecurityGroups[0].IpPermissionsEgress')\""}),
    ("5.5", {"severity": "LOW",
             "recommendation": "Manual: review VPC peering route tables and make sure routes only point to the specific CIDRs that are needed (least access).",
             "command": "aws ec2 describe-route-tables --query 'RouteTables[].Routes[?VpcPeeringConnectionId]'"}),
    ("6.1", {"severity": "HIGH",
             "recommendation": "Enable GuardDuty for continuous threat detection (malicious IPs, credential compromise, crypto-mining).",
             "command": "aws guardduty create-detector --enable"}),
    ("6.2", {"severity": "MEDIUM",
             "recommendation": "Enable AWS Security Hub to aggregate and prioritise security findings.",
             "command": "aws securityhub enable-security-hub --enable-default-standards"}),
    ("6.3", {"severity": "MEDIUM",
             "recommendation": "Enable GuardDuty in every enabled region, since attackers often use unused regions.",
             "command": "for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do\n  aws guardduty create-detector --enable --region $r\ndone"}),
    ("6.4", {"severity": "MEDIUM",
             "recommendation": "Enable Security Hub in every enabled region.",
             "command": "for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do\n  aws securityhub enable-security-hub --enable-default-standards --region $r\ndone"}),
    ("6.5", {"severity": "LOW",
             "recommendation": "Subscribe Security Hub to the CIS AWS Foundations Benchmark standard for continuous compliance checks.",
             "command": "aws securityhub batch-enable-standards --standards-subscription-requests \\\n  StandardsArn=arn:aws:securityhub:<region>::standards/cis-aws-foundations-benchmark/v/1.4.0"}),
    ("6.6", {"severity": "MEDIUM",
             "recommendation": "Enable EBS encryption by default in every region so new volumes and snapshot copies are always encrypted.",
             "command": "aws ec2 enable-ebs-encryption-by-default --region <region>"}),
    ("6.7", {"severity": "HIGH",
             "recommendation": "Enable account-level S3 Block Public Access so no bucket in the account can be made public by mistake.",
             "command": f"aws s3control put-public-access-block --account-id <account-id> \\\n  --public-access-block-configuration {_PA}"}),
    ("6.8", {"severity": "MEDIUM",
             "recommendation": "Require IMDSv2 on all EC2 instances to mitigate SSRF-based credential theft from the metadata service.",
             "command": "aws ec2 modify-instance-metadata-options --instance-id <instance-id> \\\n  --http-tokens required --http-endpoint enabled"}),
    ("6.9", {"severity": "MEDIUM",
             "recommendation": "Replace unencrypted EBS volumes with encrypted ones: snapshot, copy the snapshot with encryption, create a new volume and swap it in.",
             "command": "aws ec2 create-snapshot --volume-id <volume-id>\naws ec2 copy-snapshot --source-region <region> --source-snapshot-id <snap-id> --encrypted --kms-key-id <key>\naws ec2 create-volume --snapshot-id <new-snap-id> --availability-zone <az> --encrypted"}),
])

DEFAULT = {"severity": "MEDIUM",
           "recommendation": "Review this finding against the CIS AWS Foundations Benchmark and remediate it.",
           "command": ""}


def severity_rank(sev):
    return _RANK.get(sev, len(_RANK))


def enrich(result):
    """Add severity / recommendation / command to a result dict (idempotent)."""
    info = REMEDIATION.get(str(result.get("check_id")), DEFAULT)
    result.setdefault("severity", info["severity"])
    result.setdefault("recommendation", info["recommendation"])
    result.setdefault("command", info["command"])
    return result
