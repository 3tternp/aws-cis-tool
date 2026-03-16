from .base import CISCheck
import botocore.exceptions

class MetricFilterAlarmCheck(CISCheck):
    """
    Helper class to reduce code duplication for 3.1 - 3.14 checks
    """
    def __init__(self, auth_session, check_id, title, filter_pattern_keywords, description=""):
        super().__init__(
            auth_session, 
            check_id=check_id, 
            title=title, 
            category="Monitoring", 
            description=description or f"Ensure a log metric filter and alarm exist for {title}"
        )
        self.keywords = filter_pattern_keywords

    def execute(self):
        try:
            logs = self.auth.get_client('logs')
            cw = self.auth.get_client('cloudwatch')
            
            paginator = logs.get_paginator('describe_metric_filters')
            
            found_filter = False
            metric_name = None
            metric_namespace = None
            
            for page in paginator.paginate():
                for mf in page['metricFilters']:
                    pattern = mf.get('filterPattern', '')
                    # Check if all keywords are present in the pattern
                    if all(k in pattern for k in self.keywords):
                        found_filter = True
                        if mf['metricTransformations']:
                            metric_name = mf['metricTransformations'][0]['metricName']
                            metric_namespace = mf['metricTransformations'][0]['metricNamespace']
                        break
                if found_filter:
                    break
            
            if not found_filter:
                self.fail_check(f"No metric filter found matching pattern keywords: {self.keywords}")
                return

            # Now check for alarm
            alarms = cw.describe_alarms_for_metric(
                MetricName=metric_name,
                Namespace=metric_namespace
            )
            
            if alarms['MetricAlarms']:
                self.pass_check(f"Metric filter and alarm found for {self.title}.")
            else:
                self.fail_check(f"Metric filter found ({metric_name}) but NO alarm associated.")

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check monitoring: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_1(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.1", "Ensure a log metric filter and alarm exist for unauthorized API calls", ["UnauthorizedOperation", "AccessDenied"])

class Check_3_2(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.2", "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA", ["ConsoleLogin", "MFAUsed", "No"])

class Check_3_3(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.3", "Ensure a log metric filter and alarm exist for usage of 'root' account", ["Root", "ConsoleLogin"])

class Check_3_4(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.4", "Ensure a log metric filter and alarm exist for IAM policy changes", ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"])

class Check_3_5(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.5", "Ensure a log metric filter and alarm exist for CloudTrail configuration changes", ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"])

class Check_3_6(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.6", "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures", ["ConsoleLogin", "Failure", "LoginTo"])

class Check_3_7(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.7", "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs", ["DisableKey", "ScheduleKeyDeletion"])

class Check_3_8(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.8", "Ensure a log metric filter and alarm exist for S3 bucket policy changes", ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication"])

class Check_3_9(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.9", "Ensure a log metric filter and alarm exist for AWS Config configuration changes", ["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"])

class Check_3_10(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.10", "Ensure a log metric filter and alarm exist for security group changes", ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "CreateSecurityGroup", "DeleteSecurityGroup"])

class Check_3_11(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.11", "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)", ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"])

class Check_3_12(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.12", "Ensure a log metric filter and alarm exist for changes to network gateways", ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"])

class Check_3_13(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.13", "Ensure a log metric filter and alarm exist for route table changes", ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"])

class Check_3_14(MetricFilterAlarmCheck):
    def __init__(self, auth_session):
        super().__init__(auth_session, "3.14", "Ensure a log metric filter and alarm exist for VPC changes", ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection", "AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink", "EnableVpcClassicLink"])

def get_monitoring_checks(auth_session):
    return [
        Check_3_1(auth_session),
        Check_3_2(auth_session),
        Check_3_3(auth_session),
        Check_3_4(auth_session),
        Check_3_5(auth_session),
        Check_3_6(auth_session),
        Check_3_7(auth_session),
        Check_3_8(auth_session),
        Check_3_9(auth_session),
        Check_3_10(auth_session),
        Check_3_11(auth_session),
        Check_3_12(auth_session),
        Check_3_13(auth_session),
        Check_3_14(auth_session)
    ]
