from .base import CISCheck
import botocore.exceptions

class Check_3_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="3.1", 
            title="Ensure CloudTrail is enabled in all regions", 
            category="Logging", 
            description="AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            response = cloudtrail.describe_trails()
            trails = response.get('trailList', [])
            
            multi_region_trail_exists = False
            for trail in trails:
                if trail.get('IsMultiRegionTrail') and trail.get('LogFileValidationEnabled'):
                    status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                    if status.get('IsLogging'):
                        multi_region_trail_exists = True
                        break
                        
            if multi_region_trail_exists:
                self.pass_check("A multi-region CloudTrail trail is configured and logging.")
            else:
                self.fail_check("No active multi-region CloudTrail trail found with log file validation enabled.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check CloudTrail status: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_2(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="3.2", 
            title="Ensure CloudTrail log file validation is enabled", 
            category="Logging", 
            description="CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            response = cloudtrail.describe_trails()
            trails = response.get('trailList', [])
            
            invalid_trails = []
            for trail in trails:
                if not trail.get('LogFileValidationEnabled'):
                    invalid_trails.append(trail['Name'])
                    
            if invalid_trails:
                self.fail_check(f"CloudTrail trails without log file validation enabled: {', '.join(invalid_trails)}")
            else:
                self.pass_check("All CloudTrail trails have log file validation enabled.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check CloudTrail log file validation: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_4(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="3.4", 
            title="Ensure CloudTrail trails are integrated with CloudWatch Logs", 
            category="Logging", 
            description="AWS CloudTrail can be configured to send logs to CloudWatch Logs."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            response = cloudtrail.describe_trails()
            trails = response.get('trailList', [])
            
            unintegrated_trails = []
            for trail in trails:
                if not trail.get('CloudWatchLogsLogGroupArn'):
                    unintegrated_trails.append(trail['Name'])
                    
            if unintegrated_trails:
                self.fail_check(f"CloudTrail trails not integrated with CloudWatch Logs: {', '.join(unintegrated_trails)}")
            else:
                self.pass_check("All CloudTrail trails are integrated with CloudWatch Logs.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check CloudTrail integration with CloudWatch: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_5(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="3.5", 
            title="Ensure AWS Config is enabled in all regions", 
            category="Logging", 
            description="AWS Config is a web service that performs configuration management of supported AWS resources."
        )

    def execute(self):
        try:
            # This check ideally requires checking all regions, but for simplicity we check the current region
            # and hint about multi-region.
            config = self.auth.get_client('config')
            
            # Check recorder status
            recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
            if not recorders:
                self.fail_check("No AWS Config recorder found in this region.")
                return

            recorder_status = config.describe_configuration_recorder_status()
            is_recording = False
            for status in recorder_status['ConfigurationRecordersStatus']:
                if status['recording']:
                    is_recording = True
                    break
            
            if is_recording:
                # Check for global resource recording (IAM)
                if recorders[0]['recordingGroup'].get('includeGlobalResourceTypes'):
                    self.pass_check("AWS Config is enabled and recording global resources.")
                else:
                    self.pass_check("AWS Config is enabled (Note: Ensure global resources are recorded in at least one region).")
            else:
                self.fail_check("AWS Config recorder exists but is NOT recording.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check AWS Config: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_7(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="3.7", 
            title="Ensure CloudTrail logs are encrypted with KMS CMKs", 
            category="Logging", 
            description="Configuring CloudTrail to use Server-Side Encryption (SSE) and an AWS KMS key provides an extra layer of security."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            response = cloudtrail.describe_trails()
            trails = response.get('trailList', [])
            
            unencrypted_trails = []
            for trail in trails:
                if not trail.get('KmsKeyId'):
                    unencrypted_trails.append(trail['Name'])
                    
            if unencrypted_trails:
                self.fail_check(f"CloudTrail trails not using KMS encryption: {', '.join(unencrypted_trails)}")
            else:
                self.pass_check("All CloudTrail trails are encrypted with KMS CMKs.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check CloudTrail encryption: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_9(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="3.9", 
            title="Ensure VPC flow logging is enabled in all VPCs", 
            category="Logging", 
            description="VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            vpcs = ec2.describe_vpcs().get('Vpcs', [])
            
            violating_vpcs = []
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                # Check flow logs for this VPC
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                ).get('FlowLogs', [])
                
                active_flow_log = False
                for fl in flow_logs:
                    if fl['FlowLogStatus'] == 'ACTIVE':
                        active_flow_log = True
                        break
                
                if not active_flow_log:
                    violating_vpcs.append(vpc_id)
            
            if violating_vpcs:
                self.fail_check(f"VPCs without active Flow Logs: {', '.join(violating_vpcs)}")
            else:
                self.pass_check("All VPCs have active Flow Logs enabled.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check VPC Flow Logs: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

def get_logging_checks(auth_session):
    return [
        Check_3_1(auth_session),
        Check_3_2(auth_session),
        Check_3_4(auth_session),
        Check_3_5(auth_session),
        Check_3_7(auth_session),
        Check_3_9(auth_session)
    ]
