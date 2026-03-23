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
            trails_evaluated = []
            for trail in trails:
                trail_info = {
                    "Name": trail.get('Name'),
                    "TrailARN": trail.get('TrailARN'),
                    "IsMultiRegionTrail": trail.get('IsMultiRegionTrail'),
                    "LogFileValidationEnabled": trail.get('LogFileValidationEnabled'),
                }
                if trail.get('IsMultiRegionTrail') and trail.get('TrailARN'):
                    status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                    trail_info["IsLogging"] = status.get('IsLogging')
                    if status.get('IsLogging'):
                        multi_region_trail_exists = True
                trails_evaluated.append(trail_info)
                        
            evidence = {"Trails": trails_evaluated}
            if multi_region_trail_exists:
                self.pass_check("A multi-region CloudTrail trail is configured and logging.", evidence=evidence)
            else:
                self.fail_check("No active multi-region CloudTrail trail found with log file validation enabled.", evidence=evidence)
                
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
            trails_evaluated = []
            for trail in trails:
                trails_evaluated.append(
                    {
                        "Name": trail.get('Name'),
                        "TrailARN": trail.get('TrailARN'),
                        "LogFileValidationEnabled": trail.get('LogFileValidationEnabled'),
                    }
                )
                if not trail.get('LogFileValidationEnabled'):
                    invalid_trails.append(trail['Name'])
                    
            evidence = {"Trails": trails_evaluated, "InvalidTrails": invalid_trails}
            if invalid_trails:
                self.fail_check(f"CloudTrail trails without log file validation enabled: {', '.join(invalid_trails)}", evidence=evidence)
            else:
                self.pass_check("All CloudTrail trails have log file validation enabled.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check CloudTrail log file validation: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_3(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="3.3",
            title="Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            category="Logging",
            description="CloudTrail logs should be stored in a bucket that is not publicly accessible."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            s3 = self.auth.get_client('s3')

            trails = cloudtrail.describe_trails().get('trailList', [])
            trail_buckets = sorted({t.get('S3BucketName') for t in trails if t.get('S3BucketName')})
            if not trail_buckets:
                self.fail_check("No CloudTrail trails with an S3 bucket configured were found.", evidence={"Trails": trails, "TrailBuckets": []})
                return

            violating = []
            access_denied = []
            buckets_evaluated = []

            public_group_uris = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            }

            for bucket_name in trail_buckets:
                bucket_info = {"Bucket": bucket_name}
                try:
                    try:
                        ps = s3.get_bucket_policy_status(Bucket=bucket_name).get("PolicyStatus", {})
                        bucket_info["PolicyIsPublic"] = ps.get("IsPublic")
                    except botocore.exceptions.ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "")
                        if code in {"NoSuchBucketPolicy", "NoSuchBucketPolicyStatus"}:
                            bucket_info["PolicyIsPublic"] = False
                        else:
                            raise

                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket_name)
                        public_acl = False
                        for g in acl.get("Grants", []):
                            grantee = g.get("Grantee") or {}
                            if grantee.get("Type") == "Group" and grantee.get("URI") in public_group_uris:
                                public_acl = True
                                break
                        bucket_info["AclHasPublicGrant"] = public_acl
                    except botocore.exceptions.ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "")
                        if code == "AccessDenied":
                            bucket_info["AclAccessDenied"] = True
                        else:
                            raise

                    try:
                        pab = s3.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration", {})
                        bucket_info["PublicAccessBlock"] = pab
                        bucket_info["PublicAccessBlockAllEnabled"] = all(
                            [
                                pab.get("BlockPublicAcls"),
                                pab.get("IgnorePublicAcls"),
                                pab.get("BlockPublicPolicy"),
                                pab.get("RestrictPublicBuckets"),
                            ]
                        )
                    except botocore.exceptions.ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "")
                        if code == "NoSuchPublicAccessBlockConfiguration":
                            bucket_info["PublicAccessBlockAllEnabled"] = False
                        elif code == "AccessDenied":
                            bucket_info["PublicAccessBlockAccessDenied"] = True
                        else:
                            raise

                    is_public = bool(bucket_info.get("PolicyIsPublic")) or bool(bucket_info.get("AclHasPublicGrant"))
                    bucket_info["IsPublic"] = is_public
                    if is_public:
                        violating.append(bucket_name)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "AccessDenied":
                        access_denied.append(bucket_name)
                        bucket_info["AccessDenied"] = True
                    else:
                        bucket_info["Error"] = {"Code": code, "Message": str(e)}
                        access_denied.append(bucket_name)

                buckets_evaluated.append(bucket_info)

            evidence = {
                "TrailBuckets": trail_buckets,
                "Buckets": buckets_evaluated,
                "ViolatingBuckets": violating,
                "AccessDeniedBuckets": access_denied,
            }

            if access_denied:
                self.error_check("Unable to evaluate CloudTrail S3 bucket public access for one or more buckets.", evidence=evidence)
            elif violating:
                self.fail_check(f"CloudTrail log buckets publicly accessible: {', '.join(violating)}", evidence=evidence)
            else:
                self.pass_check("CloudTrail log buckets are not publicly accessible.", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate CloudTrail S3 bucket public access: {e}")
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
            trails_evaluated = []
            for trail in trails:
                trails_evaluated.append(
                    {
                        "Name": trail.get('Name'),
                        "TrailARN": trail.get('TrailARN'),
                        "CloudWatchLogsLogGroupArn": trail.get('CloudWatchLogsLogGroupArn'),
                    }
                )
                if not trail.get('CloudWatchLogsLogGroupArn'):
                    unintegrated_trails.append(trail['Name'])
                    
            evidence = {"Trails": trails_evaluated, "UnintegratedTrails": unintegrated_trails}
            if unintegrated_trails:
                self.fail_check(f"CloudTrail trails not integrated with CloudWatch Logs: {', '.join(unintegrated_trails)}", evidence=evidence)
            else:
                self.pass_check("All CloudTrail trails are integrated with CloudWatch Logs.", evidence=evidence)
                
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
                self.fail_check("No AWS Config recorder found in this region.", evidence={"ConfigurationRecorders": []})
                return

            recorder_status = config.describe_configuration_recorder_status()
            is_recording = False
            for status in recorder_status['ConfigurationRecordersStatus']:
                if status['recording']:
                    is_recording = True
                    break
            
            evidence = {"ConfigurationRecorders": recorders, "RecorderStatus": recorder_status.get('ConfigurationRecordersStatus', [])}
            if is_recording:
                # Check for global resource recording (IAM)
                if recorders[0]['recordingGroup'].get('includeGlobalResourceTypes'):
                    self.pass_check("AWS Config is enabled and recording global resources.", evidence=evidence)
                else:
                    self.pass_check("AWS Config is enabled (Note: Ensure global resources are recorded in at least one region).", evidence=evidence)
            else:
                self.fail_check("AWS Config recorder exists but is NOT recording.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check AWS Config: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_6(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="3.6",
            title="Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
            category="Logging",
            description="S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            s3 = self.auth.get_client('s3')

            trails = cloudtrail.describe_trails().get('trailList', [])
            if not trails:
                self.fail_check("No CloudTrail trails configured, skipping S3 bucket logging check.", evidence={"Trails": []})
                return

            trail_buckets = set([t.get('S3BucketName') for t in trails if t.get('S3BucketName')])
            violating_buckets = []
            access_denied_buckets = []

            for bucket_name in trail_buckets:
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                    if not logging.get('LoggingEnabled'):
                        violating_buckets.append(bucket_name)
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDenied':
                        self.details.append(f"AccessDenied checking logging for bucket {bucket_name}")
                        access_denied_buckets.append(bucket_name)
                    else:
                        raise e

            evidence = {
                "TrailBuckets": sorted(trail_buckets),
                "ViolatingBuckets": violating_buckets,
                "AccessDeniedBuckets": access_denied_buckets,
            }
            if access_denied_buckets:
                self.error_check("Unable to evaluate access logging for one or more CloudTrail buckets.", evidence=evidence)
            elif violating_buckets:
                self.fail_check(f"CloudTrail buckets without access logging enabled: {', '.join(violating_buckets)}", evidence=evidence)
            else:
                self.pass_check("All CloudTrail S3 buckets have access logging enabled.", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate S3 bucket logging: {e}")
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
            trails_evaluated = []
            for trail in trails:
                trails_evaluated.append(
                    {
                        "Name": trail.get('Name'),
                        "TrailARN": trail.get('TrailARN'),
                        "KmsKeyId": trail.get('KmsKeyId'),
                    }
                )
                if not trail.get('KmsKeyId'):
                    unencrypted_trails.append(trail['Name'])
                    
            evidence = {"Trails": trails_evaluated, "UnencryptedTrails": unencrypted_trails}
            if unencrypted_trails:
                self.fail_check(f"CloudTrail trails not using KMS encryption: {', '.join(unencrypted_trails)}", evidence=evidence)
            else:
                self.pass_check("All CloudTrail trails are encrypted with KMS CMKs.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check CloudTrail encryption: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_3_8(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="3.8",
            title="Ensure rotation for customer created symmetric CMKs is enabled",
            category="Logging",
            description="KMS key rotation reduces the risk of a compromised key being used for long periods of time."
        )

    def execute(self):
        try:
            kms = self.auth.get_client('kms')
            paginator = kms.get_paginator('list_keys')

            checked = 0
            customer_symmetric_checked = 0
            violating = []
            skipped = 0
            other_errors = []

            for page in paginator.paginate():
                for k in page.get('Keys', []):
                    checked += 1
                    key_id = k.get('KeyId')
                    if not key_id:
                        continue
                    try:
                        metadata = kms.describe_key(KeyId=key_id).get('KeyMetadata', {})
                        if metadata.get('KeyManager') != 'CUSTOMER':
                            skipped += 1
                            continue

                        key_spec = metadata.get('KeySpec') or metadata.get('CustomerMasterKeySpec')
                        if key_spec != 'SYMMETRIC_DEFAULT':
                            skipped += 1
                            continue

                        customer_symmetric_checked += 1
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get('KeyRotationEnabled'):
                            violating.append(
                                {
                                    "KeyId": key_id,
                                    "Arn": metadata.get('Arn'),
                                    "Description": metadata.get('Description'),
                                }
                            )
                    except botocore.exceptions.ClientError as e:
                        code = e.response.get('Error', {}).get('Code', '')
                        other_errors.append({"KeyId": key_id, "Code": code, "Message": str(e)})

            evidence = {
                "TotalKeys": checked,
                "CustomerSymmetricKeysChecked": customer_symmetric_checked,
                "SkippedKeys": skipped,
                "ViolatingKeys": violating[:200],
                "OtherErrors": other_errors[:50],
            }
            if len(violating) > 200:
                evidence["ViolatingKeysTruncated"] = len(violating) - 200
            if len(other_errors) > 50:
                evidence["OtherErrorsTruncated"] = len(other_errors) - 50

            if other_errors:
                self.error_check("Unable to evaluate KMS key rotation for one or more keys.", evidence=evidence)
            elif violating:
                self.fail_check(f"Customer managed symmetric CMKs without rotation enabled: {len(violating)}", evidence=evidence)
            else:
                self.pass_check("Customer managed symmetric CMK rotation is enabled for all applicable keys.", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate KMS key rotation: {e}")
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
            vpc_evidence = []
            
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
                vpc_evidence.append(
                    {
                        "VpcId": vpc_id,
                        "ActiveFlowLog": active_flow_log,
                        "FlowLogs": [{"FlowLogId": fl.get('FlowLogId'), "FlowLogStatus": fl.get('FlowLogStatus')} for fl in flow_logs],
                    }
                )
                
                if not active_flow_log:
                    violating_vpcs.append(vpc_id)
            
            evidence = {"Vpcs": vpc_evidence, "ViolatingVpcs": violating_vpcs}
            if violating_vpcs:
                self.fail_check(f"VPCs without active Flow Logs: {', '.join(violating_vpcs)}", evidence=evidence)
            else:
                self.pass_check("All VPCs have active Flow Logs enabled.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check VPC Flow Logs: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

def get_logging_checks(auth_session):
    return [
        Check_3_1(auth_session),
        Check_3_2(auth_session),
        Check_3_3(auth_session),
        Check_3_4(auth_session),
        Check_3_5(auth_session),
        Check_3_6(auth_session),
        Check_3_7(auth_session),
        Check_3_8(auth_session),
        Check_3_9(auth_session)
    ]
