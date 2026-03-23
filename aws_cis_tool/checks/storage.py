from .base import CISCheck
import botocore.exceptions
import json

class Check_2_1_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="2.1.1",
            title="Ensure all S3 buckets employ encryption-at-rest",
            category="Storage",
            description="S3 default encryption helps ensure objects are encrypted at rest when uploaded to a bucket."
        )

    def execute(self):
        try:
            s3 = self.auth.get_client('s3')
            buckets = s3.list_buckets().get('Buckets', [])

            missing = []
            denied = []
            other_errors = []

            for b in buckets:
                name = b.get('Name')
                if not name:
                    continue
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = ((enc.get('ServerSideEncryptionConfiguration') or {}).get('Rules') or [])
                    if not rules:
                        missing.append(name)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    if code == 'ServerSideEncryptionConfigurationNotFoundError':
                        missing.append(name)
                    elif code == 'AccessDenied':
                        denied.append(name)
                    else:
                        other_errors.append({"Bucket": name, "Code": code, "Message": str(e)})

            evidence = {
                "TotalBuckets": len(buckets),
                "BucketsWithoutDefaultEncryption": missing,
                "BucketsAccessDenied": denied,
                "OtherErrors": other_errors[:50],
            }
            if len(other_errors) > 50:
                evidence["OtherErrorsTruncated"] = len(other_errors) - 50

            if denied or other_errors:
                self.error_check("Unable to evaluate S3 bucket default encryption for one or more buckets.", evidence=evidence)
            elif missing:
                self.fail_check(f"Buckets without default encryption: {', '.join(missing)}", evidence=evidence)
            else:
                self.pass_check("All S3 buckets have default encryption enabled.", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check S3 bucket encryption: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_2_1_2(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="2.1.2", 
            title="Ensure S3 Bucket Policy is set to deny HTTP requests", 
            category="Storage", 
            description="S3 buckets should be configured to only allow access over HTTPS (TLS) via the aws:SecureTransport condition."
        )

    def execute(self):
        try:
            s3 = self.auth.get_client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            violating_buckets = []
            access_denied_buckets = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    policy_str = s3.get_bucket_policy(Bucket=bucket_name).get('Policy')
                    policy = json.loads(policy_str)
                    statements = policy.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                        
                    secure_transport_enforced = False
                    for stmt in statements:
                        if stmt.get('Effect') == 'Deny' and stmt.get('Action') == 's3:*':
                            condition = stmt.get('Condition', {})
                            bool_cond = condition.get('Bool', {})
                            if bool_cond.get('aws:SecureTransport') == 'false':
                                secure_transport_enforced = True
                                break
                                
                    if not secure_transport_enforced:
                        violating_buckets.append(bucket_name)
                        
                except botocore.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchBucketPolicy':
                        violating_buckets.append(bucket_name)
                    elif error_code == 'AccessDenied':
                        self.details.append(f"AccessDenied reading policy for bucket {bucket_name}")
                        access_denied_buckets.append(bucket_name)
                        violating_buckets.append(bucket_name)
                    else:
                        raise e
                        
            evidence = {
                "TotalBuckets": len(buckets),
                "ViolatingBuckets": violating_buckets,
                "AccessDeniedBuckets": access_denied_buckets,
            }
            if violating_buckets:
                self.fail_check(f"Buckets without SecureTransport enforced: {', '.join(violating_buckets)}", evidence=evidence)
            else:
                self.pass_check("All buckets enforce SecureTransport via bucket policies.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate S3 bucket policies: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_2_1_3(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="2.1.3",
            title="Ensure MFA Delete is enabled on S3 buckets",
            category="Storage", 
            description="MFA Delete provides an additional layer of security by requiring MFA to permanently delete objects or suspend versioning."
        )

    def execute(self):
        try:
            s3 = self.auth.get_client('s3')

            buckets = s3.list_buckets().get('Buckets', [])
            violating_buckets = []
            access_denied_buckets = []
            other_errors = []

            for b in buckets:
                bucket_name = b.get('Name')
                if not bucket_name:
                    continue
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    mfa_delete = versioning.get('MFADelete')
                    if mfa_delete != 'Enabled':
                        violating_buckets.append(bucket_name)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    if code == 'AccessDenied':
                        self.details.append(f"AccessDenied checking MFA Delete for bucket {bucket_name}")
                        access_denied_buckets.append(bucket_name)
                    else:
                        other_errors.append({"Bucket": bucket_name, "Code": code, "Message": str(e)})

            evidence = {
                "TotalBuckets": len(buckets),
                "ViolatingBuckets": violating_buckets,
                "AccessDeniedBuckets": access_denied_buckets,
                "OtherErrors": other_errors[:50],
            }
            if len(other_errors) > 50:
                evidence["OtherErrorsTruncated"] = len(other_errors) - 50

            if access_denied_buckets or other_errors:
                self.error_check("Unable to evaluate MFA Delete for one or more buckets.", evidence=evidence)
            elif violating_buckets:
                self.fail_check(f"Buckets without MFA Delete enabled: {', '.join(violating_buckets)}", evidence=evidence)
            else:
                self.pass_check("All buckets have MFA Delete enabled.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate S3 bucket MFA Delete: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_2_1_5(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="2.1.5", 
            title="Ensure that S3 buckets are configured with 'Block public access (bucket settings)'", 
            category="Storage", 
            description="S3 Block Public Access provides settings for access points, buckets, and accounts to help you manage public access to Amazon S3 resources."
        )

    def execute(self):
        try:
            s3 = self.auth.get_client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            violating_buckets = []
            access_denied_buckets = []
            other_errors = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    # Check bucket-level Block Public Access
                    response = s3.get_public_access_block(Bucket=bucket_name)
                    conf = response.get('PublicAccessBlockConfiguration', {})
                    
                    if not (conf.get('BlockPublicAcls') and 
                            conf.get('IgnorePublicAcls') and 
                            conf.get('BlockPublicPolicy') and 
                            conf.get('RestrictPublicBuckets')):
                        violating_buckets.append(bucket_name)
                        
                except botocore.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchPublicAccessBlockConfiguration':
                        violating_buckets.append(bucket_name)
                    else:
                        # Could be access denied or other error
                        self.details.append(f"Error checking {bucket_name}: {error_code}")
                        if error_code == 'AccessDenied':
                            access_denied_buckets.append(bucket_name)
                        else:
                            other_errors.append({"Bucket": bucket_name, "Code": error_code})
            
            evidence = {
                "TotalBuckets": len(buckets),
                "ViolatingBuckets": violating_buckets,
                "AccessDeniedBuckets": access_denied_buckets,
                "OtherErrors": other_errors[:50],
            }
            if len(other_errors) > 50:
                evidence["OtherErrorsTruncated"] = len(other_errors) - 50

            if violating_buckets:
                self.fail_check(f"Buckets without Block Public Access enabled: {', '.join(violating_buckets)}", evidence=evidence)
            else:
                self.pass_check("All buckets have Block Public Access enabled.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check S3 Block Public Access: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

def get_storage_checks(auth_session):
    return [
        Check_2_1_1(auth_session),
        Check_2_1_2(auth_session),
        Check_2_1_3(auth_session),
        Check_2_1_5(auth_session)
    ]
