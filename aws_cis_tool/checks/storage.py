from .base import CISCheck
import botocore.exceptions
import json

class Check_2_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="2.1", 
            title="Ensure S3 Bucket Policy is set to deny HTTP requests", 
            category="Storage", 
            description="S3 buckets should be configured to only allow access over HTTPS (TLS) via the aws:SecureTransport condition."
        )

    def execute(self):
        try:
            s3 = self.auth.get_client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            violating_buckets = []
            
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
                        violating_buckets.append(bucket_name)
                    else:
                        raise e
                        
            if violating_buckets:
                self.fail_check(f"Buckets without SecureTransport enforced: {', '.join(violating_buckets)}")
            else:
                self.pass_check("All buckets enforce SecureTransport via bucket policies.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate S3 bucket policies: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_2_2(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="2.2", 
            title="Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket", 
            category="Storage", 
            description="S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket."
        )

    def execute(self):
        try:
            cloudtrail = self.auth.get_client('cloudtrail')
            s3 = self.auth.get_client('s3')
            
            trails = cloudtrail.describe_trails().get('trailList', [])
            if not trails:
                self.fail_check("No CloudTrail trails configured, skipping S3 bucket logging check.")
                return
                
            trail_buckets = set([t.get('S3BucketName') for t in trails if t.get('S3BucketName')])
            violating_buckets = []
            
            for bucket_name in trail_buckets:
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                    if not logging.get('LoggingEnabled'):
                        violating_buckets.append(bucket_name)
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDenied':
                        self.details.append(f"AccessDenied checking logging for bucket {bucket_name}")
                    else:
                        raise e
                        
            if violating_buckets:
                self.fail_check(f"CloudTrail buckets without access logging enabled: {', '.join(violating_buckets)}")
            else:
                self.pass_check("All CloudTrail S3 buckets have access logging enabled.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to evaluate S3 bucket logging: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_2_3(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="2.3", 
            title="Ensure that the S3 Block Public Access setting is enabled", 
            category="Storage", 
            description="S3 Block Public Access provides settings for access points, buckets, and accounts to help you manage public access to Amazon S3 resources."
        )

    def execute(self):
        try:
            s3 = self.auth.get_client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            violating_buckets = []
            
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
            
            if violating_buckets:
                self.fail_check(f"Buckets without Block Public Access enabled: {', '.join(violating_buckets)}")
            else:
                self.pass_check("All buckets have Block Public Access enabled.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check S3 Block Public Access: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

def get_storage_checks(auth_session):
    return [
        Check_2_1(auth_session),
        Check_2_2(auth_session),
        Check_2_3(auth_session)
    ]
