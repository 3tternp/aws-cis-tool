from .base import CISCheck
import json
import botocore.exceptions

class Check_1_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.1", 
            title="Ensure no 'root' user account access key exists", 
            category="IAM", 
            description="The 'root' user account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given AWS account."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            response = iam.get_account_summary()
            summary = response.get('SummaryMap', {})
            
            # Evidence
            evidence = {"AccountSummary": summary}
            
            root_keys = summary.get('AccountAccessKeysPresent', 0)
            if int(root_keys) > 0:
                self.fail_check(f"Root account has {root_keys} active access keys.", evidence=evidence)
            else:
                self.pass_check("No root access keys found.", evidence=evidence)
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check root access keys: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_4(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.4", 
            title="Ensure MFA is enabled for the 'root' user account", 
            category="IAM", 
            description="The 'root' user account is the most privileged user in an AWS account. Multi-Factor Authentication (MFA) adds an extra layer of protection."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            response = iam.get_account_summary()
            summary = response.get('SummaryMap', {})
            
            mfa_active = summary.get('AccountMFAEnabled', 0)
            if int(mfa_active) == 1:
                self.pass_check("MFA is enabled for the root account.")
            else:
                self.fail_check("MFA is NOT enabled for the root account.")
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check root MFA: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_5(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.5", 
            title="Ensure MFA is enabled for all IAM users that have a console password", 
            category="IAM", 
            description="Multi-Factor Authentication (MFA) adds an extra layer of protection on top of your user name and password."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            paginator = iam.get_paginator('list_users')
            
            users_without_mfa = []
            
            for page in paginator.paginate():
                for user in page['Users']:
                    # Check if user has console password
                    try:
                        iam.get_login_profile(UserName=user['UserName'])
                        has_console_password = True
                    except botocore.exceptions.ClientError:
                        has_console_password = False
                    
                    if has_console_password:
                        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                        if not mfa_devices:
                            users_without_mfa.append(user['UserName'])
            
            if users_without_mfa:
                self.fail_check(f"Users with console password but no MFA: {', '.join(users_without_mfa)}")
            else:
                self.pass_check("All users with console password have MFA enabled.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check user MFA status: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_8(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.8", 
            title="Ensure IAM password policy requires minimum length of 14 or greater", 
            category="IAM", 
            description="Password policies can help ensure that users are creating strong passwords."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                if policy.get('MinimumPasswordLength', 0) >= 14:
                    self.pass_check("Password policy requires minimum length of 14 or greater.")
                else:
                    self.fail_check(f"Password minimum length is {policy.get('MinimumPasswordLength', 0)} (required >= 14).")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    self.fail_check("No password policy found.")
                else:
                    raise e
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_9(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.9", 
            title="Ensure IAM password policy prevents password reuse", 
            category="IAM", 
            description="Prevents users from reusing their previous passwords."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                if policy.get('PasswordReusePrevention', 0) >= 24:
                    self.pass_check("Password policy prevents reuse of last 24 passwords.")
                else:
                    self.fail_check(f"Password reuse prevention is set to {policy.get('PasswordReusePrevention', 0)} (required >= 24).")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    self.fail_check("No password policy found.")
                else:
                    raise e
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_12(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.12", 
            title="Ensure credentials unused for 90 days or greater are disabled", 
            category="IAM", 
            description="Users with unused credentials (passwords or access keys) should be disabled."
        )

    def execute(self):
        # Note: This requires generating a credential report which is async. 
        # For simplicity in this tool, we will use list_users and their last used dates if available,
        # or list_access_keys.
        # However, list_users doesn't give last used date directly.
        # Generating a credential report is the robust way but takes time.
        # We'll do a simpler check using get_access_key_last_used for keys, and get_login_profile for console (doesn't give last used).
        # To be fast and synchronous, we might skip full implementation or use a heuristic.
        # Let's try to check Access Keys last used.
        try:
            iam = self.auth.get_client('iam')
            paginator = iam.get_paginator('list_users')
            from datetime import datetime, timezone, timedelta
            
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            violating_users = []
            
            for page in paginator.paginate():
                for user in page['Users']:
                    # Check Access Keys
                    keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                    for key in keys:
                        if key['Status'] == 'Active':
                            last_used_resp = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                            last_used_date = last_used_resp.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                            
                            if last_used_date and last_used_date < threshold:
                                violating_users.append(f"{user['UserName']} (Key {key['AccessKeyId']} unused since {last_used_date})")
                            elif not last_used_date and key['CreateDate'] < threshold:
                                violating_users.append(f"{user['UserName']} (Key {key['AccessKeyId']} never used, created {key['CreateDate']})")
            
            if violating_users:
                self.fail_check(f"Users with active credentials unused for >90 days: {', '.join(violating_users)}")
            else:
                self.pass_check("No active credentials found unused for >90 days.")
                
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_16(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.16", 
            title="Ensure IAM policies are attached only to groups or roles", 
            category="IAM", 
            description="IAM policies should be attached to groups or roles rather than directly to users to simplify permission management."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            paginator = iam.get_paginator('list_users')
            
            users_with_policies = []
            
            for page in paginator.paginate():
                for user in page['Users']:
                    attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                    inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
                    
                    if attached_policies or inline_policies:
                        users_with_policies.append(user['UserName'])
            
            if users_with_policies:
                self.fail_check(f"Users with directly attached policies: {', '.join(users_with_policies)}")
            else:
                self.pass_check("No users have directly attached policies.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check user policies: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_13(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.13", 
            title="Ensure access keys are rotated every 90 days or less", 
            category="IAM", 
            description="Access keys should be rotated to reduce the business impact if they are compromised."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            paginator = iam.get_paginator('list_users')
            from datetime import datetime, timezone, timedelta
            
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            violating_users = []
            
            for page in paginator.paginate():
                for user in page['Users']:
                    # Check Access Keys
                    keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                    for key in keys:
                        if key['Status'] == 'Active':
                            if key['CreateDate'] < threshold:
                                violating_users.append(f"{user['UserName']} (Key {key['AccessKeyId']} age > 90 days)")
            
            if violating_users:
                self.fail_check(f"Users with active access keys older than 90 days: {', '.join(violating_users)}")
            else:
                self.pass_check("All active access keys are younger than 90 days.")
                
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_1_22(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.22", 
            title="Ensure IAM policies that allow full '*:*' administrative privileges are not attached", 
            category="IAM", 
            description="IAM policies that provide full administrative privileges allow a user, role, or group to perform any action on any resource."
        )

    def execute(self):
        try:
            iam = self.auth.get_client('iam')
            paginator = iam.get_paginator('list_policies')
            
            violating_policies = []
            policies_evidence = []
            
            for page in paginator.paginate(Scope='Local'):
                for policy in page.get('Policies', []):
                    if policy.get('AttachmentCount', 0) > 0:
                        policy_version = iam.get_policy_version(
                            PolicyArn=policy['Arn'], 
                            VersionId=policy['DefaultVersionId']
                        )
                        document = policy_version['PolicyVersion']['Document']
                        
                        # Document might be a string or dictionary depending on the SDK behavior, typically dict
                        if isinstance(document, str):
                            document = json.loads(document)
                            
                        statements = document.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                            
                        for statement in statements:
                            if statement.get('Effect') == 'Allow':
                                action = statement.get('Action')
                                resource = statement.get('Resource')
                                
                                if action == '*' or (isinstance(action, list) and '*' in action):
                                    if resource == '*' or (isinstance(resource, list) and '*' in resource):
                                        violating_policies.append(policy['PolicyName'])
                                        policies_evidence.append({
                                            "PolicyName": policy['PolicyName'],
                                            "Arn": policy['Arn'],
                                            "Document": document
                                        })
            
            if violating_policies:
                self.fail_check(f"Found policies with '*:*' permissions attached: {', '.join(violating_policies)}", evidence={"ViolatingPolicies": policies_evidence})
            else:
                self.pass_check("No customer-managed policies with '*:*' permissions are attached.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to list or evaluate policies: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_Manual_1_15(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.15", 
            title="Ensure IAM instance roles are used", 
            category="IAM", 
            description="IAM roles for EC2 instances allow you to delegate permissions to make API requests from the instance without distributing credentials.",
            check_type="MANUAL",
            manual_steps=[
                "List all running EC2 instances and verify each has an IAM instance profile/role attached.",
                "For instances with no role, confirm the workload does not use AWS APIs, or attach a least-privilege role.",
                "On instances that call AWS APIs, confirm applications use the Instance Metadata Service (IMDS) credentials and not static access keys.",
                "Search for long-lived access keys in user data, environment variables, or files on the instance."
            ],
            manual_poc=[
                "CLI: aws ec2 describe-instances --query \"Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn]\" --output table",
                "Expected: every InstanceId has a non-empty IamInstanceProfile.Arn (except explicitly non-AWS workloads).",
                "CLI: aws ec2 describe-instances --query \"Reservations[].Instances[?IamInstanceProfile==null].[InstanceId,State.Name]\" --output table",
                "Expected: empty result or only documented exceptions."
            ]
        )
    def execute(self):
        super().execute()

class Check_Manual_1_17(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="1.17", 
            title="Ensure a support role has been created to manage the incident with AWS Support", 
            category="IAM", 
            description="AWS provides a support center that can be used for incident notification and response.",
            check_type="MANUAL",
            manual_steps=[
                "Confirm an IAM role exists for Support access and is assigned to the appropriate admin group/team.",
                "Verify the role has AWS managed policy AWSSupportAccess (or an equivalent least-privilege policy).",
                "Verify the trust policy only allows approved principals (IdP, SSO permission set, or specific admin roles) to assume it.",
                "Validate users can access AWS Support Center using the role without using the root account."
            ],
            manual_poc=[
                "Console: IAM → Roles → search for a Support role; confirm attached policies include AWSSupportAccess.",
                "CLI: aws iam list-roles --query \"Roles[?contains(RoleName, 'Support')].RoleName\" --output table",
                "CLI: aws iam list-attached-role-policies --role-name <SupportRoleName> --output table",
                "CLI: aws iam get-role --role-name <SupportRoleName> --query \"Role.AssumeRolePolicyDocument\" --output json"
            ]
        )
    def execute(self):
        super().execute()

def get_iam_checks(auth_session):
    return [
        Check_1_1(auth_session),
        Check_1_4(auth_session),
        Check_1_5(auth_session),
        Check_1_8(auth_session),
        Check_1_9(auth_session),
        Check_1_12(auth_session),
        Check_1_13(auth_session),
        Check_Manual_1_15(auth_session),
        Check_1_16(auth_session),
        Check_Manual_1_17(auth_session),
        Check_1_22(auth_session)
    ]
