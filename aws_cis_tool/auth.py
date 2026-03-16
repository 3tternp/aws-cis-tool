import boto3
import botocore.exceptions
from colorama import Fore, Style

class AWSAuth:
    def __init__(self, profile_name=None, region_name=None, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None):
        self.profile_name = profile_name
        self.region_name = region_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.session = None

    def authenticate(self):
        try:
            print(f"{Fore.CYAN}[*] Authenticating with AWS...{Style.RESET_ALL}")
            if self.aws_access_key_id and self.aws_secret_access_key:
                self.session = boto3.Session(
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    aws_session_token=self.aws_session_token,
                    region_name=self.region_name
                )
            elif self.profile_name:
                self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
            else:
                self.session = boto3.Session(region_name=self.region_name)
            
            # Verify credentials by calling STS GetCallerIdentity
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            print(f"{Fore.GREEN}[+] Successfully authenticated!{Style.RESET_ALL}")
            print(f"    Account ID: {identity.get('Account')}")
            print(f"    ARN: {identity.get('Arn')}")
            print(f"    Region: {self.session.region_name}")
            return True
            
        except botocore.exceptions.ProfileNotFound as e:
            print(f"{Fore.RED}[!] Profile '{self.profile_name}' not found. Please check your ~/.aws/credentials or ~/.aws/config files.{Style.RESET_ALL}")
            return False
        except botocore.exceptions.NoCredentialsError:
            print(f"{Fore.RED}[!] No AWS credentials found.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Hint: Run 'aws configure' or 'aws sso login --profile <profile_name>'{Style.RESET_ALL}")
            return False
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'ExpiredToken':
                print(f"{Fore.RED}[!] AWS Token is expired.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Hint: It seems your SSO session has expired.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}      Please run the following command in your terminal to login:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}      aws sso login --profile {self.profile_name or 'default'}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Authentication Error: {str(e)}{Style.RESET_ALL}")
            return False
        except botocore.exceptions.SSOTokenLoadError:
             print(f"{Fore.RED}[!] Error loading SSO Token.{Style.RESET_ALL}")
             print(f"{Fore.YELLOW}Hint: You might not be logged in via SSO.{Style.RESET_ALL}")
             print(f"{Fore.YELLOW}      Please run the following command in your terminal to login:{Style.RESET_ALL}")
             print(f"{Fore.CYAN}      aws sso login --profile {self.profile_name or 'default'}{Style.RESET_ALL}")
             return False
        except Exception as e:
            if "Token has expired" in str(e) or "SSO" in str(e):
                print(f"{Fore.RED}[!] AWS Token/SSO Error.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Hint: Please run the following command in your terminal to login:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}      aws sso login --profile {self.profile_name or 'default'}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Unexpected error during authentication: {str(e)}{Style.RESET_ALL}")
            return False

    def get_client(self, service_name, region=None):
        if not self.session:
            raise Exception("Session not initialized. Call authenticate() first.")
        if region:
            return self.session.client(service_name, region_name=region)
        return self.session.client(service_name)
