import boto3
import botocore.exceptions
from botocore.config import Config
from colorama import Fore, Style

DEFAULT_REGION = "us-east-1"

# Retries + timeouts so throttling / slow regions don't surface as scan errors.
_BOTO_CONFIG = Config(
    retries={"max_attempts": 8, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
)


class AuthError(Exception):
    """Raised with a user-friendly message when authentication fails."""


def _clean(value):
    """Strip whitespace/quotes/newlines that commonly sneak in when pasting keys."""
    if value is None:
        return None
    value = str(value).strip().strip("'\"").strip()
    return value or None


class AWSAuth:
    def __init__(self, profile_name=None, region_name=None, aws_access_key_id=None,
                 aws_secret_access_key=None, aws_session_token=None):
        self.profile_name = _clean(profile_name)
        self.region_name = _clean(region_name)
        self.aws_access_key_id = _clean(aws_access_key_id)
        self.aws_secret_access_key = _clean(aws_secret_access_key)
        self.aws_session_token = _clean(aws_session_token)
        self.session = None
        self.identity = {}
        self.last_error = None

    # ------------------------------------------------------------------ helpers
    def _build_session(self):
        if self.aws_access_key_id or self.aws_secret_access_key:
            if not (self.aws_access_key_id and self.aws_secret_access_key):
                raise AuthError("Both Access Key ID and Secret Access Key are required.")
            if self.aws_access_key_id.startswith("ASIA") and not self.aws_session_token:
                raise AuthError(
                    "This Access Key ID starts with 'ASIA' (temporary credentials), "
                    "so a Session Token is required as well."
                )
            return boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                region_name=self.region_name,
            )
        if self.profile_name:
            return boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
        return boto3.Session(region_name=self.region_name)

    def _explain(self, e):
        """Turn a boto/botocore exception into a short actionable message."""
        if isinstance(e, AuthError):
            return str(e)
        if isinstance(e, botocore.exceptions.ProfileNotFound):
            return (f"Profile '{self.profile_name}' not found. Check ~/.aws/credentials "
                    "and ~/.aws/config.")
        if isinstance(e, botocore.exceptions.NoCredentialsError):
            return ("No AWS credentials found. Enter an access key / secret key, pick a "
                    "profile, or run 'aws configure' / 'aws sso login'.")
        if isinstance(e, botocore.exceptions.SSOTokenLoadError) or "SSO" in str(e) \
                or "Token has expired" in str(e):
            return ("SSO session missing or expired. Run: "
                    f"aws sso login --profile {self.profile_name or 'default'}")
        if isinstance(e, botocore.exceptions.ClientError):
            code = e.response.get("Error", {}).get("Code", "Unknown")
            hints = {
                "InvalidClientTokenId": "The Access Key ID is invalid, deleted or inactive "
                                        "(or temporary keys are missing their Session Token).",
                "SignatureDoesNotMatch": "The Secret Access Key does not match the Access "
                                         "Key ID (check for typos / extra spaces).",
                "ExpiredToken": "The credentials/session token have expired. Generate new ones.",
                "ExpiredTokenException": "The credentials/session token have expired. Generate new ones.",
                "AccessDenied": "The identity is not allowed to call sts:GetCallerIdentity.",
                "AuthFailure": "AWS rejected the credentials (AuthFailure). Check key and clock skew.",
            }
            return f"{code}: {hints.get(code, e.response.get('Error', {}).get('Message', str(e)))}"
        if isinstance(e, (botocore.exceptions.EndpointConnectionError,
                          botocore.exceptions.ConnectTimeoutError,
                          botocore.exceptions.ProxyConnectionError)):
            return f"Cannot reach AWS ({e}). Check your network/proxy and region."
        return f"Unexpected authentication error: {e}"

    # --------------------------------------------------------------------- API
    def authenticate(self):
        self.last_error = None
        try:
            print(f"{Fore.CYAN}[*] Authenticating with AWS...{Style.RESET_ALL}")
            self.session = self._build_session()

            # Many checks create regional clients; with no region boto3 raises
            # "You must specify a region". Fall back to a sane default.
            if not self.session.region_name:
                self.region_name = DEFAULT_REGION
                self.session = self._rebuild_with_region(DEFAULT_REGION)
                print(f"{Fore.YELLOW}[!] No region configured - using {DEFAULT_REGION}."
                      f"{Style.RESET_ALL}")
            else:
                self.region_name = self.session.region_name

            self.identity = self.session.client("sts", config=_BOTO_CONFIG).get_caller_identity()
            print(f"{Fore.GREEN}[+] Successfully authenticated!{Style.RESET_ALL}")
            print(f"    Account ID: {self.identity.get('Account')}")
            print(f"    ARN: {self.identity.get('Arn')}")
            print(f"    Region: {self.region_name}")
            return True
        except Exception as e:  # noqa: BLE001 - we translate every failure
            self.last_error = self._explain(e)
            print(f"{Fore.RED}[!] {self.last_error}{Style.RESET_ALL}")
            return False

    def _rebuild_with_region(self, region):
        if self.aws_access_key_id:
            return boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                region_name=region,
            )
        return boto3.Session(profile_name=self.profile_name, region_name=region)

    @property
    def account_id(self):
        return self.identity.get("Account")

    def get_client(self, service_name, region=None):
        if not self.session:
            raise Exception("Session not initialized. Call authenticate() first.")
        return self.session.client(service_name, region_name=region or self.region_name,
                                   config=_BOTO_CONFIG)
