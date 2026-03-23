from .base import CISCheck
import botocore.exceptions


class Check_6_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.1",
            title="Ensure Amazon GuardDuty is enabled",
            category="Security",
            description="Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior."
        )

    def execute(self):
        try:
            guardduty = self.auth.get_client('guardduty')
            detector_ids = guardduty.list_detectors().get('DetectorIds', [])

            evidence = {"DetectorIds": detector_ids, "Detectors": []}

            if not detector_ids:
                self.fail_check("No GuardDuty detectors found in this region.", evidence=evidence)
                return

            enabled_detectors = []
            disabled_detectors = []

            for detector_id in detector_ids:
                detector = guardduty.get_detector(DetectorId=detector_id)
                status = detector.get('Status')
                evidence["Detectors"].append({"DetectorId": detector_id, "Status": status})

                if status == 'ENABLED':
                    enabled_detectors.append(detector_id)
                else:
                    disabled_detectors.append(detector_id)

            if enabled_detectors:
                self.pass_check(f"GuardDuty is enabled (detectors: {', '.join(enabled_detectors)}).", evidence=evidence)
            else:
                self.fail_check(f"GuardDuty detectors exist but none are enabled (detectors: {', '.join(disabled_detectors)}).", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check GuardDuty status: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_2(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.2",
            title="Ensure AWS Security Hub is enabled",
            category="Security",
            description="AWS Security Hub provides a comprehensive view of your security posture across AWS accounts and services."
        )

    def execute(self):
        try:
            securityhub = self.auth.get_client('securityhub')
            evidence = {}

            try:
                response = securityhub.describe_hub()
                hub_arn = response.get('HubArn')
                evidence["Hub"] = response
                if hub_arn:
                    self.pass_check(f"Security Hub is enabled (HubArn: {hub_arn}).", evidence=evidence)
                else:
                    self.fail_check("Security Hub describe_hub returned no HubArn.", evidence=evidence)
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', '')
                evidence["Error"] = {"Code": code, "Message": str(e)}

                if code in {"InvalidAccessException", "ResourceNotFoundException"}:
                    self.fail_check("Security Hub is not enabled in this region.", evidence=evidence)
                else:
                    raise

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check Security Hub status: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_3(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.3",
            title="Ensure Amazon GuardDuty is enabled in all enabled regions",
            category="Security",
            description="GuardDuty is a regional service. For consistent coverage, enable GuardDuty in every enabled region."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            regions_resp = ec2.describe_regions(AllRegions=True)
            regions = regions_resp.get('Regions', [])

            enabled_regions = []
            for r in regions:
                name = r.get('RegionName')
                opt_in = r.get('OptInStatus')
                if not name:
                    continue
                if opt_in in (None, 'opt-in-not-required', 'opted-in'):
                    enabled_regions.append(name)

            evidence = {"EnabledRegions": enabled_regions, "Regions": {}}

            missing = []
            disabled = []

            for region in enabled_regions:
                try:
                    guardduty = self.auth.get_client('guardduty', region=region)
                    detector_ids = guardduty.list_detectors().get('DetectorIds', [])
                    region_detectors = []
                    for detector_id in detector_ids:
                        detector = guardduty.get_detector(DetectorId=detector_id)
                        status = detector.get('Status')
                        region_detectors.append({"DetectorId": detector_id, "Status": status})
                    evidence["Regions"][region] = {"DetectorIds": detector_ids, "Detectors": region_detectors}

                    if not detector_ids:
                        missing.append(region)
                    elif not any(d.get("Status") == "ENABLED" for d in region_detectors):
                        disabled.append(region)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    evidence["Regions"][region] = {"Error": {"Code": code, "Message": str(e)}}
                    missing.append(region)

            if not missing and not disabled:
                self.pass_check("GuardDuty is enabled in all enabled regions.", evidence=evidence)
            else:
                detail_parts = []
                if missing:
                    detail_parts.append(f"Regions without GuardDuty detectors: {', '.join(missing)}")
                if disabled:
                    detail_parts.append(f"Regions with GuardDuty detectors not enabled: {', '.join(disabled)}")
                self.fail_check("; ".join(detail_parts), evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check GuardDuty across regions: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_4(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.4",
            title="Ensure AWS Security Hub is enabled in all enabled regions",
            category="Security",
            description="Security Hub is a regional service. For consistent coverage, enable Security Hub in every enabled region."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            regions_resp = ec2.describe_regions(AllRegions=True)
            regions = regions_resp.get('Regions', [])

            enabled_regions = []
            for r in regions:
                name = r.get('RegionName')
                opt_in = r.get('OptInStatus')
                if not name:
                    continue
                if opt_in in (None, 'opt-in-not-required', 'opted-in'):
                    enabled_regions.append(name)

            evidence = {"EnabledRegions": enabled_regions, "Regions": {}}
            not_enabled = []

            for region in enabled_regions:
                try:
                    securityhub = self.auth.get_client('securityhub', region=region)
                    hub = securityhub.describe_hub()
                    hub_arn = hub.get('HubArn')
                    evidence["Regions"][region] = {"HubArn": hub_arn}
                    if not hub_arn:
                        not_enabled.append(region)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    evidence["Regions"][region] = {"Error": {"Code": code, "Message": str(e)}}
                    if code in {"InvalidAccessException", "ResourceNotFoundException"}:
                        not_enabled.append(region)
                    else:
                        raise

            if not not_enabled:
                self.pass_check("Security Hub is enabled in all enabled regions.", evidence=evidence)
            else:
                self.fail_check(f"Security Hub is not enabled in regions: {', '.join(not_enabled)}", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check Security Hub across regions: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_5(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.5",
            title="Ensure Security Hub CIS AWS Foundations Benchmark standard is enabled",
            category="Security",
            description="When using Security Hub, enabling the CIS AWS Foundations Benchmark standard helps track CIS-aligned findings."
        )

    def execute(self):
        try:
            securityhub = self.auth.get_client('securityhub')
            paginator = securityhub.get_paginator('get_enabled_standards')
            subs = []
            for page in paginator.paginate():
                subs.extend(page.get('StandardsSubscriptions', []))

            evidence = {"StandardsSubscriptions": subs}

            cis_subs = []
            for s in subs:
                arn = s.get('StandardsArn', '') or ''
                if 'cis-aws-foundations-benchmark' in arn:
                    cis_subs.append(s)

            if not cis_subs:
                self.fail_check("CIS AWS Foundations Benchmark standard is not enabled in Security Hub (this region).", evidence=evidence)
                return

            if any(s.get('StandardsStatus') in {'READY', 'INCOMPLETE'} for s in cis_subs):
                self.pass_check("CIS AWS Foundations Benchmark standard is enabled in Security Hub.", evidence={"CISStandardsSubscriptions": cis_subs})
            else:
                statuses = sorted({s.get('StandardsStatus', 'UNKNOWN') for s in cis_subs})
                self.fail_check(f"CIS standard subscription exists but is not active (statuses: {', '.join(statuses)}).", evidence={"CISStandardsSubscriptions": cis_subs})

        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in {"InvalidAccessException", "ResourceNotFoundException"}:
                self.fail_check("Security Hub is not enabled in this region, so standards cannot be evaluated.")
            else:
                self.error_check(f"Failed to check enabled Security Hub standards: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_6(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.6",
            title="Ensure EBS encryption by default is enabled",
            category="Security",
            description="Enabling EBS encryption by default helps ensure new EBS volumes and snapshots are encrypted."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            resp = ec2.get_ebs_encryption_by_default()
            enabled = resp.get('EbsEncryptionByDefault')
            evidence = {"EbsEncryptionByDefault": enabled}

            if enabled is True:
                self.pass_check("EBS encryption by default is enabled.", evidence=evidence)
            else:
                self.fail_check("EBS encryption by default is not enabled.", evidence=evidence)
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check EBS encryption by default: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_7(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.7",
            title="Ensure S3 account-level Block Public Access is enabled",
            category="Security",
            description="S3 account-level Block Public Access provides a safety net that helps prevent public exposure of S3 resources."
        )

    def execute(self):
        try:
            sts = self.auth.get_client('sts')
            account_id = sts.get_caller_identity().get('Account')
            s3control = self.auth.get_client('s3control')

            resp = s3control.get_public_access_block(AccountId=account_id)
            config = resp.get('PublicAccessBlockConfiguration', {})
            evidence = {"AccountId": account_id, "PublicAccessBlockConfiguration": config}

            required_flags = [
                'BlockPublicAcls',
                'IgnorePublicAcls',
                'BlockPublicPolicy',
                'RestrictPublicBuckets',
            ]

            missing = [k for k in required_flags if config.get(k) is not True]

            if not missing:
                self.pass_check("S3 account-level Block Public Access is fully enabled.", evidence=evidence)
            else:
                self.fail_check(f"S3 account-level Block Public Access is not fully enabled (missing/false: {', '.join(missing)}).", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in {'NoSuchPublicAccessBlockConfiguration'}:
                self.fail_check("S3 account-level Block Public Access is not configured.")
            else:
                self.error_check(f"Failed to check S3 account-level Block Public Access: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_8(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.8",
            title="Ensure EC2 instances require IMDSv2",
            category="Security",
            description="Requiring IMDSv2 (HttpTokens=required) reduces risk of SSRF-based credential theft from the Instance Metadata Service."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            paginator = ec2.get_paginator('describe_instances')

            non_compliant = []
            checked = 0

            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        checked += 1
                        instance_id = instance.get('InstanceId')
                        state = (instance.get('State') or {}).get('Name')
                        metadata = instance.get('MetadataOptions') or {}
                        http_tokens = metadata.get('HttpTokens')
                        if http_tokens != 'required':
                            non_compliant.append(
                                {
                                    "InstanceId": instance_id,
                                    "State": state,
                                    "HttpTokens": http_tokens,
                                    "HttpEndpoint": metadata.get('HttpEndpoint'),
                                    "HttpPutResponseHopLimit": metadata.get('HttpPutResponseHopLimit'),
                                }
                            )

            evidence = {"CheckedInstances": checked}

            if non_compliant:
                evidence["NonCompliantInstances"] = non_compliant[:200]
                if len(non_compliant) > 200:
                    evidence["NonCompliantTruncated"] = len(non_compliant) - 200
                self.fail_check(f"Instances not requiring IMDSv2: {len(non_compliant)}", evidence=evidence)
            else:
                self.pass_check("All EC2 instances require IMDSv2 (HttpTokens=required).", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check EC2 IMDS settings: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_9(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.9",
            title="Ensure all EBS volumes are encrypted",
            category="Security",
            description="EBS encryption helps protect data at rest on block storage volumes."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            paginator = ec2.get_paginator('describe_volumes')

            unencrypted = []
            checked = 0

            for page in paginator.paginate():
                for vol in page.get('Volumes', []):
                    checked += 1
                    if vol.get('Encrypted') is True:
                        continue
                    attachments = []
                    for a in vol.get('Attachments', []) or []:
                        attachments.append(
                            {
                                "InstanceId": a.get('InstanceId'),
                                "State": a.get('State'),
                                "Device": a.get('Device'),
                            }
                        )
                    unencrypted.append(
                        {
                            "VolumeId": vol.get('VolumeId'),
                            "State": vol.get('State'),
                            "Size": vol.get('Size'),
                            "VolumeType": vol.get('VolumeType'),
                            "Attachments": attachments,
                        }
                    )

            evidence = {"CheckedVolumes": checked}

            if unencrypted:
                evidence["UnencryptedVolumes"] = unencrypted[:200]
                if len(unencrypted) > 200:
                    evidence["UnencryptedTruncated"] = len(unencrypted) - 200
                self.fail_check(f"Unencrypted EBS volumes found: {len(unencrypted)}", evidence=evidence)
            else:
                self.pass_check("All EBS volumes are encrypted.", evidence=evidence)

        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check EBS volume encryption: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")


class Check_6_10(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="6.10",
            title="Ensure S3 bucket default encryption is enabled",
            category="Security",
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


def get_security_checks(auth_session):
    return [
        Check_6_1(auth_session),
        Check_6_2(auth_session),
        Check_6_3(auth_session),
        Check_6_4(auth_session),
        Check_6_5(auth_session),
        Check_6_6(auth_session),
        Check_6_7(auth_session),
        Check_6_8(auth_session),
        Check_6_9(auth_session),
        Check_6_10(auth_session),
    ]
