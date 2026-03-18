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


def get_security_checks(auth_session):
    return [
        Check_6_1(auth_session),
        Check_6_2(auth_session),
    ]
