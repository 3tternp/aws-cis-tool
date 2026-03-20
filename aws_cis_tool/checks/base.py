class CISCheck:
    def __init__(self, auth_session, check_id, title, category, description, check_type="AUTOMATED", manual_steps=None, manual_poc=None):
        self.auth = auth_session
        self.check_id = check_id
        self.title = title
        self.category = category
        self.description = description
        self.check_type = check_type  # "AUTOMATED" or "MANUAL"
        self.manual_steps = manual_steps or []
        self.manual_poc = manual_poc or []
        
        # Result states: PASS, FAIL, ERROR, WARNING, NOT_APPLICABLE, MANUAL_VERIFICATION_REQUIRED
        self.result = "UNKNOWN"
        self.details = []
        self.evidence = {}  # Store raw data for report (e.g., config snippet)

    def execute(self):
        """
        Main execution logic. Should be implemented by child classes.
        Must set self.result and self.details.
        """
        if self.check_type == "MANUAL":
            self.result = "MANUAL_VERIFICATION_REQUIRED"
            self.details.append("This check requires manual verification.")
            if self.manual_steps:
                self.details.append("Steps:")
                for step in self.manual_steps:
                    self.details.append(f"- {step}")
            if self.manual_poc:
                self.details.append("PoC:")
                for line in self.manual_poc:
                    self.details.append(f"- {line}")
            return
        
        raise NotImplementedError("Each check must implement the execute method.")

    def pass_check(self, detail="", evidence=None):
        self.result = "PASS"
        if detail:
            self.details.append(detail)
        if evidence:
            self.evidence.update(evidence)

    def fail_check(self, detail="", evidence=None):
        self.result = "FAIL"
        if detail:
            self.details.append(detail)
        if evidence:
            self.evidence.update(evidence)

    def error_check(self, detail="", evidence=None):
        self.result = "ERROR"
        if detail:
            self.details.append(detail)
        if evidence:
            self.evidence.update(evidence)

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "check_type": self.check_type,
            "result": self.result,
            "details": self.details,
            "evidence": self.evidence,
            "manual_steps": self.manual_steps,
            "manual_poc": self.manual_poc
        }
