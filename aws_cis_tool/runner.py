"""Shared scan engine used by the CLI and the web UI."""
import traceback

from .checks import get_all_checks
from .report import ReportGenerator

PERMISSION_HINT = ("Permission issue: attach the AWS managed policies 'SecurityAudit' and "
                   "'ViewOnlyAccess' to the scanning identity.")
_DENIED = ("AccessDenied", "UnauthorizedOperation", "not authorized", "AuthorizationError")


def run_scan(auth, on_progress=None, should_stop=None):
    """Run every check, isolating failures so one bad check never aborts the scan.

    on_progress(index, total, check_dict) is called after each check.
    Returns the list of result dicts.
    """
    checks = get_all_checks(auth)
    total = len(checks)
    results = []
    for i, check in enumerate(checks, 1):
        if should_stop and should_stop():
            break
        try:
            check.execute()
        except Exception as e:  # noqa: BLE001
            check.error_check(f"Check crashed: {e}", evidence={"Traceback": traceback.format_exc()})
        if check.result == "UNKNOWN":
            check.error_check("Check finished without setting a result.")
        if check.result == "ERROR" and any(s in " ".join(map(str, check.details)) for s in _DENIED):
            if PERMISSION_HINT not in check.details:
                check.details.append(PERMISSION_HINT)
        d = check.to_dict()
        results.append(d)
        if on_progress:
            on_progress(i, total, d)
    return results


def summarize(results):
    s = {"PASS": 0, "FAIL": 0, "ERROR": 0, "MANUAL_VERIFICATION_REQUIRED": 0}
    for r in results:
        k = r.get("result", "ERROR")
        s[k] = s.get(k, 0) + 1
    return s


def write_reports(results, account_id, out_dir, formats):
    gen = ReportGenerator(results, account_id, output_dir=out_dir)
    files = {}
    if "json" in formats:
        files["json"] = gen.generate_json()
    if "html" in formats:
        files["html"] = gen.generate_html()
    if "pdf" in formats:
        files["pdf"] = gen.generate_pdf()
    return {k: v for k, v in files.items() if v}
