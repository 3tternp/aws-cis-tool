from .iam import get_iam_checks
from .storage import get_storage_checks
from .logging import get_logging_checks
from .networking import get_networking_checks
from .monitoring import get_monitoring_checks
from .security import get_security_checks

def get_all_checks(auth_session):
    checks = []
    checks.extend(get_iam_checks(auth_session))
    checks.extend(get_storage_checks(auth_session))
    checks.extend(get_logging_checks(auth_session))
    checks.extend(get_networking_checks(auth_session))
    checks.extend(get_monitoring_checks(auth_session))
    checks.extend(get_security_checks(auth_session))
    return checks
