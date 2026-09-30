from ..rules import (r001_required_info, r002_chronology, r003_coverage_active,
                     r004_member_match, r005_network, r006_duplicates,
                     r007_line_arithmetic, r008_auth_reference, r009_auth_record,
                     r010_document, r011_service_catalogue, r012_total_match,
                     r013_limits, r014_submission_window, r015_currency)

RULES = {
    "R001": r001_required_info.evaluate, "R002": r002_chronology.evaluate,
    "R003": r003_coverage_active.evaluate, "R004": r004_member_match.evaluate,
    "R005": r005_network.evaluate, "R006": r006_duplicates.evaluate,
    "R007": r007_line_arithmetic.evaluate, "R008": r008_auth_reference.evaluate,
    "R009": r009_auth_record.evaluate, "R010": r010_document.evaluate,
    "R011": r011_service_catalogue.evaluate, "R012": r012_total_match.evaluate,
    "R013": r013_limits.evaluate, "R014": r014_submission_window.evaluate,
    "R015": r015_currency.evaluate,
}
