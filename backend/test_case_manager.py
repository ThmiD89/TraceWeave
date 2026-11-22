from services.case_manager import (
    create_case,
    list_cases,
    get_case
)

# Create a new investigation.
case = create_case(
    title="Ubuntu Heartbeat Investigation",
    description="Investigation of Ubuntu endpoint heartbeat network activity."
)

print("\n===== CREATED CASE =====")
print(case)

# Retrieve all cases.
print("\n===== ALL CASES =====")
print(list_cases())

# Retrieve one specific case.
print("\n===== CASE DETAILS =====")
print(get_case(case["case_id"]))
