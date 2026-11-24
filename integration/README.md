# Integration Testing – Person A (Rofiat)

## Overview

This folder contains integration tests developed to verify communication between the components of the automated threat enforcement system.

## Person A – Individual Contribution

- Integration of authentication log processing, alert validation and simulated network enforcement.
- End-to-end test development and API compatibility improvements.
- Integration of the policy engine with the merged Cisco Driver.
- Troubleshooting and resolution of driver import conflicts.
- Verification of approved IP blocking, trusted and internal IP protection, duplicate alert rejection and audit logging.

## Integration Test Files

| File | Purpose |
|---|---|
| https://github.com/Rofiat05/Automated-threat-enforcement-system/blob/main/integration/test_end_to_end.py | Original offline integration testing using simulated network enforcement. |
| https://github.com/Rofiat05/Automated-threat-enforcement-system/blob/main/integration/test_merged_end_to_end.py | Integration testing of the API, policy engine and merged Cisco Driver. |

## Testing Results

The selected combined test suite recorded 171 passing tests following the merged driver integration and compatibility fixes.

These results demonstrate successful testing of the selected components in a simulated environment at the tested repository version.

## Supporting Evidence

- [Original End-to-End Integration Test](./test_end_to_end.py)
- [Merged Cisco Driver Integration Tests](./test_merged_end_to_end.py)
- [Pull Request #23 – Integration Testing and Fixes](https://github.com/Rofiat05/Automated-threat-enforcement-system/pull/23)
