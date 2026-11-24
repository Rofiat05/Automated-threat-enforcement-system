# Merged Cisco Driver – Person A and Person E Contributions

**Module:** COM732 – Computer Fundamentals and Problem Solving

**Project:** Python-Based Linux Authentication Monitoring and Automated Network Response System

## 1. Person A (Rofiat) – Architecture, Communication and Integration

Assigned responsibilities:

- Cisco Driver technical architecture and mock environment.
- RESTCONF client implementation and Cisco device connectivity.
- API communication and configuration.
- Connection security and error handling.
- Integration with other project components.

Additional contributions include integration testing, troubleshooting driver import conflicts and verifying communication between the alert validation API, policy engine and merged Cisco Driver in a simulated environment.

**Supporting evidence:**

- https://github.com/Rofiat05/Automated-threat-enforcement-system/tree/main/cisco_driver/com732_build
- [Merged Cisco Driver integration tests](../integration/test_merged_end_to_end.py)
- [Integration testing and fixes – Pull Request #23](https://github.com/Rofiat05/Automated-threat-enforcement-system/pull/23)

## 2. Person E – Enforcement and Rule Lifecycle Management

Assigned responsibilities:

- IP-blocking logic.
- Duplicate blocking rule prevention.
- Temporary blocking and TTL expiry.
- Rollback and recovery mechanisms.
- Cisco Driver user documentation.

Person E's v1.1 contribution also documents enhancements to block storage, expiry processing, IP validation, blocking policies and command-line operations.

**Supporting evidence:**

- https://github.com/Rofiat05/Automated-threat-enforcement-system/blob/main/updated-repo/CONTRIBUTION_README.md
- https://github.com/Rofiat05/Automated-threat-enforcement-system/blob/main/updated-repo/CISCO_DRIVER_USER_GUIDE.md 
- https://github.com/Rofiat05/Automated-threat-enforcement-system/blob/main/updated-repo/ENHANCEMENTS_v1.1.md
- [Testing and supporting evidence](../updated-repo/evidence/)

## 3. Merged Implementation

The merged Cisco Driver brings together device communication and network enforcement functionality to support the wider automated threat enforcement system.

The combined implementation can be examined through the following files:

- [Cisco Driver modules](./cisco_driver/)
- [Merged Driver Adapter](./merged_driver_adapter.py)
- [Mock Device](./mock_device.py)
- [Driver Demonstration](./driver_demo.py)
- [Driver Tests](./tests/)

## 4. Integration and Testing

Person A contributed additional integration tests covering:

- Blocking of an approved untrusted IP address.
- Protection of trusted IP addresses.
- Prevention of inappropriate blocking of internal IP addresses.
- Duplicate alert rejection.
- Verification of audit records.

The selected combined test suite recorded 171 passing tests following the integration test fixes documented in Pull Request #23.

Person E separately documented 145 passing tests for the v1.1 enhanced implementation.

These results relate to their respective tested versions and test selections.

## 5. Individual Attribution

The merged Cisco Driver represents collaborative development. Individual contributions should be assessed using the original implementations, assigned responsibilities, GitHub commits, pull requests and supporting test evidence.
