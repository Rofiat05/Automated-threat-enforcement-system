This folder contains the Cisco network device integration
# Cisco Driver – Network Enforcement Component

## COM732: Computer Fundamentals and Problem Solving

**Project:** Python-Based Linux Authentication Monitoring and Automated Network Response System

**Contributor:** Rofiat   
**Component:** Cisco Driver and Network Enforcement

## 1. Overview

The Cisco Driver is responsible for the network response stage of our group project. Its purpose is to receive an approved security action and communicate with a Cisco network device to apply the appropriate network control.

The wider system analyses Linux authentication logs, identifies suspicious login activity, validates alerts and determines whether a network response is necessary.

My contribution focuses on the Cisco integration and enforcement stage, including connection testing, access control operations, verification, audit logging and removal of temporary blocking rules.

## 2. Objectives

The main objectives of this component are to:

- Establish communication with a Cisco IOS XE network device.
- Use Python to interact with the Cisco RESTCONF interface.
- Receive and process approved blocking requests.
- Check existing access control rules before applying changes.
- Prevent duplicate blocking rules.
- Record enforcement activities for auditing.
- Support temporary blocking and subsequent removal of rules.
- Test network enforcement safely before attempting changes on a real device.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Develop the Cisco Driver and automated tests |
| Cisco IOS XE | Network device operating system |
| RESTCONF | Communicate with Cisco IOS XE over HTTPS |
| JSON | Represent requests, responses and audit records |
| VS Code | Write, run and debug Python code |
| Cisco DevNet Sandbox | Test connectivity to a Cisco IOS XE environment |
| Python unittest | Verify Cisco Driver behaviour |
| GitHub | Store code and track contributions |

## 4. Implementation

### Cisco Device Connectivity

I developed Python scripts to establish communication with a Cisco IOS XE environment using RESTCONF.

The connection testing included authentication, sending an HTTPS GET request and checking the response from the device.

During testing, the connection returned HTTP status code **200**, indicating that the request was successful.

This confirmed that the Python application could communicate with the Cisco sandbox and retrieve device information.

The successful connection was read-only. It did not involve applying a live access control rule to the sandbox.

### Network Enforcement

The Cisco Driver includes functionality for processing approved blocking requests.

It checks existing rules before adding a new rule. This helps prevent duplicate entries when the same request is received more than once.

The component also supports removing temporary rules after their specified time-to-live has expired.

These enforcement functions were tested using a simulated Cisco client rather than modifying a real network device.

### Audit Logging

The component records enforcement activities so that actions can be reviewed.

This includes information about blocking operations, repeated requests and rule removal.

Audit logging helps provide evidence of what the system attempted and how it responded.

## 5. Testing and Results

The following tests were performed during development:

| Test | Result |
|---|---|
| Cisco IOS XE RESTCONF connectivity | HTTP 200 |
| Cisco Driver unit tests | 6 passed |
| Simulated blocking request | Successful |
| Duplicate blocking prevention | Successful |
| Temporary rule removal | Successful |
| Offline integration test | Passed |

The integration test connects the log processing component, alert validation and simulated Cisco enforcement.

During the wider project test, **45 tests passed**, comprising 44 Enforcer API tests and one integration test.

These results demonstrate the tested behaviour of the components. They do not establish that live Cisco enforcement or the complete Policy Engine integration has been achieved.

## 6. Integration With Other Components

The Cisco Driver is intended to operate as the final network enforcement component of the system.

The planned workflow is:

1. The Preprocessor analyses Linux authentication logs.
2. Suspicious activity generates a security alert.
3. The Enforcer API validates the alert.
4. The Policy Engine checks the relevant security rules and determines whether blocking is permitted.
5. The Cisco Driver receives an approved action and applies the appropriate network restriction.
6. The system records the action and removes temporary restrictions when they expire.

The offline integration test currently demonstrates the processing, validation and simulated enforcement stages. The actual Policy Engine still needs to be connected and verified.

## 7. Challenges and Learning Outcomes

During development, I encountered authentication and API response issues while testing Cisco RESTCONF connectivity.

I investigated these responses, checked the connection settings and repeated the tests until communication with the sandbox was successful.

Through this work, I developed practical experience in:

- Python programming and debugging.
- Network automation using RESTCONF.
- Cisco IOS XE connectivity.
- API requests and HTTP response codes.
- Network access control concepts.
- Automated software testing.
- Audit logging and temporary enforcement controls.
- GitHub collaboration and integration testing.

## 8. Current Status and Future Work

The Cisco Driver has passed its available unit tests, and RESTCONF connectivity to the Cisco sandbox has been demonstrated.

The next stage is to connect the actual Policy Engine, verify the complete workflow with the other group components and complete the final group demonstration.

The current automated enforcement tests use a simulated device to avoid making unintended network changes.

## 9. Conclusion

The Cisco Driver provides the network enforcement functionality required by the proposed authentication monitoring system.

The work demonstrates how Python can communicate with a Cisco IOS XE environment and how approved network restrictions can be applied, checked, recorded and removed in a controlled test environment.

Further integration testing will be required before the complete group system can be considered finished.
