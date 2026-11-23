# COM732 AE2 – SSH Authentication Monitoring and Automated Network Enforcement

## Project Overview

This repository contains the development of a Python-based cybersecurity solution for detecting suspicious remote login activities, aggregating authentication events, and enforcing automated network security controls.

The project focuses on identifying potentially hostile SSH login attempts against Linux systems through the analysis of authentication logs. Rather than forwarding every individual event to a Security Information and Event Management (SIEM) system, the solution aims to aggregate related events, assess their significance, and generate meaningful security alerts.

Where predefined security conditions are met, the system is designed to trigger appropriate network controls on Cisco IOS XE devices through an automated enforcement mechanism.

The project is being developed as part of the requirements of the **COM732 – Computer Fundamentals assessment at Solent University**.

## Project Objectives

The primary objectives are to:

* Detect suspicious remote login activities from Linux authentication logs.
* Aggregate and enrich authentication events to reduce unnecessary SIEM processing and associated costs.
* Identify repeated failed login attempts using configurable time windows and asset-based thresholds.
* Maintain an asset inventory to support risk assessment and informed security decisions.
* Apply automated and reversible network controls to appropriate Cisco network devices.
* Maintain secure communication, reliable processing, auditability and accountability across the system.

## System Architecture

The proposed solution consists of three principal functional areas:

### 1. Authentication Log Preprocessor

The preprocessor analyses Linux authentication logs and identifies relevant SSH authentication events.

Its responsibilities include:

* Reading multiple authentication log files, including compressed `.gz` files.
* Parsing authentication records into structured event data.
* Identifying failed and successful login attempts.
* Grouping failed login attempts according to host, source IP address and configurable time windows.
* Applying alert thresholds based on the business criticality of the affected asset.
* Generating structured summaries in JSON Lines (JSONL) format or forwarding them through an HTTPS interface.

This component is intended to minimise unnecessary event forwarding by identifying potentially significant activity before it reaches downstream security services.

### 2. Asset Inventory and Policy Engine

The asset inventory maintains relevant information about monitored systems, including:

* Hostname and primary IP address.
* Environment and system owner.
* Business function.
* Business criticality.

The policy engine uses this information alongside predefined allowlists and risk modifiers to determine whether an alert warrants further action.

It also determines the appropriate network control point for a potential enforcement action.

### 3. Policy Enforcement and Cisco Network Integration

The enforcement component receives relevant alerts and determines whether an automated network response is authorised.

The intended workflow includes:

* Validating incoming alert requests.
* Checking authentication and replay-protection requirements.
* Preventing duplicate enforcement actions.
* Communicating with Cisco IOS XE devices through a secure configuration interface.
* Applying appropriate network controls, such as access-control restrictions or sinkhole routes.
* Recording enforcement actions and their outcomes.
* Applying time-to-live (TTL) values to ensure temporary controls can be removed.
* Supporting rollback and recovery.

## High-Level Data Flow

The intended system workflow is as follows:

```text
Linux Authentication Logs
          |
          v
Authentication Log Preprocessor
          |
          v
Event Parsing and Aggregation
          |
          v
Asset-Based Threshold Evaluation
          |
          v
Security Event Summary
       /       \
      v         v
    JSONL      HTTPS
      \         /
       v       v
   Asset Inventory
          |
          v
     Policy Engine
          |
          v
   Enforcement API
          |
          v
   Cisco Network Driver
          |
          v
    Cisco IOS XE Device
          |
          v
  Network Security Control
          |
          v
 Audit Logging and TTL/Rollback
```

## Technology and Development Approach

The project uses the following technologies and concepts:

| Technology / Concept            | Application                               |
| ------------------------------- | ----------------------------------------- |
| Python                          | Core application development              |
| Linux authentication logs       | Source of authentication events           |
| Python file handling            | Reading authentication log files          |
| Gzip                            | Processing compressed authentication logs |
| Regular expressions and parsing | Extracting structured event information   |
| JSON / JSONL                    | Structured event and alert representation |
| HTTPS                           | Secure communication between components   |
| Cisco IOS XE                    | Target network infrastructure             |
| RESTCONF                        | Network device configuration interface    |
| HMAC                            | Request authentication and integrity      |
| Git and GitHub                  | Version control and collaboration         |
| Python testing tools            | Functional and integration testing        |

The application is designed using a modular approach, allowing individual components to be developed, tested and integrated independently.

## Team Responsibilities

The project is divided among six team members, each responsible for specific implementation and project management activities.

| Member | Primary Responsibility             | Main Contribution                                                                                  |
| ------ | ---------------------------------- | -------------------------------------------------------------------------------------------------- |
| A      | Project management and integration | Repository management, shared configuration, logging, CI skeleton and end-to-end integration       |
| B      | Authentication log preprocessor    | Log reading, parsing, event aggregation, threshold evaluation, JSONL and HTTPS output              |
| C      | Asset inventory and policy engine  | CSV inventory, HTTP inventory endpoint, allowlists, risk modifiers and control-point selection     |
| D      | Enforcement API                    | HMAC authentication, timestamp and nonce replay protection, deduplication and schema validation    |
| E      | Cisco network driver               | RESTCONF communication, read-before-write, retries, TTL expiry and rollback                        |
| F      | Testing and security               | Unit and integration testing, performance testing, Bandit, pip-audit, Gitleaks, SBOM and checksums |

The separation of responsibilities supports parallel development while allowing the individual components to be integrated into one functional application.

## Current Development Progress

Development is being carried out incrementally, with individual components implemented and tested before integration.

The initial preprocessor development has established a working foundation for reading and parsing Linux authentication log entries into structured Python data.

Initial test outputs have demonstrated the identification of both failed and successful login events, including relevant information such as usernames, source IP addresses and source ports.

The wider preprocessor functionality is designed to extend this foundation through event aggregation, time-window evaluation, asset-based thresholds and structured output for integration with the other components.

The remaining implementation and integration progress will be reflected through repository commits, test results and project documentation.

## Security Considerations

Security is a central consideration throughout the development process.

The solution is designed around the following security requirements:

* **Encrypted communication:** Network communication between application components and devices must use secure transport.
* **Input validation:** Incoming data, file paths, IP addresses and configuration parameters must be validated.
* **Secure secrets management:** Credentials and sensitive configuration values must not be hardcoded into the source code.
* **Least privilege:** Application and network device accounts should operate with only the permissions required.
* **Request authentication:** Enforcement requests must be authenticated and protected against replay attacks.
* **Duplicate prevention:** Repeated alerts should not result in unnecessary or duplicated network changes.
* **Auditability:** Relevant processing and enforcement activities should be recorded without exposing sensitive information.
* **Reversibility:** Automated network controls should have defined expiry periods and rollback mechanisms.

## Testing and Quality Assurance

Testing is necessary to establish the reliability, functionality and security of the application.

The project testing strategy includes:

**Functional testing**

* Authentication log reading and parsing.
* Recognition of relevant login events.
* Event aggregation and threshold evaluation.
* JSONL output generation.
* Validation of application inputs.

**Integration testing**

* Communication between the preprocessor and enforcement components.
* Inventory and policy engine interactions.
* Mocked external services and network device interfaces.
* Verification of the overall event-to-enforcement workflow.

**Performance testing**

* Assessment of log-processing performance.
* Evaluation of event aggregation under increased workloads.
* Measurement of enforcement response times.

**Security testing**

* Static code analysis.
* Dependency vulnerability assessment.
* Secret scanning.
* Input validation and secure communication checks.

The intended testing and security tools include Bandit, pip-audit and Gitleaks, alongside the team's automated and manual testing activities.

## Repository Organisation

The application is being developed as separate functional modules.

The current preprocessor development is organised under:

```text
preprocessor/
```

Shared configuration and logging are part of the wider repository structure under:

```text
common/
```

Additional component directories, test files and documentation are maintained as the individual modules and integration work progress.

## Development Environment

The assessment requires a Python-based application using Python 3.6 or above. A virtual environment is recommended to keep project dependencies separate from the system Python installation.


Component-specific execution and testing instructions will be maintained as the application entry points and shared test framework are finalised.

## Project Scope and Limitations

This project is an academic software development exercise demonstrating the practical application of computer systems, cybersecurity principles, Python programming, network automation and collaborative software development.

The automated enforcement functionality is intended to operate within a controlled and authorised testing environment. Sample authentication logs, mocked external services and simulated network devices can be used to validate system behaviour without affecting production infrastructure.

The project is not intended to replace a full enterprise SIEM, network access-control platform or dedicated threat detection system.

## Academic Context

**Institution:** Solent University
**Module:** COM732 – Computer Fundamentals
**Assessment:** AE2 – Group Software Project
**Academic Year:** 2026–2027

The repository provides evidence of the software implementation, individual contributions, collaborative development and technical decisions made throughout the project.

Individual contributions are supported through Git commits and accompanying project documentation.
