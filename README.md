### Automated Threat Enforcement System COM732 Project ###

## Project Overview

The Automated Threat Enforcement System is a project designed to detect suspicious remote login activities from Linux authentication logs, reduce unnecessary Security Information and Event Management (SIEM) workload, and automatically apply appropriate network security controls to Cisco IOS XE devices.

The system uses log preprocessing, asset inventory information and policy-based enforcement to identify potential threats and respond through controlled and reversible network actions.

The project adopts a modular approach, allowing individual components to be developed, tested and integrated independently.

## Problem Statement

Repeated failed remote login attempts can indicate malicious activities, such as brute-force attacks. Sending every authentication event individually to a SIEM system can increase event volume, processing requirements and operational costs.

This project aims to develop an automated solution that processes authentication logs, identifies suspicious login patterns, enriches events with asset information and applies appropriate network controls.

The system will also ensure that enforcement actions are authorised, secure, traceable and reversible.

## Project Scope and Objectives

* Detect hostile remote login activity from Linux authentication logs.
* Aggregate failed login attempts within configurable time windows.
* Enrich authentication events using asset inventory information.
* Apply risk-based thresholds according to asset business criticality.
* Reduce unnecessary SIEM processing through event pre-correlation.
* Generate structured security summaries and alerts.
* Apply allowlists and security policies before enforcement.
* Automatically apply reversible network controls to Cisco IOS XE devices.
* Maintain audit records of successful and unsuccessful enforcement actions.
* Ensure the system is secure, reliable and properly tested.

## System Architecture

The system consists of three main functional components:

# 1 Log Preprocessor

The preprocessor reads Linux authentication logs, including rotated and compressed files.
Its responsibilities include:

* Reading multiple authentication log files.
* Identifying failed remote login attempts.
* Grouping events by host, source IP address and time window.
* Enriching events with asset information.
* Calculating thresholds based on asset criticality.
* Generating summary records and alert flags.
* Saving summaries as JSONL files or sending them through HTTPS.

# 2 Asset Inventory

The asset inventory stores essential information about network hosts to support security decisions.
The inventory includes:

* Hostname.
* Primary IP address.
* Environment.
* Owner.
* Function.
* Business criticality.

The information will be accessed through a CSV export or a read-only HTTP endpoint.

# 3 Policy-Enforcer Service

The policy-enforcer receives security alerts and determines whether network enforcement is required.
Its responsibilities include:

* Consulting the asset inventory.
* Checking allowlists.
* Applying risk modifiers.
* Selecting appropriate network control points.
* Validating enforcement requests.
* Communicating securely with Cisco IOS XE devices.
* Applying reversible network controls.
* Recording enforcement actions for auditing.
* Removing temporary controls when their time-to-live (TTL) expires.

### System Workflow

. Linux authentication logs are collected.
. The preprocessor reads and analyses the logs.
. Failed login attempts are grouped into time windows.
. Asset information is retrieved to enrich the events.
. Thresholds are calculated according to asset criticality.
. Summary records and alerts are generated.
. The policy-enforcer receives the alerts.
. Allowlist and risk policies are checked.
. The enforcement request is validated.
. The Cisco Driver applies the approved network control in a simulated environment.
. The action is recorded for auditing.
. Temporary controls are automatically removed when their TTL expires.

### Technologies and Tools

Technology / Tool	        |     |Application
----------------------------------------------------     
Python	                  | Core application development
Linux                     |	Authentication log source and application environment
Gzip	                    | Processing compressed log files
Regular Expressions	      | Extracting information from authentication logs
JSON / JSONL	            | Structured event and alert representation
CSV	                      | Asset inventory
HTTPS	                    | Secure communication
Cisco IOS XE	            | Target network infrastructure
RESTCONF	                | Network device configuration
HMAC	                    | Request authentication and integrity
Git and GitHub	          | Version control and team collaboration
Pytest	                  | Automated testing
CI/CD	                    | Automated testing and development checks

### Security Requirements

Security is a priority throughout the project.
The system will implement the following security measures:

* Encrypted communication between components.
* Least-privilege access for device and data-store accounts.
* Secure storage of secrets outside the source code.
* Input validation to prevent command injection.
* Replay protection for enforcement requests.
* Duplicate alert handling and idempotent operations.
* Authentication and integrity verification using HMAC.
* Protection of sensitive information in application logs.
* Audit logging of network enforcement activities.
* Reversible controls with clearly defined expiry times.

### Reliability and Performance
The system will be designed to provide reliable and efficient operation through:

* Clear error messages.
* Input validation.
* Network timeouts.
* Retry mechanisms with back-off.
* Idempotent network operations.
* Read-before-write configuration checks.
* Rate-limiting per device.
* Controlled concurrency.

### Testing and Validation
The project will use automated testing to verify the functionality and security of individual components and the complete system.
Testing will include:

* Unit testing of log parsing and aggregation.
* Testing of threshold calculations.
* Testing of allowlists and policy decisions.
* API validation and HMAC testing.
* Replay and duplicate request testing.
* Integration testing between components.
* Simulated network enforcement testing.
* Verification of automatic control expiry and rollback.
* Static code analysis and dependency checks.
* Software Bill of Materials (SBOM) generation.

A Continuous Integration (CI) workflow will automatically run tests whenever changes are pushed or submitted through pull requests.

### Team Responsibilities
The project is divided among six team members.

/Team Member /	            /  Role   /                              /	Main Responsibilities/
Rofiat (A)  |	Project Manager and Integration Lead	| Project coordination, repository management, shared utilities, documentation and integration
Aisha (B)  |	Log Preprocessor Developer	          | Log reading, parsing, aggregation and event summaries
Ismael (C)  |	Policy Engine Developer	              | Asset inventory loading, allowlists and risk-based policy decisions
Eunice (D)  |	Enforcer API Developer	              | API development, request validation, HMAC and replay protection
Sukhdeep (E) | Cisco Driver Developer	              | Mock router, RESTCONF, network controls and rollback
Swatha (F)  |	Testing and Security Lead	            | Unit testing, integration testing and security checks

### Repository Structure
The repository is organised into the following folders:

* common/ – Shared configuration, logging and secrets management.
* preprocessor/ – Authentication log processing and aggregation.
* policy_engine/ – Asset inventory and security policy decisions.
* enforcer_api/ – API endpoints and request validation.
* cisco_driver/ – Cisco device communication and simulated enforcement.
* tests/ – Unit, integration and security tests.
* .github/workflows/ – Automated testing and CI configuration.

### Development and Collaboration
The team will follow a modular development approach, with each member responsible for an assigned component.
GitHub will be used for:

* Source code management.
* Project documentation.
* Task allocation and progress tracking.
* Code reviews and pull requests.
* Collaboration between team members.

Team members will provide regular progress updates, commit their work with meaningful commit messages and coordinate integration activities.

Component interfaces and data formats will be agreed early to ensure that individual modules work together correctly.

13. Project Monitoring and Integration

Weekly progress will be monitored through team meetings and progress updates.

The Project Manager and Integration Lead will:

* Monitor task completion.
* Identify delays and development challenges.
* Coordinate support and redistribute tasks when necessary.
* Ensure that component interfaces are agreed.
* Coordinate integration testing.
* Monitor project milestones and deliverables.

Integration testing will verify the complete workflow, from authentication log processing to simulated network enforcement and automatic rollback.

14. Documentation and Expected Deliverables

The project documentation will include:

* Quick-start instructions for running the preprocessor and enforcer.
* Deployment and configuration runbook.
* Troubleshooting guidance.
* Network enforcement rollback instructions.
* System architecture and data-flow diagrams.
* Enforcement lifecycle diagram.

Expected deliverables include:

1. A functional log preprocessing component.
2. An asset inventory.
3. A policy-enforcer service.
4. A simulated Cisco network enforcement environment.
5. Automated unit and integration tests.
6. A Continuous Integration workflow.
7. Security testing evidence and an SBOM.
8. Project documentation and operational runbooks.
9. A final project demonstration and report.

## Project Gantt Chart

The Gantt chart below provides an overview of the project schedule, including activities, task allocation, planned start and end dates, and project progress.

Click here to view the Automated Threat Enforcement System Gantt Chart⁠|
https://github.com/Rofiat05/Automated-threat-enforcement-system/blob/main/Gantt%20Chart%20for%20Group.xlsx
