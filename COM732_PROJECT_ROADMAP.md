### PROJECT ROADMAP AND DEVELOPMENT TIMELINE FOR COM732 AUTOMATED-THREAT-ENFORCEMENT-SYSTEM PROJECT

### Project Overview

This roadmap outlines the main phases, activities, responsibilities and deadlines for the Automated Threat Enforcement System project (COM 732). It provides a shared timeline to help all team members monitor progress, coordinate tasks and complete the project before the submission deadline.

### Project Team and Responsibilities
Member                                                            Main Responsibilities

Rofiat

A – Project Manager and Integration Lead                 Repository and folder structure, WBS, Gantt chart, roadmap, shared utilities, coordination and integration


Aisha

B – Preprocessor                                         Log reader, parser, time-window counting, thresholds, JSON summaries and unit tests


Ismael

C – Policy Engine                                        CSV inventory loader, allowlist, risk rules, control-point selection and safety limits


Eunice

D – Enforcer API                                         API endpoint, schema validation, HMAC verification, replay protection and duplicate checks


Sukhdeep

E – Cisco Driver                                         Mock router, RESTCONF client, block operations, retries, expiry and rollback


Swatha

F – Test and Security Lead                               Pytest, CI testing, integration and performance tests, security scans, SBOM and checksums.


### Project Development Timeline
##
### Phase 1: Project Planning and Setup Date: 29 October

Activities:

* Confirm project requirements and objectives.
* Create the shared GitHub repository.
* Establish the repository folder structure.
* Allocate responsibilities to all team members.
* Agree on component interfaces and communication methods.
* Prepare the WBS, and risk register.

Expected deliverables:

* Shared GitHub repository.
* Agreed team responsibilities.
* Initial project planning documents.

### Phase 2: Foundation and Basic Components Date: 30 October – 5 November

Activities:

* Create shared configuration, logging and secrets utilities.
* Establish the initial GitHub Actions CI workflow.
* Each member creates an initial version of their assigned component.
* Agree on sample inputs and expected outputs.

Expected deliverables:

* Shared utilities.
* Initial CI workflow.
* Component structures and sample data.

### Phase 3: Core Development Date: 6–12 November

Activities:

* Develop the log reader and parser.
* Implement the inventory and policy engine.
* Develop the secure enforcement API.
* Build the mock Cisco router and driver.
* Establish the test framework.
* Write unit tests alongside the implementation.

Expected deliverables:

* Working individual components.
* Initial unit tests.
* Updated technical documentation.

### Phase 4: System Integration Date: 13–17 November

Activities:

* Connect the preprocessor, enforcer API, policy engine and Cisco driver.
* Test communication between components.
* Run an end-to-end test from log input to simulated blocking.
* Test automatic expiry and rollback.
* Identify and resolve integration problems.

Expected deliverables:

* Integrated system.
* Successful end-to-end demonstration.
* Integration test evidence.

### Phase 5: Final Testing and Submission Preparation Date: 18–20 November

Activities:

* Complete functional, security and performance testing.
* Fix identified defects.
* Generate SBOM and SHA-256 checksums.
* Complete project documentation and user guide.
* Rehearse the project demonstration.
* Prepare the final report and presentation.

Expected deliverables:

* Tested project.
* Security and performance reports.
* Final documentation.
* Presentation and submission materials.

### Progress Monitoring
##
The project team will monitor progress through:

* Regular team meetings.
* GitHub commits and pull requests.
* Updates to the project task board.
* Review of outstanding tasks and deadlines.
* Recording of decisions, challenges and completed activities.

Each team member is expected to provide regular progress updates, communicate any difficulties and complete assigned tasks within the agreed timeframe.

### Project Completion Target
##
The target completion date is 20 November 2026. All members are expected to complete their assigned responsibilities and contribute to the final testing, documentation and presentation before this date.
