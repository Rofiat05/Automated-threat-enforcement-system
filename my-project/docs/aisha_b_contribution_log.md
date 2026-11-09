# Contribution Entry 1 — Project Initialisation

**Date:** 28 October 2026

**Task:** Initial project and development environment setup

**What I implemented:**

* Created the initial COM732 project structure in VS Code.
* Created separate folders for the preprocessor, sample data, tests and documentation.
* Created a Python virtual environment (`.venv`) for the project.
* Configured VS Code to use the project's virtual environment.
* Verified that Python 3.14.8 was running from the project virtual environment.
* Created a `.gitignore` file to prevent the virtual environment and Python-generated files from being committed.
* Initialised a local Git repository for version control.
* Created a personal contribution log to record my development activities and evidence.
* Created the initial project README.
* Created the first Git commit as a baseline for subsequent development.

**Reason for the work:**
I established a controlled and reproducible development environment before beginning implementation of the preprocessor. Version control was also established early so that my individual development activities and progress can be evidenced through meaningful commits.

**Testing/Verification:**

* Confirmed that the virtual environment could be activated successfully.
* Confirmed Python 3.14.8 was available within the virtual environment.
* Confirmed that `where.exe python` identified the project's `.venv\Scripts\python.exe` as the active Python interpreter.
* Confirmed that `.venv` was excluded from Git tracking through `.gitignore`.
* Confirmed that the initial project files were successfully committed.

**Git commit:**
`chore: initialize COM732 project structure`

**Evidence:**

* VS Code project structure
* Active `.venv` environment
* Git repository status
* Initial Git commit

### Contribution Entry 2 — Log Reader and Parser Development

**Date:** 29 October 2026

**Task:** Development and testing of Linux authentication log reader and parser.

**What I implemented:**

* Continued development of the authentication log preprocessor.
* Implemented the functionality for reading Linux authentication log entries.
* Worked on extracting relevant information from individual authentication events.
* Developed parsing logic to identify authentication event types, including successful and failed login attempts.
* Extracted relevant attributes such as usernames, source IP addresses and source ports.
* Worked on supporting both ordinary text-based log files and compressed `.gz` log files.
* Organised the implementation into separate Python modules to improve maintainability.

**Reason for the work:**

The log reader and parser form the foundation of my assigned component. Before authentication events can be analysed or grouped, raw log entries must first be read and converted into structured information that other components can process.

**Testing/Verification:**

* Tested the log-reading functionality.
* Verified that authentication entries could be extracted from sample logs.
* Confirmed that failed and successful login attempts were correctly identified.
* Examined the parsed output to ensure relevant attributes were extracted.

**Evidence:**

* `log_reader.py`
* Parser implementation.
* Terminal output showing successfully parsed authentication events.
* Sample authentication log files.

---

### Contribution Entry 3 — Authentication Event Aggregation

**Date:** 30 October 2026

**Task:** Development of authentication event aggregation functionality.

**What I implemented:**

* Developed the aggregation functionality for processing parsed authentication events.
* Implemented grouping of failed authentication attempts.
* Designed the grouping logic around relevant attributes, including hostname and source IP address.
* Introduced a fixed five-minute aggregation window.
* Worked on identifying repeated failed authentication attempts originating from the same source.
* Incorporated threshold-based detection logic into the aggregation process.

**Reason for the work:**

Individual failed login events may not independently indicate a security incident. However, repeated authentication failures within a short period can indicate password guessing or brute-force activity. Aggregation allows the preprocessor to identify patterns that would otherwise be difficult to recognise from individual log entries.

**Testing/Verification:**

* Tested the aggregation functionality using sample authentication events.
* Examined how multiple failed login attempts were grouped.
* Verified that events were grouped according to their relevant attributes and time windows.

**Evidence:**

* Aggregation module.
* Sample authentication events.
* Terminal output from aggregation tests.

---

### Contribution Entry 4 — Threshold-Based Detection and Aggregation Testing

**Date:** 31 October 2026

**Task:** Refinement and testing of authentication event aggregation and threshold-based detection.

**What I implemented:**

* Continued refining the aggregation module.
* Incorporated asset criticality into the detection threshold mechanism.
* Implemented different authentication failure thresholds for different asset criticality levels.
* Worked with the following prototype threshold configuration:

  * Critical assets: 3 failed attempts.
  * High-priority assets: 5 failed attempts.
  * Medium-priority assets: 8 failed attempts.
  * Low-priority assets: 10 failed attempts.
* Implemented alert identification when the relevant failure threshold was reached.
* Reviewed the interaction between parsed authentication events and the aggregation component.

**Reason for the work:**

Different assets have different security requirements and levels of importance. A critical system should generally trigger an alert after fewer suspicious authentication attempts than a less critical system. This approach makes the detection mechanism more context-aware.

**Testing/Verification:**

* Successfully tested the aggregation functionality.
* Verified that repeated failed authentication attempts could trigger the expected alert condition.
* Checked the relationship between asset criticality and detection thresholds.
* Confirmed that the aggregation component worked with the parsed authentication events.

**Evidence:**

* Aggregation implementation.
* Threshold configuration.
* Test outputs demonstrating grouped authentication failures and alert identification.

---

### Contribution Entry 5 — JSONL Output Implementation

**Date:** 1 November 2026

**Task:** Implementation and testing of structured JSON Lines output.

**What I implemented:**

* Developed the output functionality for the authentication log preprocessor.
* Implemented JSON Lines (JSONL) output for aggregated authentication events.
* Worked on converting aggregation results into structured JSON records.
* Ensured that individual output records could be represented as separate JSON objects.
* Organised the output functionality into a separate module.
* Tested the interaction between the log reader, parser, aggregation component and output functionality.

**Reason for the work:**

The preprocessor needs to produce structured information that can be consumed by other components of the wider security monitoring system. JSONL provides a convenient format for representing individual event summaries and supporting subsequent processing.

**Testing/Verification:**

* Successfully tested the JSONL output functionality.
* Verified that aggregation results could be converted into structured output.
* Tested the output stage independently and alongside the other preprocessor components.
* Confirmed that the JSONL implementation was functioning as expected.

**Evidence:**

* JSONL output module.
* Generated JSONL records.
* Terminal output from successful tests.
* Sample structured output files.

---

### Contribution Entry 6 — Component Integration and Functional Review

**Date:** 2 November 2026

**Task:** Review of the preprocessor development stages and component integration.

**What I worked on:**

* Reviewed the implementation of the authentication log reader.
* Examined the parser and its ability to extract authentication information.
* Reviewed the aggregation functionality and its threshold-based detection mechanism.
* Examined the JSONL output stage.
* Considered the flow of information between the different modules.
* Reviewed the separation of responsibilities between the individual components.

**Reason for the work:**

As the preprocessor consists of several interconnected modules, it is important to understand how information moves through the implementation. Reviewing the individual components helps identify inconsistencies and ensures that the overall design remains organised and maintainable.

**Testing/Verification:**

* Reviewed the previously completed reader, parser, aggregator and output tests.
* Examined the expected data flow between the modules.
* Confirmed the completion of the JSONL development stage.

**Evidence:**

* Existing module implementations.
* Previous test outputs.
* Project directory structure.

---

### Contribution Entry 7 — HTTP Integration Research and Development Planning

**Date:** 3 November 2026

**Task:** Investigation and planning of HTTP-based communication for preprocessor integration.

**What I worked on:**

* Reviewed the requirements for communicating preprocessor output to other components.
* Examined the role of HTTP-based communication in system integration.
* Studied how structured JSON data can be transmitted through HTTP requests.
* Investigated the use of Python's standard library for making HTTP requests.
* Examined the importance of HTTPS for protecting transmitted information.
* Considered security requirements such as TLS certificate verification, request timeouts and error handling.
* Reviewed how the existing JSONL output stage relates to the proposed HTTP integration.

**Reason for the work:**

The preprocessor must be capable of producing information that can be consumed by other parts of the wider system. Understanding HTTP communication and secure transmission is therefore important when considering integration beyond local file-based output.

**Testing/Verification:**

* Reviewed the proposed HTTP communication approach.
* Examined the proposed HTTPS implementation design.
* Identified the remaining implementation and testing requirements.

**Evidence:**

* HTTP/HTTPS development notes.
* Project requirements.
* Proposed HTTP sender implementation.

**Development status:** HTTP/HTTPS functionality remains subject to implementation verification and testing.

---

### Contribution Entry 8 — Review of Individual Progress and Next Development Stage

**Date:** 4 November 2026

**Task:** Review of completed development activities and preparation for continued implementation.

**What I worked on:**

* Reviewed the development progress made since initial projectisation.
* Examined the structure and responsibilities of the individual Python modules.
* Reviewed the functionality of the authentication log reader and parser.
* Reviewed the aggregation and threshold-based detection mechanisms.
* Confirmed the successful completion of the JSONL output stage.
* Identified HTTP/HTTPS communication as the next development area requiring further implementation and verification.
* Reviewed the relationship between my assigned component and the wider COM732 project requirements.

**Reason for the work:**

Regular reviews are necessary to ensure that the implementation remains aligned with the assigned project responsibilities. This also helps identify outstanding development tasks and establish a clear direction for subsequent work.

**Testing/Verification:**

* Reviewed the existing implementation and test results.
* Identified completed and outstanding development activities.
* Established the next implementation stage.

**Evidence:**

* Current project source files.
* Existing test scripts.
* Project README.
* Individual contribution log.
* GitHub repository.

---

### Contribution Entry 9 — HTTPS Sender Implementation and Testing

**Date:** 5 November 2026

**Task:** Implementation and testing of HTTP/HTTPS communication functionality.

**What I implemented:**

- Continued development of the HTTP sender component responsible for transmitting preprocessed authentication summaries.
- Worked on the HTTPS communication functionality.
- Examined how structured JSON data could be transmitted to an external endpoint.
- Worked on the integration between the preprocessor output and the HTTP communication component.
- Reviewed the sender implementation to understand how the different functions contribute to secure data transmission.
- Conducted unit testing of the HTTPS sender functionality.

**Reason for the work:**

The preprocessor needs to make its output available to other components of the wider security monitoring system. HTTP-based communication provides a mechanism for transmitting structured authentication summaries, while HTTPS introduces encryption to protect information during transmission.

**Testing/Verification:**

- Successfully executed the HTTP sender test.
- Confirmed that the HTTP sender functionality was working as expected.
- Successfully executed the HTTPS sender unit tests.
- Confirmed that the HTTPS sender tests passed.

**Evidence:**
- HTTP sender implementation.
- HTTPS sender module.
- HTTP sender test output.
- Successful HTTPS unit test results.

---

### Contribution Entry 10 — JSONL Writer and Aggregation Module Testing

**Date:** 7 November 2026

**Task:** Functional testing and refinement of JSONL output and authentication event aggregation.

**What I implemented and worked on:**

**JSONL Writer:**

- Continued testing the JSON Lines output functionality.
- Tested the ability to write individual authentication summaries.
- Tested the ability to append multiple summaries to an output file.
- Examined the handling of invalid summary structures.
- Tested the rejection of values that could not be properly serialised into JSON.
- Verified the behaviour of the writer under different test conditions.

**Aggregation Module:**

- Returned to the aggregation component to conduct further testing.
- Tested the grouping of failed authentication attempts.
- Verified the relationship between the number of failed attempts and the configured detection thresholds.
- Tested the identification of suspicious authentication activity involving critical assets.
- Reviewed and corrected a sample log file path issue encountered during testing.
- Removed unnecessary debugging output from the implementation.

**Reason for the work:**

Testing individual modules is important to ensure that each component performs its intended function before wider integration. The JSONL writer must produce valid structured output, while the aggregator must correctly identify repeated authentication failures and determine when an alert should be generated.

**Testing/Verification:**

**JSONL Writer:**
- Successfully completed four unit tests.
- Test results: 4 tests passed.
- Confirmed successful handling of single and multiple summaries.
- Confirmed that invalid summaries and non-JSON-serialisable values were rejected appropriately.

**Aggregation Module:**
- Successfully completed eight aggregation unit tests.
- Verified that three failed authentication attempts against a critical asset triggered an alert.
- Confirmed that the configured critical asset threshold was three failed attempts.
- Verified the resulting aggregation summary, including the hostname, source IP, number of failed attempts, criticality, threshold and alert status.

**Issue encountered and resolved:**

During aggregation testing, a `FileNotFoundError` occurred because the test script was referencing the sample authentication log from an incorrect directory. I investigated the issue and corrected the relative file path to point to `../sample_data/auth.log`.

**Evidence:**
- JSONL writer source code.
- JSONL writer test results showing four successful tests.
- Aggregator source code.
- Aggregator test results showing eight successful tests.
- Terminal output showing the critical asset alert.
- Corrected sample log file path.

---

### Contribution Entry 11 — Authentication Log Preprocessor Review and Development Prioritisation

**Date:** 8 November 2026

**Task:** Review of preprocessor implementation and identification of outstanding development responsibilities.

**What I worked on:**

- Reviewed the progress of the individual authentication log preprocessor.
- Revisited the implementation of the Linux authentication log parser.
- Examined the regular expression approach being considered for extracting timestamps and other information from SSH authentication log entries.
- Investigated how timestamp information would be extracted from raw Linux authentication logs.
- Identified that the proposed timestamp parsing expression required further simplification and understanding before implementation could continue.
- Decided to temporarily postpone the timestamp parsing task to prioritise the remaining major responsibilities of the assigned component.
- Reviewed the existing reader, parser, aggregator, JSONL writer and HTTPS sender implementations.
- Considered the remaining development and integration requirements for Person B's contribution.

**Reason for the work:**

The preprocessor involves several interconnected responsibilities, and development must remain focused on completing the essential functionality of the assigned component. Reviewing the implementation and prioritising outstanding responsibilities helps prevent unnecessary complexity and ensures that development proceeds in a structured manner.

**Testing/Verification:**

- Reviewed the previously successful JSONL writer tests.
- Reviewed the eight successful aggregation unit tests.
- Confirmed the successful HTTPS sender testing completed earlier.
- Identified timestamp extraction and further integration work as areas requiring additional attention.

**Outstanding development considerations:**

- Simplification and completion of SSH authentication log timestamp parsing.
- Further validation of authentication event extraction.
- Review of plain-text and compressed log handling.
- Further testing of the complete preprocessor workflow.
- Verification of the integration between the individual modules.

**Evidence:**
- Current preprocessor source files.
- Existing parser implementation.
- JSONL writer test results.
- Aggregator test results.
- HTTPS sender test results.
- Development notes identifying outstanding tasks.

---

## Summary of Progress: 5–8 November 2026

During this reporting period, development focused primarily on testing and validating the individual modules of the Linux authentication log preprocessor.

The HTTPS sender functionality was successfully tested, while the JSONL writer completed four successful unit tests. Further testing of the aggregation component resulted in eight successful unit tests, alongside successful verification of the critical asset alert threshold.

An issue involving an incorrect sample log file path was also identified and resolved during aggregation testing.

By 8 November, the main development focus had shifted towards reviewing the remaining responsibilities, simplifying the timestamp parsing approach and preparing for further integration testing.

**Overall development status:** The main output and aggregation components have undergone successful testing. Further parser refinement and end-to-end integration remain outstanding.

