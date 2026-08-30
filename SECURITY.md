# Security Policy

The ZKTrace team takes the security and integrity of our cryptographic audit trail system, zero-knowledge circuits, and proxy interceptors with the highest priority.

---

## 1. Supported Versions

Security updates and patches are actively maintained for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability, cryptographic flaw, or potential exploit in ZKTrace (including under-constrained circuits, soundness breaches, replay attacks, or data leaks), please follow responsible disclosure guidelines.

**DO NOT file a public GitHub Issue for security vulnerabilities.**

### Disclosure Process
1. **Email**: Send your vulnerability report directly to `security@zktrace.io` (or maintainers via private GPG/encrypted email).
2. **Details to Include**:
   - Component / Module affected (e.g., `zktrace-core`, `zktrace-circuits`, `zktrace-mcp-proxy`).
   - Detailed description of the vulnerability, including attack vectors and potential impact.
   - Proof of Concept (PoC) code or script demonstrating the vulnerability.
   - Any suggested mitigations or fixes.
3. **Response SLA**:
   - Initial acknowledgement: within **24 hours**.
   - Severity assessment & triage: within **48 hours**.
   - Patch delivery & advisory: within **7 business days** (depending on complexity).

---

## 3. Cryptographic Bug Bounty & Responsible Disclosure Guidelines

- Please provide sufficient time for the maintainers to release a fix before public disclosure.
- Do not attempt to access or tamper with third-party data or production deployments without authorization.
- We will credit all security researchers who adhere to responsible disclosure in our Security Advisories and Release Notes.
