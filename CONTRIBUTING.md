# Contributing to ZKTrace

Thank you for your interest in contributing to **ZKTrace**! ZKTrace is an enterprise-grade, open-source Zero-Knowledge Cryptographic Audit Trail system for AI Agents utilizing the Model Context Protocol (MCP).

To maintain high code quality, strict security standards, and seamless collaboration, all contributors must adhere to the following guidelines.

---

## 1. Code of Conduct

All contributors and maintainers are expected to uphold the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to `security@zktrace.io` (or maintainer contact).

---

## 2. Git Branching Strategy

We enforce a strict Git Flow / Trunk-Based hybrid workflow:

- `main`: **Production-ready, stable releases only.** Every commit to `main` is tagged with a SemVer version (`vX.Y.Z`). Direct pushes are forbidden.
- `develop`: **Integration branch.** All active feature branches and bug fixes merge into `develop` via pull requests.
- `feature/<feature-name>`: Isolated feature branches created from `develop` (e.g., `feature/poseidon-circuit`, `feature/mcp-interceptor`).
- `fix/<bug-name>`: Bug fix branches branched from `develop` (e.g., `fix/proof-deserialization`).
- `hotfix/<hotfix-name>`: Urgent production patches branched directly from `main` and merged into both `main` and `develop`.

---

## 3. Commit Message Standards (Conventional Commits)

All commits MUST follow the [Conventional Commits v1.0.0](https://www.conventionalcommits.org/) specification.

### Format
```text
<type>(<scope>): <short summary>

[optional body explaining motivation and architectural context]

[optional footer(s), e.g., Closes #123]
```

### Allowed Types
- `feat`: A new feature or cryptographic capability.
- `fix`: A bug fix or security patch.
- `perf`: A code change that improves performance or reduces constraint count.
- `refactor`: Code change that neither fixes a bug nor adds a feature.
- `test`: Adding missing tests or correcting existing tests (Must maintain >= 80% coverage).
- `docs`: Documentation updates only.
- `chore`: Build process, dependency updates, tooling, or CI updates.
- `ci`: Changes to CI/CD workflows and configuration scripts.

### Examples
- `feat(circuit): implement range proof constraint for tool parameters`
- `fix(ledger): correct Merkle path computation for left-balanced leaves`
- `perf(prover): optimize multi-scalar multiplication (MSM) in BN254 batch prover`

---

## 4. Development Workflow & Micro-Stepping

1. **Fork and Branch**: Clone the repository and branch from `develop`.
2. **Implement Iteratively**: Keep Pull Requests focused and granular (Micro-Stepping).
3. **Format & Lint**:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   ```
4. **Run Unit & Integration Tests**:
   ```bash
   cargo test --all-features --workspace
   ```
5. **Enforce Test Coverage**: Ensure all new core cryptographic circuits and business logic maintain **>= 80%** test coverage.
6. **Open a Pull Request**: Target the `develop` branch using our [PR Template](.github/PULL_REQUEST_TEMPLATE.md).

---

## 5. Security & Cryptographic Review

Any changes touching zero-knowledge circuits, cryptographic primitives, serialization formats, or policy verification logic require:
- Explicit constraint satisfaction analysis (preventing under-constrained circuits).
- Zero-knowledge soundness and completeness review.
- Constant-time verification audits where applicable.

---

## 6. Licensing

By contributing to ZKTrace, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).
