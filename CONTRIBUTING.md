# Contributing Guidelines

We welcome contributions. To ensure efficient and meaningful review, the following minimum requirements apply.

---

## 1. Change Type & Verifiable Statement

Every pull request must clearly declare its type and provide appropriate justification.

### Supported PR Types

- **Bug Fix**
  A PR that fixes a reproducible and verifiable issue.

- **Feature / Enhancement**
  A PR that introduces new functionality or improves existing behavior without fixing a bug.

- **Refactor**
  A PR that changes internal implementation without changing external behavior.

- **Documentation**
  A PR that only affects documentation.

- **Other**
  For changes that do not fit the categories above (must be explained clearly).

---

### 1a. Requirements for Bug Fixes

Bug-fix PRs must include **verifiable evidence of the issue**, such as:

- a reproducible test case
- compiler or sanitizer output (e.g. ASan, UBSan)
- clearly demonstrable incorrect behavior in the existing code
- or a reliable technical reference

Speculative statements (e.g. “might be unsafe”, “could be NULL”) are not sufficient without proof.

---

### 1b. Requirements for Features

Feature PRs must include a clear description of:

- what new functionality is introduced
- why the change is useful
- how the behavior changes for users or callers

If applicable, feature PRs should also include tests or usage examples.

---

### 1c. Requirements for Refactoring

Refactoring PRs must ensure:

- no change in external behavior unless explicitly stated
- justification for structural changes (readability, performance, maintainability, etc.)
- tests remain valid or are updated accordingly

---

## 2. Human Review Required

Automatically generated or assisted changes (including AI-assisted contributions) must be **reviewed and validated by a real person before submission**.

The contributor is responsible for ensuring that:

- the proposed change is technically correct
- the issue description has been independently verified
- the change is not based on speculation or unverified assumptions

---

## 3. No Substantive Value → No Merge

Pull requests that:

- only contain cosmetic or non-functional changes
- address issues that are not demonstrably valid
- or do not provide a verifiable improvement

may be closed without further discussion.

---

## 4. Review Policy

PRs that do not meet the above requirements may be **closed without entering a full review cycle**, in order to protect maintainers’ time and keep the project maintainable.
