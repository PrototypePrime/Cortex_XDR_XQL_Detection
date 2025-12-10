# Contributing to Cortex XDR XQL Detection Library

First off, thank you for considering contributing! This library relies on security practitioners like you to stay ahead of emerging threats.

## 🤝 How to contribute

### 1. Add a New Detection
1.  **Fork** the repository.
2.  **Create** a branch: `git checkout -b detection/T1234-my-detection`
3.  **Copy** one of the templates:
    *   `templates/TEMPLATE_BIOC_Rule.xql` (For active BIOC rules)
    *   `templates/TEMPLATE_Threat_Hunting.xql` (For hunting queries)
4.  **Write** your XQL logic.
5.  **Test** it! (See Testing Guidelines below).
6.  **Push** and submit a Pull Request.

### 2. Improve Existing Detections
*   Found a logic error?
*   Have a better way to filter false positives?
*   Want to add missing exclusions?
*   **PRs are welcome!**

---

## 🧪 Testing Guidelines

We aim for **production-ready** code. Please verify the following before submitting:

*   **Syntax**: Does the XQL run in the XDR Query Builder?
*   **Performance**: Do you use `filter` early? Avoid complex `alter` operations on full datasets.
*   **Fields**: Do you use standard XDR schema (`actor_process_image_name`, `agent_hostname`)?
*   **Documentation**: Did you fill out the Description and False Positives sections?

---

## 📝 Pull Request Template

When submitting a PR, please provide:

```markdown
## Detection Overview
- **Name**: [Name of detection]
- **MITRE Technique**: [T####]
- **Goal**: [What does this catch?]

## Testing Support
- [ ] I have tested this query in Cortex XDR.
- [ ] It returns results for the intended threat.
- [ ] It does NOT generate excessive noise.

## Screenshots (Optional)
[Paste screenshot of query builder results]
```
