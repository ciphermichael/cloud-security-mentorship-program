# Contributing

## Pull Request Process
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-check-name`
3. Write your security check or detection rule
4. Add tests in `tests/`
5. Ensure all checks pass: `pytest && bandit -r src/`
6. Submit a PR with a description of the security issue addressed

## Adding a New Security Check
```python
# In the appropriate project src/checks/ file:
def check_your_finding(client) -> list:
    findings = []
    # ... your detection logic ...
    findings.append(format_finding(
        severity="HIGH",
        check_id="YOUR-001",
        resource="arn:...",
        description="What is wrong",
        remediation="How to fix it"
    ))
    return findings
```

## Code Style
- Python: PEP 8, type hints where possible
- All findings must use `format_finding()` from `shared/utils/aws_helpers.py`
- Each check must have a clear `check_id`, `severity`, and `remediation`

## Security
- Never commit real credentials or access keys
- Use `.env` files (listed in `.gitignore`) for local testing
- All test AWS accounts should use read-only IAM roles
