# Contributing to Agentic AI Security and Governance

First off, thank you for considering contributing to this project! It's people like you that make the open-source community such a great place to learn, inspire, and create.

## How Can I Contribute?

### Reporting Bugs
* Ensure the bug was not already reported by searching on GitHub under Issues.
* If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a title and clear description, as much relevant information as possible, and a code sample or an executable test case demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements
* Open a new issue with a clear title and description.
* Explain why this enhancement would be useful to most users.
* For security-related enhancements, please consider whether discussing it publicly introduces risk. If so, follow standard responsible disclosure practices.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests to the `agentsecgov/tests/` directory.
3. Ensure the test suite passes by running:
   ```bash
   python -m unittest discover -s agentsecgov/tests
   ```
4. Make sure your code aligns with the core architectural principle of this repository: **All tool invocations must pass through the Policy Engine security boundary before execution.** Do not bypass the `execute_tool` gateway.
5. Issue that pull request!

## Local Development Setup

1. Clone the repository locally.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. To test with the live LangChain planner, copy `.env.example` to `.env` and add your `OPENAI_API_KEY`.
4. Start the local server for testing:
   ```bash
   python run.py
   ```

## Security Guidelines

Because this is a security and governance framework, any pull requests that modify the `PolicyEngine`, `PIIRedactor`, or `GovernedAgent` will be subject to strict review to ensure they do not introduce bypass vulnerabilities or prompt injection vectors. 

Thank you for contributing!
