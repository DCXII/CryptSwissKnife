# Contributing to CryptoSwissKnife

We welcome contributions to the CryptoSwissKnife project! To ensure a smooth and effective collaboration, please follow these guidelines.

## How to Contribute

1.  **Fork the Repository**: Start by forking the `CryptoSwissKnife` repository to your GitHub account.
2.  **Clone Your Fork**: Clone your forked repository to your local machine.
    ```bash
    git clone https://github.com/your-username/CryptoSwissKnife.git
    cd CryptoSwissKnife
    ```
3.  **Create a New Branch**: Create a new branch for your feature or bug fix. Use a descriptive name.
    ```bash
    git checkout -b feature/your-feature-name
    # or
    git checkout -b bugfix/issue-description
    ```
4.  **Make Your Changes**: Implement your feature, fix the bug, or improve the documentation.
    *   Adhere to the existing code style and conventions.
    *   Write clear, concise, and well-documented code.
    *   Ensure your changes do not break existing functionality.
    *   Add or update tests as appropriate for your changes.
5.  **Test Your Changes**: Run the existing test suite and any new tests you've added.
    ```bash
    # Example: pytest
    pytest
    ```
6.  **Commit Your Changes**: Write clear and concise commit messages.
    ```bash
    git commit -m "feat: Add new feature X"
    # or
    git commit -m "fix: Resolve issue Y"
    ```
7.  **Push to Your Fork**: Push your new branch to your forked repository on GitHub.
    ```bash
    git push origin feature/your-feature-name
    ```
8.  **Create a Pull Request (PR)**:
    *   Go to the original `CryptoSwissKnife` repository on GitHub.
    *   You should see a prompt to create a new Pull Request from your recently pushed branch.
    *   Provide a detailed description of your changes, including why they are needed and what they accomplish.
    *   Reference any related issues.

## Code Style

Please try to match the existing code style. We use `ruff` for linting and `black` for formatting.

## Reporting Bugs

If you find a bug, please open an issue on GitHub. Provide as much detail as possible, including:
*   A clear and concise description of the bug.
*   Steps to reproduce the behavior.
*   Expected behavior.
*   Screenshots or error messages if applicable.
*   Your operating system and Python version.

## Feature Requests

For new features or enhancements, please open an issue first to discuss the idea before submitting a pull request. This helps ensure that the feature aligns with the project's goals and avoids duplicate work.

Thank you for contributing!
