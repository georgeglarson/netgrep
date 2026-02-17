# Contributing to netgrep

Thank you for your interest in contributing to netgrep!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/netgrep.git`
3. Create a feature branch: `git checkout -b my-feature`
4. Make your changes
5. Submit a pull request

## Prerequisites

- Rust 1.85+ (edition 2024)
- `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (RHEL/Fedora)

## Development Workflow

Before submitting a PR, ensure all checks pass:

```bash
cargo fmt --check          # Code formatting
cargo clippy -- -D warnings  # Lint checks
cargo test                 # All tests pass
```

## Code Conventions

- **One concern per module** — when a file accumulates multiple responsibilities, extract the distinct concern into its own module
- Use `anyhow::Result` in application code, `thiserror` for library-style errors
- Prefer `etherparse` Slice types (zero-copy) over owned Header types
- Avoid unnecessary abstractions — three similar lines are better than a premature helper function
- Keep functions focused and small

## Pull Request Process

1. Ensure your branch is up to date with `master`
2. All CI checks must pass (`fmt`, `clippy`, `test`)
3. Add tests for new functionality
4. Update CHANGELOG.md for user-visible changes
5. Keep PRs focused — one feature or fix per PR

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- OS, Rust version, libpcap version
