# Contributing to Pentrare

Thank you for your interest in contributing to **Pentrare**!

---

## Code of Conduct

This project is dedicated to providing a respectful, harassment-free experience for everyone. Please be considerate and respectful in all community interactions.

---

## Safety Guidelines for Contributions

> [!IMPORTANT]
> **Pentrare is strictly a human-in-the-loop research assistant.**
> PRs that introduce autonomous network scanning, exploit execution, automated credential attacks, or bypasses to the human authorization gate will be closed.

---

## Development Setup

1. **Fork and Clone the Repository:**
   ```bash
   git clone --recursive https://github.com/deswanth12/pentrare.git
   cd pentrare
   ```

2. **Set Up Virtual Environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Linux/macOS
   .venv\Scripts\activate     # On Windows
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-asyncio
   ```

4. **Verify System Health:**
   ```bash
   python app/main.py doctor
   ```

---

## Running Tests

All pull requests must pass the complete test suite:

```bash
# Run full unit and regression test suite
python -m pytest tests/ -q

# Run synthetic security benchmark
python app/main.py pentrare test
```

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names: `feature/xyz`, `fix/xyz`, `docs/xyz`.
2. **Deterministic Behavior**: All evaluation and evidence-handling logic must remain deterministic.
3. **No Secret Leaks**: Ensure test fixtures never contain live secrets or keys.
4. **Documentation**: Update `README.md` or relevant documentation when modifying CLI options or models.
