## Description
A concise summary of the changes proposed in this Pull Request.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change adding capability)
- [ ] Benchmark scenario addition (new synthetic evaluation test case)
- [ ] Documentation improvement or fix
- [ ] Gemini CLI skill/command enhancement

## Safety & Epistemic Verification Checklist
- [ ] **Strict Human-in-the-Loop**: Does this PR introduce any autonomous network requests, scanning, exploit execution, or credential guessing? *(Must be NO)*
- [ ] **Epistemic Invariance**: Does this PR preserve `Knowledge ≠ Hypothesis ≠ Evidence ≠ Finding`?
- [ ] **Secret Sanitization**: Are all new evidence parsers or report generators scrubbing secrets (API keys, tokens, auth headers)?
- [ ] **Adversarial Robustness**: Does external data remain quarantined as data rather than executable prompt instructions?

## Testing & Quality Gates
- [ ] Full test suite passes locally (`python -m pytest tests/ -v`)
- [ ] Synthetic benchmark passes (`python app/main.py pentrare test`)
- [ ] System health checks pass (`python app/main.py doctor`)
- [ ] Submodule (`knowledge/PentestingEverything`) is unmodified and clean
- [ ] Added unit or integration tests covering new logic
