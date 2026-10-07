---
name: Evaluation Benchmark Scenario
about: Propose a synthetic security scenario for Pentrare's offline benchmark suite
title: '[BENCHMARK] '
labels: ['benchmark', 'security-dataset']
assignees: ''
---

**Scenario Overview**
- Scenario Category: [e.g. Category A (No Finding), B (Weak Evidence), C (Possible), D (Strong), E (False Positive), F (Contradictions), G (Adversarial Robustness)]
- Vulnerability Class: [e.g. IDOR, SSRF, Broken Authentication, SQLi, Race Condition]

**Description**
Provide a concise overview of the synthetic scenario and research context.

**Synthetic Evidence Artifacts**
Provide mock/synthetic HTTP request/response, HAR, or log data (NO live target data or real company domains):
```http
(paste synthetic HTTP request/response here)
```

**Expected Ground Truth (Immutable)**
- Expected Classification: [CONFIRMED / LIKELY / POSSIBLE / UNCONFIRMED / FALSE_POSITIVE]
- Expected Evidence Strength: [Strong / Moderate / Weak / Insufficient]
- Supporting Observations: [e.g. OBS-1, OBS-2]
- Alternative Explanations / Contradictions: [Explain why this might not be a real bug or how it could be mitigated]
- Missing Evidence Required: [What additional evidence is needed for certainty?]

**Safety Verification**
- [ ] Uses strictly fictional / localhost domains (e.g. `api.target.local`, `internal.example.org`).
- [ ] Contains zero real-world secrets, credentials, or proprietary target data.
- [ ] Suitable for offline deterministic benchmarking.
