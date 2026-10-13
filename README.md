# 🔴 RedChain

**Autonomous Multi-Turn Red-Teaming Engine for AI Agents**

RedChain is an automated penetration testing framework designed to discover security vulnerabilities in agentic AI workflows. It targets the **OWASP Top 10 for Agentic AI (ASI01–ASI05)** by running multi-turn adaptive attacks, scoring responses with high precision, and generating forensic audit traces.

---

## ⚡ Quick Start

### Installation
```bash
git clone https://github.com/Vibho1/RedChain.git
cd RedChain
pip install -e .
```

### Running an Attack
```bash
# Start your target agent (or mock vulnerable agent):
python tests/fixtures/mock_target_agent.py

# Launch RedChain attack:
redchain run --target http://localhost:8001 --strategy direct_hijack --max-turns 4 --forbidden-tools send_email
```

### Viewing Reports
```bash
# List all audit reports:
redchain list

# Inspect a specific report:
redchain show <session_id>
```

---

## 🛡️ OWASP Agentic AI Coverage
- **ASI01**: Goal Hijacking / System Prompt Override
- **ASI02**: Tool Misuse & Unauthorized Tool Invocation
- **ASI03**: Memory Poisoning & Cross-Turn Persistence
- **ASI04**: Privilege Escalation
- **ASI05**: Sensitive Data Exfiltration & Context Leaks

---

## 📄 License
MIT
