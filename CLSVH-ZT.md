# CLSVH-ZT Prototype (Cross-Layer Security Validation Header - Zero Trust)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Research prototype** demonstrating a security header for Zero Trust architectures with cross-layer validation, lineage tracking, and fast-path/slow-path decision making.

---

## 🎯 What is CLSVH-ZT?

CLSVH-ZT is a **Cross-Layer Security Validation Header** designed for **Zero Trust** network architectures. Think of it as a "security passport" that travels with each network request, carrying:

- **Trust level** (0-3): Earned through successful security validations
- **Lineage**: Complete audit trail of every security component that inspected this request
- **Path hint**: Suggests fast-path (trusted) or slow-path (detailed inspection) processing
- **Session/request correlation**: Links related requests for better visibility

### Why This Matters

Traditional security checks happen in isolation. CLSVH-ZT enables:
- ✅ **Cross-layer visibility**: Network, transport, and application layers share context
- ✅ **Zero Trust enforcement**: Start with zero trust, earn it through validation
- ✅ **Performance optimization**: Trusted requests can take fast-path processing
- ✅ **Forensic capabilities**: Complete lineage for incident investigation

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/clsvh-zt-prototype.git
cd clsvh-zt-prototype

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run Demos

```bash
# Demo 1: Fast vs Slow Path
python examples/demo_fast_slow_path.py

# Demo 2: Lineage Tracking
python examples/demo_lineage.py
```

### Run Tests

```bash
pytest tests/ -v
```

---

## 📁 Project Structure

```
clsvh-zt-prototype/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── clsvh_zt/                 # Main package
│   ├── __init__.py          # Package initialization
│   ├── header.py            # CLSVH header data model
│   ├── policy.py            # Security policy rules
│   ├── validator.py         # Component validation logic
│   └── simulator.py         # End-to-end request flow
├── examples/                 # Demo scripts
│   ├── demo_fast_slow_path.py
│   └── demo_lineage.py
└── tests/                    # Automated tests
    ├── test_header.py
    └── test_validator.py
```

---

## 🔧 Core Components

### 1. CLSVHHeader (`clsvh_zt/header.py`)

The core data structure representing the security header:

```python
from clsvh_zt.header import CLSVHHeader

# Create a new session
header = CLSVHHeader.create_new_session(path_hint="slow")

# Access header fields
print(f"Session: {header.session_id}")
print(f"Trust Level: {header.trust_level}")
print(f"Lineage: {header.lineage}")
```

**Key Fields:**
- `session_id`: Unique identifier for the user session
- `request_id`: Unique identifier for each request
- `trust_level`: 0 (untrusted) to 3 (highly trusted)
- `path_hint`: "fast" or "slow" processing suggestion
- `lineage`: List of components that validated this request

### 2. Security Policy (`clsvh_zt/policy.py`)

Defines decision rules for request processing:

```python
from clsvh_zt.policy import evaluate_path_policy

decision = evaluate_path_policy(header)
# Returns: "allow_fast", "allow_slow", or "block"
```

**Policy Logic:**
- `trust_level >= 2` + `path_hint="fast"` → `allow_fast` (skip deep inspection)
- Otherwise → `allow_slow` (full security checks)

### 3. Validator (`clsvh_zt/validator.py`)

Each security component (WAF, firewall, service) uses this to validate requests:

```python
from clsvh_zt.validator import CLSVHValidator

# Create validator for a component
waf = CLSVHValidator("WAF")

# Validate a request
decision = waf.validate_and_update(header, checks_passed=1)
# Header is updated with lineage and possibly trust level
```

**What Happens:**
1. Sanitizes trust level (ensures 0-3 range)
2. Applies policy to get decision
3. Updates lineage (e.g., "WAF:ok" or "Firewall:blocked")
4. May upgrade trust after sufficient validations

### 4. Simulator (`clsvh_zt/simulator.py`)

Demonstrates end-to-end request flow:

```python
from clsvh_zt.simulator import simulate_request_flow

# Simulate requests through WAF → Firewall → Service
final_header = simulate_request_flow(path_hint="slow")

print(f"Final trust: {final_header.trust_level}")
print(f"Total validations: {len(final_header.lineage)}")
```

---

## 📊 Example Output

### Demo 1: Fast vs Slow Path

```bash
$ python examples/demo_fast_slow_path.py

=== Demo: Fast vs Slow Path ===

1) Session with path_hint='slow'
Final trust_level: 2
Final path_hint: slow
Lineage: ['client', 'WAF:ok', 'Firewall:ok', 'Service:ok', ...]

2) Session with path_hint='fast'
Final trust_level: 2
Final path_hint: fast
Lineage: ['client', 'WAF:ok', 'Firewall:ok', 'Service:ok', ...]
```

### Demo 2: Lineage Tracking

```bash
$ python examples/demo_lineage.py

=== Demo: Lineage Tracking ===

Session ID: 0cfbca63-a6ac-45da-9e0b-4334c7526cfa
Final trust level: 2
Path hint: slow

Lineage (components that validated this session):
 1. client
 2. WAF:ok
 3. Firewall:ok
 4. Service:ok
 5. WAF:ok
 6. Firewall:ok
 7. Service:ok
 8. WAF:ok
 9. Firewall:ok
10. Service:ok
```

---

## 🧪 Testing

All components have automated tests:

```bash
$ pytest tests/ -v

tests/test_header.py::test_create_new_session PASSED
tests/test_header.py::test_promote_trust PASSED
tests/test_validator.py::test_validator_allows_requests PASSED
tests/test_validator.py::test_validator_upgrades_trust PASSED

4 passed in 0.05s
```

---

## 🏗️ Architecture

### Request Flow

```
Client Request
    ↓
[Create CLSVH Header]
    ↓
[WAF Validation] ──→ Update lineage, check policy
    ↓
[Firewall Validation] ──→ Update lineage, check policy
    ↓
[Service Validation] ──→ Update lineage, check policy
    ↓
[Trust Upgrade] ──→ If enough validations passed
    ↓
[Response to Client]
```

### Trust Evolution

```
Request 1: trust_level=0 → WAF:ok → Firewall:ok → Service:ok
Request 2: trust_level=0 → WAF:ok → Firewall:ok → Service:ok
Request 3: trust_level=0 → WAF:ok → Firewall:ok → Service:ok
    ↓
Total validations: 9
    ↓
Trust upgraded: 0 → 1 → 2
```

---

## 💡 Use Cases

### 1. Zero Trust Network Architecture
Implement progressive trust where requests earn higher privileges through repeated validation.

### 2. Security Audit & Forensics
Complete lineage tracking enables rapid incident investigation and compliance reporting.

### 3. Performance Optimization
Trusted sessions can bypass expensive deep packet inspection, improving throughput.

### 4. Multi-Layer Security Coordination
Share context between network, transport, and application security layers.

---

## 🔬 Research Context

This is a **research prototype** focused on concept validation, not production deployment. It demonstrates:

- ✅ Feasibility of cross-layer security headers
- ✅ Zero Trust implementation patterns
- ✅ Lineage tracking for audit trails
- ✅ Dynamic trust-based routing

**Potential Extensions:**
- Real network protocol integration (HTTP headers, TCP options)
- Advanced policy engines (ML-based anomaly detection)
- Distributed trust management across microservices
- Integration with existing frameworks (SPIFFE, OpenTelemetry)

---

## 📚 Learn More

### Related Concepts
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [SPIFFE: Secure Production Identity Framework](https://spiffe.io/)
- [Service Mesh Security Patterns](https://github.com/service-mesh-patterns)

### Documentation
- [Complete Code Explanation PDF](docs/clsvh_zt_complete_guide.pdf) - Step-by-step breakdown of every file
- [API Reference](docs/api_reference.md) - Detailed class and function documentation

---

## 🤝 Contributing

This is a research project. Contributions welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Cybersecurity Research Project**

Built as part of ongoing research into Zero Trust architectures and cross-layer security validation.

---

## 🙏 Acknowledgments

- Zero Trust architecture principles from NIST SP 800-207
- Inspired by work on service mesh security and SPIFFE
- Built with Python's dataclasses for clean data modeling

---

## 📬 Contact

For questions or collaboration opportunities:
- Open an issue on this repository
- Connect on LinkedIn: [Your Profile](https://linkedin.com/in/yourprofile)
- Email: your.email@example.com

---

<div align="center">

**⭐ Star this repo if you find the CLSVH-ZT concept interesting!**

Built with 🔒 for Zero Trust research

</div>
