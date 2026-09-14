# CLSVH-ZT Single-File Prototype

This repository contains the complete CLSVH-ZT research prototype in one file: `clsvh_zt.py`.

## Features

- Ed25519 signatures and key identifiers.
- Expiring request-bound headers.
- Replay-cache example.
- Hash-linked validation lineage.
- Fast, slow, and block policy decisions.
- Sensitive resources always use slow path.

## Install

```bash
python -m venv .venv
python -m pip install cryptography
```

## Run

```bash
python clsvh_zt.py
python clsvh_zt.py test
```

## VS Code

Open this folder in Visual Studio Code, select the `.venv` Python interpreter, and run `clsvh_zt.py` using the Run button or integrated terminal.

## GitHub

```bash
git init
git add .
git commit -m "Add single-file CLSVH-ZT prototype"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/clsvh-zt-prototype.git
git push -u origin main
```

## Contact

Email: [shubhamsawant1908@gmail.com](mailto:shubhamsawant1908@gmail.com)

No LinkedIn account is listed.

## Security notice

This is a research prototype. Do not use `trust_level` alone for authorization or to disable inspection. Production deployment requires secure key management, key rotation, identity verification, distributed replay protection, centralized policy, revocation, and independent security review.

## License

MIT
