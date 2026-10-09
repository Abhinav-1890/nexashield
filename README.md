# NexaShield

**A Modular Risk-Adaptive Runtime Governance and Security Framework for Large Language Model Applications**

> Guarding LLMs with Policy, Proof, and Precision.

---

## 🚧 Project Status

This project is in its **initial / planning stage**. Literature survey and research gap identification are complete. Implementation has not yet started — the current focus is **data collection** for the ML components described below.

---

## Overview

NexaShield is a runtime governance and security layer that sits between users/applications and LLMs. Rather than being just a chatbot wrapper or a monitoring dashboard, it is a **hybrid, risk-adaptive security pipeline** that inspects, scores, and governs every request before it reaches an LLM — and verifies the response before it reaches the user.

It aims to unify capabilities that today exist only as fragmented, single-purpose tools (e.g., only PII detection, or only prompt-injection detection, or only policy enforcement) into one explainable, auditable pipeline.

### What it does

1. **Normalizes inputs** — Unicode normalization, invisible-character detection, safe decoding
2. **Detects prompt injection and jailbreak attempts** — direct, indirect, and obfuscated
3. **Detects sensitive data** — PII, API keys, passwords, tokens, and other secrets
4. **Assigns a risk score** to every request
5. **Enforces organization-specific policies** before a request reaches the LLM
6. **Sanitizes, blocks, or escalates** risky requests for human approval
7. **Verifies LLM outputs** using retrieval context, semantic similarity, and entailment checks
8. **Maintains an audit trail** of prompts, detector decisions, risk scores, responses, and final actions
9. **Provides a dashboard** for security events, policy violations, risk trends, latency, and usage
10. *(Optional)* Tracks cost and routes requests to suitable hosted models

---

## Research Direction

The core contribution of this project is **LARVA — Layered Adaptive Risk and Verification Algorithm** — a combined pipeline rather than a single detector. This addresses the identified research gap: existing systems handle PII, injection, or policy enforcement in isolation, but lack a combined, risk-adaptive, explainable runtime governance pipeline with built-in output verification and audit.

### Proposed Pipeline

```
User / Application
      │
      ▼
Input Normalization
      │
      ▼
PII and Secret Detection
      │
      ▼
Rule-Based Prompt-Injection Detection
      │
      ▼
Lightweight Transformer-Based Risk Classifier
      │
      ▼
Embedding Similarity and Novelty Detection
      │
      ▼
Risk Scoring
      │
      ▼
Policy Enforcement
      │
      ▼
LLM or RAG Application
      │
      ▼
Output Verification
      │
      ▼
Release / Regenerate / Sanitize / Human Review
      │
      ▼
Audit Logging and Dashboard
```

### LARVA — Layered Adaptive Risk and Verification Algorithm

| Layer | Function |
|---|---|
| **1. Input Normalization** | Unicode normalization, invisible-character stripping, safe decoding, separation of system/user/retrieved/tool content |
| **2. Deterministic Screening** | Regex rules, secret detection, PII detection, known jailbreak/injection patterns, obfuscation checks |
| **3. Semantic Classification** | Lightweight transformer (e.g., DeBERTa/RoBERTa/BERT) classifying prompts as benign, suspicious, or malicious, with attack category prediction |
| **4. Semantic Similarity & Novelty Detection** | Sentence embeddings, cosine similarity against known attack examples, novelty scoring for unseen attack patterns |
| **5. Risk Scoring** | Weighted score combining injection probability, PII/secret severity, policy violation score, novelty/anomaly score, and user/action risk |
| **6. Policy Enforcement** | Allow low-risk, sanitize/confirm medium-risk, block high-risk, require human approval for high-impact actions |
| **7. Output Verification** | Detect unsafe content/secrets in responses, retrieve supporting evidence, semantic similarity + entailment checks, flag unsupported claims |
| **8. Auditability** | Log redacted prompts, detector scores, policy decisions, evidence IDs, verification results, latency, model used, cost, and final action |

---

## Planned Tech Stack

> Subject to change as the project develops.

- **Frontend:** Next.js / React
- **Backend:** FastAPI (Python)
- **Database:** PostgreSQL
- **Vector Store:** pgvector or Qdrant
- **Cache/Queue:** Redis
- **Policy Engine:** Open Policy Agent or a custom rule engine
- **ML/NLP:** Hugging Face Transformers, sentence embeddings, regex + NER-based detectors
- **Observability:** OpenTelemetry / structured logging
- **Deployment:** Docker + cloud hosting

All models are chosen to be CPU/cloud-friendly (no GPU dependency), given project constraints.

---

## Roadmap

- [x] Literature survey (IEEE conference papers, 2025–present)
- [x] Research gap identification
- [ ] **Data collection** for prompt-risk classifier, PII/secret detector, and novelty detector *(current phase)*
- [ ] Input normalization module
- [ ] Deterministic screening (regex + secret/PII detection)
- [ ] Prompt-risk transformer classifier
- [ ] Embedding similarity & novelty detection
- [ ] Risk scoring engine
- [ ] Policy enforcement layer
- [ ] Output verification module
- [ ] Audit logging system
- [ ] Dashboard (security events, risk trends, usage)
- [ ] End-to-end integration & evaluation
- [ ] Research paper write-up

---

## Project Structure *(planned)*

```
nexashield/
├── backend/
│   ├── normalization/       # Unicode, invisible-char, decoding
│   ├── detectors/           # PII, secrets, injection rules
│   ├── classifier/          # Transformer-based risk classifier
│   ├── novelty/             # Embedding similarity & novelty detection
│   ├── risk_scoring/        # Weighted risk scoring engine
│   ├── policy/              # Policy enforcement logic
│   ├── verification/        # Output verification (retrieval, entailment)
│   ├── audit/                # Audit trail & logging
│   └── api/                 # FastAPI routes
├── frontend/
│   └── dashboard/           # Security events, risk trends, usage
├── data/
│   ├── raw/                 # Collected datasets
│   ├── processed/           # Cleaned, labeled, split data
│   └── scripts/             # Collection, cleaning, splitting scripts
├── notebooks/                # Experimentation & model training
├── docs/                     # Research notes, architecture docs
└── README.md
```

---

## About

This is a final-year B.Tech CSE (AI/ML) capstone project, being built as a single-student project over a 3-month timeline, with cloud-based/CPU-friendly tools and hosted LLM APIs (no local GPU).

## License

*To be decided.*
