# OWASP LLM Top 10 Validation: Autonomous Injection Agent

**Repository:** [github.com/TGKDre/autonomous-injection-agent](https://github.com/TGKDre/autonomous-injection-agent)
**Date:** June 17, 2026

---

## Overview

The Autonomous Injection Agent is a companion tool to the [Agent Security Sandbox](https://github.com/TGKDre/agent-security-sandbox). Rather than running predefined scenarios, this agent autonomously probes live LLM applications, generates novel injection payloads across 7 attack categories, evaluates responses, mutates partially successful payloads, and produces structured research reports.

## OWASP Coverage

| OWASP Category | Coverage | How |
|---|---|---|
| LLM01: Prompt Injection | FULL | 7 attack categories: role hijacking, instruction override, data exfiltration, context poisoning, delimiter injection, goal hijacking, jailbreak |
| LLM06: Sensitive Information Disclosure | PARTIAL | Data exfiltration attack category |
| LLM08: Excessive Agency | PARTIAL | Goal hijacking category tests agent behavior boundaries |

## 7 Autonomous Attack Categories

The agent generates novel payloads across these categories without human guidance:

1. **Role Hijacking** — Convincing the model it has a different role/identity
2. **Instruction Override** — Directly overriding system instructions
3. **Data Exfiltration** — Extracting sensitive information from the model or context
4. **Context Poisoning** — Manipulating the model's understanding of ongoing context
5. **Delimiter Injection** — Breaking out of structured input formats
6. **Goal Hijacking** — Redirecting the model to a different objective
7. **Jailbreak** — Bypassing safety training constraints

## Key Validation Findings

- Payload generation is LLM-driven — the agent uses the same class of model it attacks
- Mutation strategies (base64, nested delimiters, urgency framing) measurably increase success rates
- The InjectionJudge uses 3-layer detection: keyword matching + instruction-echo + structural pattern matching
- The agent runs up to 20 autonomous turns without human intervention

---

*This document supports the Agent Security Sandbox OWASP validation effort. See that repository for comprehensive mapping data.*
