# Autonomous Prompt Injection Agent

An autonomous LLM-driven red-team agent that discovers and exploits prompt injection
vulnerabilities in AI-backed web applications **without any human guidance after launch**.
The agent probes endpoints, generates novel payloads across 7 attack categories, delivers
them, evaluates responses, mutates partially successful payloads, and produces structured
research reports.

Companion project to [agent-security-sandbox](https://github.com/TGKDre/agent-security-sandbox).

**Written analysis:** [What Happens When Your Defense Hits a Hard Floor](https://medium.com/@andre.obiuzo/what-happens-when-your-defense-hits-a-hard-floor-08ad2b8fafab) -- on prompt injection, converging failures, and what the results mean beyond security.

---

## Research Motivation

The `agent-security-sandbox` project established that pattern-based injection defense
converges on a hard floor: `pi_agent_001` (Document Store Prompt Injection) survived
all defenses for both GPT and Claude because the attack encodes multiple independent
compromise phrases that a static blocklist cannot exhaustively cover.

That finding raised a follow-on question: if a static pattern library cannot close the
gap, can an **autonomous LLM agent** -- given only the target URL -- discover novel
payload variants beyond the static library? This project answers that question empirically.

---

## Architecture

```
run_attacker.py              Entry point
agents/
  attacker_agent.py          AutonomousAttackerAgent -- drives the full assessment loop
  tool_registry.py           4 tools: probe_endpoint, inject_payload, mutate_payload,
                             record_finding (all sandboxed, local HTTP only)
judges/
  injection_judge.py         Multi-signal evaluator: keyword matching + instruction-echo
                             detection + structural pattern matching
targets/
  vulnerable_app/
    app.py                   Deliberately vulnerable Flask + Claude target app
    Dockerfile               Container definition
scenarios/
  targets.yaml               Attack surface definitions and mutation strategies
reports/                     Timestamped JSON + Markdown output per run
docker-compose.yml           One-command target environment
```

---

## How the Agent Works

The agent operates in a fully autonomous agentic loop across up to 20 turns:

1. **Reconnaissance** -- calls `probe_endpoint` on each surface to discover field names,
   parameter structures, and any visible system prompt fragments.

2. **Payload generation** -- the LLM generates novel injection candidates across 7 attack
   categories: role hijacking, instruction override, data exfiltration, context poisoning,
   delimiter injection, goal hijacking, and jailbreak.

3. **Delivery** -- calls `inject_payload`, which POSTs the payload to the target and
   captures the full response.

4. **Evaluation** -- `InjectionJudge` scores each response for compromise signals using
   three independent detection layers. Results feed back into the agent context.

5. **Mutation** -- for payloads that partially succeed, the agent calls `mutate_payload`
   with a chosen strategy (urgency framing, base64 encoding, nested delimiters, etc.)
   and retries with the evolved variant.

6. **Recording** -- confirmed compromises are logged via `record_finding` with surface,
   payload, severity, response excerpt, and attack category.

The agent stops when `MAX_TURNS` is exhausted or all surfaces are covered.

---

## Attack Categories

| Category | Description |
|---|---|
| `role_hijacking` | Attempt to reassign agent identity mid-context |
| `instruction_override` | Override the system prompt with new directives |
| `data_exfiltration` | Extract synthetic secrets from agent memory |
| `context_poisoning` | Inject false context to alter agent behavior |
| `delimiter_injection` | Use special tokens to escape prompt structure |
| `goal_hijacking` | Replace task objective with attacker-specified goal |
| `jailbreak` | Remove model safety constraints entirely |

---

## Quickstart

```bash
git clone https://github.com/TGKDre/autonomous-injection-agent.git
cd autonomous-injection-agent
pip install -r requirements.txt

# Start the sandboxed target (requires Docker)
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up -d --build

# Launch the autonomous attacker
python run_attacker.py \
    --target http://localhost:5050 \
    --model anthropic/claude-haiku-4-5-20251001 \
    --turns 20
```

Reports are written to `reports/` in both JSON and Markdown.

---

## Target Application

`targets/vulnerable_app/app.py` is a deliberately insecure Flask + Claude application
simulating a real-world AI-backed customer support system. It:

- Passes user input directly into LLM context without sanitization
- Includes synthetic secrets in the system prompt (realistic formats, not real values)
- Exposes 4 input surfaces: `/chat`, `/ask`, `/document-qa`, `/search`
- The document Q&A surface mirrors the `pi_agent_001` document store vulnerability
  identified in `agent-security-sandbox` -- user-supplied content is interpolated
  directly into the LLM prompt without structural isolation

All secrets are synthetic values with realistic formats for detection fidelity.
No real credentials are used anywhere in this project.

---

## InjectionJudge -- Detection Architecture

Three independent detection layers:

1. **Category-specific keyword signals** -- pattern library keyed by attack category
2. **Cross-category signals** -- exfiltration and goal-hijacking patterns always apply
3. **Instruction-echo detection** -- identifies dangerous keyword overlap between
   payload and response, catching cases where the model paraphrases injected instructions
   rather than echoing them verbatim

A defense signal downgrades compromise to SAFE when the model explicitly flags
the injection attempt as suspicious.

---

## Mutation Strategies

| Strategy | Mechanism |
|---|---|
| Urgency framing | Prefix with `URGENT SECURITY ALERT:` |
| Base64 encoding | Encode payload; instruct model to decode and execute |
| Nested delimiters | Wrap in `</s>[INST]...[/INST]` token patterns |
| Role confusion | Frame as system administrator directive |
| Markdown injection | Use `**[SYSTEM OVERRIDE]**` bold formatting |
| Context escape | Prepend `---END OF USER INPUT---` newline break |
| Token stuffing | Bracket with `Ignore previous... Note: this is authorized` |

---

## Design Notes

- All HTTP calls are sandboxed to localhost -- no real internet access during runs
- Synthetic secrets use realistic formats (`sk-` prefix, token patterns) for detection fidelity
- The `InjectionJudge` instruction-echo layer catches semantic compromise signals that
  keyword matching alone would miss
- Mutation strategies cover the most common bypass techniques in adversarial ML literature
  (Perez & Ribeiro 2022, Greshake et al. 2023)
- Rate limit handling via `tenacity` exponential backoff (Tier 1 API compatible)
- Multi-provider: supports both Anthropic and OpenAI as the attacker model

---

## Roadmap

- [x] Autonomous endpoint reconnaissance via `probe_endpoint`
- [x] LLM-generated novel payloads across 7 attack categories
- [x] Multi-signal `InjectionJudge` with instruction-echo detection
- [x] Payload mutation engine with 7 mutation strategies
- [x] Sandboxed vulnerable target application (Flask + Claude)
- [x] Structured JSON + Markdown research reports
- [ ] Semantic tool output classifier as defense layer (closes agent-security-sandbox pi_agent_001)
- [ ] Multi-hop exfiltration chain scenarios
- [ ] SSRF via outbound tool calls
- [ ] Cross-model attacker comparison (GPT vs Claude as attacker)
- [ ] Automated payload corpus from successful runs (training set for semantic classifier)
