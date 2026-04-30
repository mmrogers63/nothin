# Rapid Threat Modeling Rubric

> Run this during planning when you are building something with real security surface area. Not every change needs it — the goal is to catch the ones that actually introduce risk before dev starts. If the scope is big enough to warrant an SIA, use that instead.

---

## Does This Need a Threat Model?

Run this rubric if your change does any of the following:

- Adds or changes how users authenticate, get authorized, or manage sessions
- Introduces a new flow that creates, moves, or stores PII or PHI
- Exposes a new endpoint or significantly changes how an existing one behaves
- Integrates a new external service, API, or SDK that touches sensitive data
- Changes how secrets, keys, or encryption are handled
- Meaningfully changes what gets logged or where logs go

Tweaks, bug fixes, copy changes, refactors that do not touch the above — skip it.

---

## Work Through These Before You Build

Any "I don't know" is a risk that needs a decision before dev starts.

### What does this change actually touch?

- What is this supposed to do?
- What PII or PHI does it create, read, update, or delete?
- Where does that data live and where does it travel?

### Who can do what?

- Who is this for, and what should they explicitly not be able to access?
- Are there multiple roles or tenants? How is their data kept separate?
- What happens if an unauthenticated user hits this?

### What is coming in from users or outside systems?

- What inputs are you accepting and where do they end up?
- If you are handling file uploads, what types and sizes are you allowing?

### How are secrets and sensitive data handled?

- Do you need new credentials? Where will they live?
- Does sensitive data need to be encrypted at rest or in transit?

### Anything coming in from outside?

- Adding new libraries or SDKs?
- If PII or PHI is going to a third party, is there a DPA or BAA in place?

### Logging?

- What security-relevant events should be logged?
- Any chance PII or PHI ends up in the logs?

### What does failure look like?

- What error states can this produce?
- Could error messages leak internal details or help someone enumerate users or data?

---

## What to Do With Your Answers

| Result | Action |
|---|---|
| Everything answered, no open questions | Good to go — document and attach to the ticket |
| 1-2 open questions | Resolve before dev starts, or flag async to ITSC |
| 3+ open questions | Get ITSC in on planning before work kicks off |
| Any "I don't know" on data handling, access control, or third parties | Get an answer before scoping is final |

---

## Looping in ITSC

When you reach out, include:

- What you are planning to build (one or two sentences)
- Which questions are unresolved
- Any timeline constraints

**Channel:** `#itsc-review` | **Async:** 1 business day | **Sync:** scheduled within 2 business days

---

## How This Sits Next to the SIA

| | This Rubric | Security Impact Analysis |
|---|---|---|
| **Use for** | Changes with real security surface area | Major changes — new systems, new data categories, architecture shifts |
| **When** | Planning and ticket scoping | Design and discovery |
| **Who drives it** | Dev or tech lead, ITSC on escalation | ITSC-led, cross-functional |

Not sure which one applies? Start here. ITSC will tell you if it needs to go to an SIA.

---

*Owner: ITSC | Review cadence: Annual | Version: 1.0 | Last reviewed: [DATE]*
