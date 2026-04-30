# Rapid Threat Modeling Rubric

> This is a pre-dev planning tool — run it when you are scoping a change, not after you have written the code. The point is to catch security questions early enough to actually do something about them. If your change is big enough to need an SIA, use that instead.

---

## Does This Apply to Your Change?

If your change touches any of the below, run this rubric:

- Auth, session management, or any kind of permission check
- PII or PHI — anything tied to a person or their health
- Where data is stored or how it moves (new DB columns, new API calls, queues, etc.)
- External APIs, SDKs, or third-party services
- Anything that takes user input (forms, file uploads, URL params, headers)
- Secrets, keys, or any crypto logic
- Logging — what gets written and where

If none of that applies, you are probably fine to skip it. When in doubt, run it anyway.

---

## Work Through These Before You Build

You do not need every answer locked down, but any "I don't know" is a risk that needs a decision before dev starts.

### What does this change actually touch?

- What is this change supposed to do?
- What PII or PHI does it create, read, update, or delete?
- Where does that data live — database, cache, file storage, a third-party system?
- Where does it travel — API calls, queues, emails, logs?

### Who can do what?

- Who is this feature for?
- What should they be able to access, and what should they definitely not?
- Are there multiple roles or tenants? How is their data kept separate?
- What happens if an unauthenticated user hits this?

### What is coming in from users or outside systems?

- What inputs are you accepting?
- Where does that data end up — a query, a template, an external API call, a file?
- If you are handling file uploads, what types and sizes are you actually allowing?

### How are secrets and sensitive data handled?

- Do you need new API keys, tokens, or credentials? Where are they going to live?
- Does sensitive data need to be encrypted at rest or in transit?
- Are you doing any crypto work? What algorithm and why?

### Anything coming in from outside?

- Adding any new libraries or SDKs?
- If PII or PHI is going to a third party, is there a DPA or BAA already in place?

### Logging?

- What security-relevant events should be getting logged (auth, access to sensitive data, admin actions)?
- Any chance PII or PHI ends up in the logs?

### What does failure look like?

- What error states can this produce?
- Could error messages leak internal details or help someone enumerate users or data?

---

## What to Do With Your Answers

| Result | Action |
|---|---|
| Everything answered, no open questions | Good to go — document it and attach to the ticket |
| 1-2 open questions | Resolve before dev starts, or flag async to AppSec |
| 3+ open questions | Get AppSec in on planning before any work kicks off |
| Any "I don't know" on data, access control, or third parties | That is a risk — get an answer before scoping is final |

---

## Looping in AppSec

When you reach out, include:

- What you are planning to build (one or two sentences)
- Which questions above are unresolved
- Any timeline constraints

**Channel:** `#appsec-review` | **Async:** 1 business day | **Sync:** scheduled within 2 business days

---

## How This Sits Next to the SIA

| | This Rubric | Security Impact Analysis |
|---|---|---|
| **Use for** | Tactical feature and code-level changes | Major changes — new systems, new data categories, architecture shifts |
| **When** | Planning and ticket scoping | Design and discovery |
| **Who drives it** | Dev or tech lead, AppSec on escalation | AppSec-led, cross-functional |

Not sure which one to use? Start here. AppSec will tell you if it needs to go to an SIA.

---

*Owner: AppSec | Review cadence: Annual | Version: 1.0 | Last reviewed: [DATE]*
