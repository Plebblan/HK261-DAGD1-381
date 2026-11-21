# Related Work: Dynamic REST/Web-API Testing & Fuzzing
### Scope: stateful, multi-actor authorization and business-logic testing (project HK261-DAGD1-381)

| | |
|---|---|
| Compiled | 2026-11-20 (web search + selected full-text reads) |
| Purpose | Prior-art map for `survey_and_boundary.md`, `research_gaps.md`, `workflow.md`, Phase-2 baselines |
| Admission rule | (a) open-source framework **or** (b) published paper proposing a solution to some portion of the problem. Closed-source products are listed in §7 with lower priority |
| Status | Draft for audit. Items marked **[C]** or **[A]** must be opened and read before being cited in the report |

---

## 0. How to read this document

**Verification level** (how well *I* verified the entry; this is not a quality score)

| Tag | Meaning |
|---|---|
| **[R]** | Full text (or most of it) read in this session |
| **[A]** | Abstract / official landing page / README / search snippets only |
| **[V]** | Vendor or marketing claim; not independently verified |
| **[C]** | Known only because another paper cites it; not opened |

**Priority for the project:** ★★★ read before freezing the boundary · ★★ read for Phase 2 or a specific module · ★ context only.

**Project mapping tags** (from `workflow.md` / `families.yaml`)
Stages `S-A … S-K` = workflow stages [A]…[K] · Families `F1–F5` · Research questions `RQ1–RQ4` · `P1`/`P2` = Phase 1 / Phase 2.

---

## 1. Taxonomy (tree)

```text
Dynamic REST / Web-API testing
│
├─ §2  Surveys, empirical comparisons, benchmark corpora
│
├─ §3  A. Spec-driven stateful REST test generators / fuzzers (general fault finding)
│     A1 RESTler · A2 Morest · A3 RestTestGen · A4 RESTest · A5 Schemathesis
│     A6 EvoMaster · A7 WuppieFuzz · A8 others (cited-only)
│
├─ §4  B. Learning-based & LLM-assisted testers  (≈ Phase-2 planner/ranker prior art)
│     B1 ARAT-RL · B2 DeepREST · B3 APIRL · B4 AutoRestTest · B5 LlamaRestTest
│     B6 Input/rule/spec helpers (RESTGPT, NLP2REST, ARTE, KAT, RESTSpecIT, MuCoREST)
│
├─ §5  C. Security-oriented REST testing
│     C1 Security-property checkers & access-policy oracles (RESTler checkers, EvoMaster)
│     C2 BOLA / BFLA specific (BOLABuster, Karate-BOLA-Guard, others)
│     C3 Mass assignment (RestTestGen-MA)
│     C4 Vulnerability-oriented injection/SSRF (Nautilus, VoAPI2)
│     C5 Excessive data exposure (EDEFuzz, Mockingbird, TrailBlazer)
│
├─ §6  D. Web-app broken-access-control scanners & stateful crawlers
│     D1 BACScan · D2 BACFuzz · D3 EvoCrawl · D4 Black Widow · D5 older differential scanners
│
├─ §7  E. Practitioner / open-source tooling      F. Commercial & closed-source
│     E1 Autorize · E2 AuthMatrix · E3 ZAP access-control add-on · E4 Akto · E5 Metlo · E6 mitmproxy2swagger
│     F1 StackHawk · F2 Wallarm · F3 APIsec · F4 42Crunch · F5 Burp Suite · F6 XBOW · F7 Invicti (gated) · F8 others
│
├─ §8  Cross-cutting comparison (capability matrix, oracle catalogue, stage coverage)
├─ §9  Audit of project decisions against this literature      ← action items
├─ §10 Proposed amendments to workflow.md / architecture.md
├─ §11 Reading order & adoption list
├─ §12 Not found / not verified / excluded
└─ §13 Reference index (URLs)
```

---

## 2. Surveys, empirical comparisons, benchmark corpora

### 2.1 Testing RESTful APIs: A Survey (Golmohammadi, Zhang, Arcuri) ★★★ [A]
- **Refs:** arXiv 2212.14604 · https://arxiv.org/pdf/2212.14604 · ACM TOSEM 2023, DOI 10.1145/3617175
- **What it gives us:** the field's reference taxonomy (black-box vs white-box, search-based, model-based, RL, etc.) and the observation that the dominant oracle in the literature is the 5xx status code.
- **Use:** cite in the survey chapter as the "state of the field" source instead of generic references [8]/[9] in the project description.

### 2.2 Open Problems in Fuzzing RESTful APIs: A Comparison of Tools (Zhang & Arcuri) ★★★ [A]
- **Refs:** arXiv 2205.05325 · https://arxiv.org/pdf/2205.05325 (TOSEM 2023)
- **Content:** 7 tools compared on 19 APIs, 1 h × 10 repetitions; only EvoMaster supports white-box; reports remaining open problems (many SUTs stay below 50 % line coverage even in white-box).
- **Use:** methodology precedent for the project's "≥ 10 seeds, 95 % CI" protocol and for choosing baselines.

### 2.3 Corpora and vulnerable-by-design targets
| Corpus | Refs | Notes |
|---|---|---|
| **WFD / EMB** (Web Fuzzing Dataset) | https://github.com/WebFuzzing/Dataset · Zenodo 10.5281/zenodo.18196038 (v4.1.0, per 2604.00702) | 36 JVM APIs used for white-box security experiments; includes the **WFC** format for auth info and fault codes |
| Vulnerable-by-design APIs used in the EvoMaster security study | crAPI (OWASP/crAPI), VAmPI (erev0s/VAmPI), DVAPI (payatu/DVAPI), dvws-node (snoopysecurity/dvws-node), Damn-Vulnerable-RESTaurant-API-Game (theowni), vulnerable-rest-api (bnematzadeh), Checkmarx/capital, WebGoat | Table 1 of arXiv 2604.00702 lists IDs, #endpoints, LOC |
| SBFT'26 REST-API fuzzing tool competition | cited in 2604.00702 as "EvoMaster at REST League 2026 Tool Competition" **[C]** | Potential external benchmark protocol; not opened |

**Project relevance:** none of these corpora provides **multi-tenant, stateful ground truth with benign twins** (the project's Gap 3). The statement is plausible but should be backed by an explicit corpus table (see AU-1).

---

## 3. Category A: Spec-driven stateful REST test generators / fuzzers

### A1. RESTler (Microsoft Research) ★★★ [A]
- **Openness:** open source (MIT-style, Microsoft) · https://github.com/microsoft/restler-fuzzer
- **Papers:** ICSE 2019 *RESTler: Stateful REST API Fuzzing* (MSR-TR-2018-11; https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing) · ICST 2020 *Checking Security Properties of Cloud Service REST APIs* (https://patricegodefroid.github.io/public_psfiles/icst2020.pdf) · ISSTA 2020 differential regression · FSE 2020 data fuzzing. Thesis: https://core.ac.uk/download/343132587.pdf
- **Pipeline (recap):**
  1. **Compile**: Swagger/OpenAPI → fuzzing grammar (requests + producer/consumer dependencies).
  2. **Test** (smoke), **Fuzz-lean** (each endpoint+method once with default checkers), **Fuzz** (smart breadth-first search of request sequences).
  3. A request is fuzzed only if the resources it depends on were created; dynamic feedback from responses prunes sequences that the service refuses.
  4. **Checkers** fire at context-specific points and send extra targeted requests.
- **Security rules (ICST 2020):** use-after-free, resource-leak, resource-hierarchy, **user-namespace** (a resource created in one user namespace must not be reachable from another).
- **Limits (stated by later work):** the user-namespace rule assumes strict isolation and ignores legitimate cross-user rights such as admins (2604.00702 §2); no model of roles, tenants, business states.
- **Relevance:** S-B dependency graph (producer→consumer), S-F template ideas, **baseline** for Phase 2. The user-namespace checker is the closest ancestor of the project's differential oracle for F1/F4.

### A2. Morest (NTU / Huawei) ★★ [A]
- **Openness:** paper + project page; repository not verified · arXiv 2204.12148 · DOI 10.1145/3510003.3510133 · https://sites.google.com/view/restful-morest/home
- **Pipeline:** (1) build a **RESTful-service Property Graph (RPG)** from OpenAPI using CRUD relations and schema in/out relations; (2) traverse RPG to produce call sequences and send them; (3) **update the RPG from responses** (edge addition and deletion).
- **Results (authors):** 6 services, 44 bugs (13 not found by others); compared with RESTler and RestTestGen.
- **Relevance:** S-B/S-D: the self-correcting dependency graph is a template for "observed vs normative" graph handling (observed edges may *propose*, not promote; see `workflow.md` principle 2).

### A3. RestTestGen (Univ. of Verona) ★★★ [A]
- **Openness:** open source (Apache-2.0) · https://github.com/SeUniVr/RestTestGen · wiki https://seunivr.github.io/RestTestGen-Wiki/
- **Papers:** ICST 2020 (Viglianisi et al.) **[C]** · STVR 2022 *nominal and error scenarios* (https://profs.scienze.univr.it/ceccato/papers/2022/stvr2022.html) · ICSME 2022 framework paper (https://profs.scienze.univr.it/~ceccato/papers/2022/icsme2022.pdf)
- **Architecture:** OpenAPI → Schema + **Operation Dependency Graph (ODG)** → pluggable *Strategy* with Operation Ordering, Mutation Operator, Oracle; writers emit reports and REST-assured/JUnit tests; coverage measurement of paths, operations, status codes, parameters.
- **Built-in strategies:** nominal+error testing; **mass-assignment security testing** (see C3); DeepREST strategy (v25.12 changelog).
- **Relevance:** the most modular open-source skeleton to **reuse as a baseline** or to mine for ODG construction code (S-B).

### A4. RESTest (Univ. of Seville) ★★ [A]
- **Openness:** open source · https://github.com/isa-group/RESTest · ICSOC 2020 (https://idus.us.es/handle/11441/133642) · ISSTA 2021 tool paper (DOI 10.1145/3460319.3469082)
- **Idea:** model-based generation from OpenAPI plus **IDL** (inter-parameter dependency language) solved by a constraint solver; random vs constraint-based testing.
- **Results (authors):** up to 99 % more valid test cases than random on 6 commercial APIs.
- **Relevance:** `valid_request` definition (project §4.1): RESTest quantifies why syntactically valid but dependency-violating requests waste budget.

### A5. Schemathesis ★★★ [A]
- **Openness:** open source · https://github.com/schemathesis/schemathesis · docs https://schemathesis.readthedocs.io
- **Paper:** *Deriving Semantics-Aware Fuzzers from Web API Schemas* (Hatfield-Dodds & Dygalo), arXiv 2112.10328 (ICSE-Companion 2022)
- **Pipeline:** OpenAPI/GraphQL → property-based strategies (Hypothesis) → request → **generic checks** (content-type, schema conformance, status-code conformance, 5xx); optional **stateful testing via OpenAPI links**; targeted testing; replay of stored requests.
- **Results (authors):** 8 fuzzers × 16 services; 1.4×–4.5× more unique defects than the second-best fuzzer per target.
- **Relevance:** the "schema-based negative testing" Phase-1 baseline. Its stateful mode depends on `links`, which the EvoMaster authors note are rarely present in real specs.

### A6. EvoMaster (Arcuri et al.) ★★★ [R for the security paper, A for the rest]
- **Openness:** open source (LGPL) · https://github.com/WebFuzzing/EvoMaster · https://www.evomaster.org · REST, GraphQL, RPC; black-box (any language) and white-box (JVM)
- **Papers:** QRS 2017 (arXiv 1901.01538) · TOSEM 2019 *RESTful API Automated Test Case Generation with EvoMaster* · ASE-journal 2025 tool report · **security extension: arXiv 2604.00702 (Apr 2026), extension of an ISSRE 2025 paper** · flakiness study arXiv 2603.28452 **[A]**
- **Core pipeline:** OpenAPI + optional auth config → search-based (MIO) or random black-box generation → minimised test suite (JUnit/Python/Kotlin/JS) → in white-box mode DB reset after each test.
- **Security phase (2604.00702) — see C1 for details.**
- **Relevance:** **the closest published system to the project's differential-oracle core**, and probably the strongest automated baseline for the Phase-2 hypothesis (AU-7).

### A7. WuppieFuzz (TNO) ★ [A]
- **Openness:** open source · https://github.com/TNO-S3/WuppieFuzz · arXiv 2512.15554 (alphaXiv: https://www.alphaxiv.org/abs/2512.15554.md)
- **Idea:** coverage-guided stateful REST fuzzing on LibAFL; initial corpus = request sequences from OpenAPI; REST-specific mutators; black/grey/white-box.
- **Relevance:** coverage-feedback loop; only useful if the target exposes coverage (not the case for the black-box lab).

### A8. Cited-only tools (not opened) ★ [C]
QuickREST (ICST 2020, property-based, Karlsson et al.), RestCT, bBOXRT, MINER, ResTest, Pythia (coverage-guided grammar fuzzing with learned mutations), APIF (reverse-proxy capture + SecLists attacks; per 2604.00702 it cannot ingest OpenAPI and needs captured live traffic). *Do not cite without reading.*

---

## 4. Category B: Learning-based and LLM-assisted testers (Phase-2 planner/ranker prior art)

> **Common pattern:** reward = code/operation coverage or new 5xx. **None optimises "valid authorization/business-logic violations under a request budget"**, which is the project's objective function (RQ2). This is the cleanest differentiator for the Planner/Ranker.

### B1. ARAT-RL — *Adaptive REST API Testing with Reinforcement Learning* (Kim, Sinha, Orso; ASE 2023) ★★ [A]
- arXiv 2309.04583 · Idea: Q-learning prioritises operations and parameters from request/response data; sampling-based value strategy. Outperformed prior tools in the authors' evaluation. Reused by LlamaRestTest.

### B2. DeepREST (Corradini et al.; ASE 2024) ★★ [A]
- arXiv 2408.08594 · Deep RL learns an operation **testing order** and implicit constraints hidden from the OpenAPI; alternates exploration with exploitation by mutating successful interactions. Now also a strategy inside RestTestGen.

### B3. APIRL (Foley & Maffeis; AAAI 2025) ★★ [A]
- arXiv 2412.15991 · Deep RL with a transformer pre-trained on JSON to mutate requests; goal: more bugs with fewer test cases.

### B4. AutoRestTest (Kim, Stennett, Sinha, Orso; ICSE 2025) ★★★ [A]
- arXiv 2411.07098 · tool paper DOI 10.1109/ICSE-Companion66252.2025.00015
- **Pipeline:** OpenAPI → **Semantic Property Dependency Graph (SPDG)** (similarity between operation parameters) → **multi-agent RL** (agents for operation, parameter, value, dependency and, in the tool version, header) with LLM-generated values → request generator → response handling updates Q-tables.
- **Relevance:** closest *architecture* to a Phase-2 planner built from a graph + learned ranking + LLM values. Has no authorization oracle and no actor concept; the header agent only manages auth headers.

### B5. LlamaRestTest (Kim, Sinha, Orso; FSE 2025) ★★ [A]
- arXiv 2501.08598 · Two fine-tuned, quantised Llama-3-8B models (LlamaREST-IPD for inter-parameter dependencies, LlamaREST-EX for example values), plugged into ARAT-RL; compared with RESTler, EvoMaster, Morest, ARAT-RL on 12 services.
- **Relevance:** evidence that **small local models** are enough for value/dependency suggestions; supports the project's token-budget and "no free LLM" constraints.

### B6. Input / rule / specification helpers
| Work | Refs | Role |
|---|---|---|
| RESTGPT (LLM rule extraction + value generation) | cited in B5; no URL verified **[C]** | S-B: pull constraints from natural-language descriptions |
| NLP2REST, ARTE | cited in B5 (NLP2REST repo referenced by RestTestGen README: github.com/codingsoo/nlp2rest) **[C]** | rule extraction / realistic parameter values |
| KAT (Katalon; HCMC-based authors) | arXiv 2407.10227 **[A]** | GPT-based test script/data generation with operation, parameter and cross-dependency awareness |
| RESTSpecIT | arXiv 2402.05102 **[A]** | LLM-guided **specification inference** by mutating requests; relevant when only traffic exists |
| MuCoREST (Q-learning, multi-coverage) | arXiv 2410.15399 **[C]** | coverage-oriented RL |

---

## 5. Category C: Security-oriented REST testing

### C1. Security properties & access-policy oracles

#### C1.1 RESTler security checkers (ICST 2020) ★★★ [A]
- See A1. Four rules; checkers are *active* (they send extra requests after a successful sequence, e.g. re-GET a deleted resource, access with a second user). Found bugs in Azure/Office 365 services.

#### C1.2 EvoMaster access-policy & injection oracles (Sahin, Zhang, Arcuri; arXiv 2604.00702) ★★★ [R]
- **Inputs:** OpenAPI + credentials for **≥ 2 users** (ideally one per role). *No formal policy is required*: allow/deny is inferred dynamically from observed 401/403.
- **Pipeline:** (1) normal fuzzing session produces a test suite *T*. (2) **Post-processing "security phase"**: for each endpoint, *slice* an existing test (drop calls after the target call, keep prior calls that set state), then **splice in a call by another user/without credentials** or combine two tests, and re-execute. (3) A finding is emitted only if the HTTP status codes of every step match the expected pattern. (4) Findings are output as executable tests (Java/Kotlin/Python/JS) with the fault commented.
- **Nine oracles** (WFC codes in brackets): not-recognised authentication [F205], existence leakage (403 vs 404) [F204], **missed authorization checks** (PUT/PATCH/DELETE: two forbidden, one allowed) [F206], anonymous modifications [F901], **ignore anonymous** [F900], leaked stack traces [F902], hidden accessible endpoints (undeclared verb works) [F903], SQLi (sleep-based timing) [F200], stored/reflected XSS [F201].
- **Scale/results (authors):** 52 APIs (9 artificial, 8 vulnerable-by-design black-box, 36 WFD white-box); hundreds of faults reported; **no F206 (missed check) or SQLi found in WFD** and none of F200/F206/F900/F901 in the 8 vulnerable APIs. Security phase overhead: median ≈ 14 s, three outliers of 13–38 min.
- **Authors' stated limitations:** many oracles need a prior 2xx call (avg 2xx endpoint coverage ≈ 55 % on WFD); black-box runs break when endpoints change login credentials (crAPI, capital, VAmPI); oracles rely on correct HTTP semantics, so a "200 with error body" yields noise; some false positives are accepted by design.
- **Why it matters for us:**
  - It is the first open-source, *automated* BOLA/BFLA-style oracle suite integrated in a mainstream fuzzer. The project's non-overlap matrix must account for it (AU-1).
  - Its **policy-free heuristics** (e.g. "forbidden DELETE but allowed PUT is suspicious") are a ready-made answer to open item **R2** in `workflow.md` (what the oracle reads when no confirmed policy exists).
  - **Test slicing + splicing** is a neat way to build self-contained sequences from existing traces (matches `workflow.md` §12).
  - It treats *existence leakage* (403 vs 404) and *authenticated-but-401* as findings; the project's decision D3 lumps 401/403/404 as safe (AU-5).

### C2. BOLA / BFLA-specific automation

#### C2.1 BOLABuster (Palo Alto Networks Unit 42) ★★★ [A, vendor research blog]
- **Refs:** https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/ · case study https://unit42.paloaltonetworks.com/bola-vulnerabilities-easyappointments/
- **Pipeline (5 steps):** (1) identify potentially vulnerable endpoints (parameters that reference objects); (2) uncover endpoint **dependencies** (producer vs consumer endpoints); (3) build a **dependency tree and execution plan** per candidate; (4) generate test scripts; (5) execute and analyse. LLMs do the semantic steps, heuristics handle the rest; OpenAPI 3 input.
- **Caveats:** methodology blog; no peer-reviewed paper or open-source release confirmed. How false positives are filtered is not detailed in what I read.
- **Relevance:** Phase-2 AI-baseline template; compare its "LLM decides" steps with the project's DSL-constrained planner.

#### C2.2 Karate-BOLA-Guard and the Pasca et al. line ★★ [A]
- IEEE Access vol. 13 (2025), *LLM-Driven, Self-Improving Framework for Security Test Automation: Leveraging Karate DSL for Augmented API Resilience* (https://library.kab.ac.ug/Record/doaj-art-4203a5ca69274ac0b0b2d2cb75812fb4/Description) · SOCO 2024 *Enhancing API Security Testing against BOLA and Authentication Vulnerabilities through an LLM-Enhanced Framework* (https://cosa.cunbm.utcluj.ro/enhancing-api-security-testing-against-bola-and-authentication-vulnerabilities-llm-enhanced-framework/page/3/)
- **Idea:** LLM + RAG (vector DB) synthesises **Karate-DSL** security tests with a feedback loop from past runs; evaluated on VAmPI, crAPI, Juice Shop and 15 production APIs.
- **Relevance:** another instance of "LLM emits a constrained DSL". The 2604.00702 authors cite an LLM-BOLA approach whose oracle is unclear and which admits it may flag non-existent bugs (reference [38] there; likely this line) — supports our requirement that every finding needs replay + before/after evidence.

#### C2.3 Other mentions ★ [C]
- Petri-net translation of OpenAPI + server-log analysis for BOLA (2604.00702 ref [42]); requires `links` in the spec.
- Patent US 2023/0229811 A1 *Detecting broken object level and function level authorization issues with API services* (https://ipiq.io/patents/360510) — closed, low priority; skim only to avoid design overlap.

### C3. Mass assignment

#### C3.1 Automated Black-box Testing of Mass Assignment Vulnerabilities in RESTful APIs (Corradini, Pasqua, Ceccato; ICSE 2023) ★★★ [A]
- **Refs:** arXiv 2301.01261 · DOI 10.1109/ICSE48619.2023.00213 · replication package Zenodo 10.5281/zenodo.7348518 · implemented in RestTestGen (`MassAssignmentSecurityTestingStrategy`)
- **Pipeline:** OpenAPI → **cluster similar operations** to reveal **read-only fields** (candidates) → instantiate abstract **test templates** → run → dedicated **oracle**.
- **Results (authors):** all seeded vulnerabilities found in almost all case studies, no false positives.
- **Relevance:** direct prior art for F3-W and `workflow.md` §6; its candidate-discovery rules overlap with §6.2 (response-only fields, `readOnly`).

### C4. Vulnerability-oriented API testing (injection/SSRF family; not our families but useful pipeline ideas)

#### C4.1 Nautilus (Deng et al.; USENIX Security 2023) ★★ [A]
- https://www.usenix.org/conference/usenixsecurity23/presentation/deng-gelei · PDF https://www.usenix.net/system/files/usenixsecurity23-deng-gelei.pdf · supplementary https://sites.google.com/view/nautilus-testing
- **Idea:** tester-supplied **specification annotations** encode operation relations and parameter strategies so multi-operation sequences can reach deep vulnerabilities. **Results (authors):** +141 % vulnerabilities and +104 % operations over four tools; 23 0-days, 12 CVEs.
- **Caveats:** needs manual annotation (per 2604.00702); code was announced "soon" on the supplementary page, availability not verified. The author's personal-site summary lists "authorization issues", but the paper abstract and the EvoMaster authors describe it as input-handling vulnerabilities — treat the former as unreliable.
- **Relevance:** the annotation idea ≈ the project's human-validated RSO model.

#### C4.2 VoAPI2 (Du et al.; USENIX Security 2024) ★★ [A]
- https://www.usenix.org/conference/usenixsecurity24/presentation/du · PDF https://usenix.org/system/files/usenixsecurity24-du.pdf · code (mirror/test repo; official repo not confirmed) https://github.com/acciomerlin/VoAPI2-test
- **Pipeline:** parse OpenAPI → **semantic keywords** (derived from CVE/NVD word-frequency analysis) classify an operation's function → map to likely vulnerability types → **reverse sequence construction** (RESTler grammar) → tailored payloads → **feedback-based verification** (callback/verification server) → PoC.
- **Results (authors):** 7 0-days + 19 disclosed bugs on 7 services; 23 CVEs.
- **Relevance:** "function → vulnerability class → targeted sequence" is a rule-based planner prototype; its verification server idea parallels our need for out-of-band evidence (but SSRF is a non-goal).

### C5. Excessive data exposure (F3-R)

| Work | Refs | Idea |
|---|---|---|
| **EDEFuzz** (Pan, Cohney, Murray, Pham; ICSE 2024) ★★★ [A] | DeepDeepAI preprint 2023 (https://api.deepai.org/publication/detecting-excessive-data-exposures-in-web-server-responses-with-metamorphic-fuzzing); PhD thesis https://minerva-access.unimelb.edu.au/server/api/core/bitstreams/086995d8-4055-40af-8ddf-eef34b8cc9bd/content | **Metamorphic fuzzing**: compare related responses (what the UI shows vs what the API returns) to flag sensitive over-sharing without a manual spec; user study showed accuracy and efficiency gains |
| **TrailBlazer** (same authors; registered report, 4th Int'l Fuzzing Workshop 2025) **[C]** | named in the thesis | end-to-end web-API fuzzing |
| **Mockingbird** (Xia et al.; ASE 2025) ★★ [A] | https://tsingpig.github.io/files/ASE%202025%20papers/ASE%202025/pdfs/ASE2025-5DQL9ko9OwpjaORDC0qal7/573300d008/573300d008.pdf · code https://github.com/NeoSunJZ/Mockingbird-JS | **Dangling data**: gray-box dynamic instrumentation of the client to find response fields never consumed |
| OWASP WSTG-APIT-03 *Testing for Excessive Data Exposure* ★★ [R-snippet] | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Testing_for_Excessive_Data_Exposure | maps to **API3:2023 BOPLA**; compare UI-displayed vs returned fields; also mentions source maps and GraphQL |

**Relevance:** `workflow.md` [C2.5] (frontend-derived allowed field set) re-invents the EDEFuzz/Mockingbird insight; cite them as prior art and say what is different (per-actor allowed set; behavioural signals).

---

## 6. Category D: Web-app broken-access-control (BAC) scanners & stateful crawlers

### D1. BACScan (Liu et al., Fudan/CUHK; ACM CCS 2025) ★★★ [R]
- **Refs:** DOI 10.1145/3719027.3744825 · https://yuanxzhang.github.io/paper/bacscan-ccs25.pdf · https://seclab.cse.cuhk.edu.hk/papers/ccs25-BACScan.pdf · prototype "will be open-sourced" (not confirmed)
- **Problem statement:** the classic **response-similarity oracle** (replay victim's request with attacker's session and compare responses) works for *read* BAC but is unreliable for *modification* BAC (MBAC): the direct response often says nothing about whether the write happened (the paper reports error rates of roughly 71 % and 87 % for this oracle on MBAC; its text states the FP/FN order inconsistently).
- **Pipeline:**
  1. Crawl the app with **victim** and **attacker** sessions (Black-Widow-style navigation graph; Playwright).
  2. **Token insertion:** intercept each POST/PUT/DELETE issued by the victim, replace unstructured parameter values with unique random tokens.
  3. Traverse the navigation graph with a **scored hierarchical search** (URL similarity to the redirect target + parameter-name overlap + navigation distance; weights 0.4/0.3/0.3) to find the **status page** where the token appears/disappears → builds the **Inter-page Data Dependency Graph (IDDG)** with INSERT/UPDATE/DELETE edges.
  4. **Replay** the modification with the attacker's session (re-inserting data first for DELETE), then **revisit the status page as the victim**; token appears/disappears ⇒ MBAC. READ BAC uses the similarity oracle (threshold 0.7).
- **Results (authors):** 20 apps, 89 vulnerabilities (54 new), 35 CVEs; MBAC precision 100 % / recall 92.98 % vs Burp+Autorize 62 % / 54.39 % and EvoCrawl 51.5 % / 29.8 %.
- **Limits (authors):** integer-only parameters cannot be token-replaced (false negatives); crawler coverage; GET assumed read-only.
- **Relevance (high):** it validates the project's **effect-based oracle** and the "affected-party readback" in `workflow.md` §5.1, and offers a concrete **footprint-discovery technique** (unique-token injection) for [C2.1]/[C2.2] (AU-9).

### D2. BACFuzz (arXiv 2507.15984) ★ [A]
- Grey-box fuzzing + LLM + SQL tracking for BAC in **PHP** apps; claims to be the first automated fuzzer targeting BAC; notes that fuzzing research rarely addresses logic flaws such as BAC. Language-specific, so mainly context.

### D3. EvoCrawl (Guo, Kawlay, Liu, Lie; NDSS 2025) ★★ [A]
- https://ndss-symposium.org/wp-content/uploads/2025-366-paper.pdf · code https://github.com/dlgroupuoft/evocrawl (as cited by BACScan)
- **Idea:** evolutionary search over interaction sequences so forms actually submit and server-side **state** is explored; +59 % code coverage, 5× more successful form submissions; integrated IDOR/XSS scanners found 8 0-days.
- **Relevance:** state-aware crawl (S-C/S-C2 crawler option); its IDOR check is a response-based oracle.

### D4. Black Widow (Eriksson, Pellegrino, Sabelfeld; IEEE S&P 2021) ★★ [A]
- https://www.cse.chalmers.se/research/group/security/black-widow (code linked there) · DOI 10.1109/SP40001.2021.00022
- **Three pillars:** navigation modelling, traversal, **inter-state dependency tracking**; 63 %–280 % better coverage than other crawlers.
- **Relevance:** the intellectual source of the IDDG; informs `workflow.md` Q6 (crawler as HAR capture assistant).

### D5. Older differential black-box scanners ★ [C]
Li & Xue (BLOCK 2011, LogicScope 2013), Li et al. (CODASPY 2014), AuthScope (CCS 2017), DetLogic (2018), Kushnir et al. (ICISSP 2021), Rennhard et al. *Automating the detection of access control vulnerabilities in web applications* (SN Comput Sci 2022; summary page https://gui-testing-wiki.netlify.app/02-Literature/papers/parameter-tampering/Automating-the-Detection-of-Access-Control-Vulnerabilities-in-Web-Applications), IDORD (RAAICON 2025; crawler + parameter mutation + response analysis; https://dspace.bracu.ac.bd/items/0abd3868-6029-4b8d-8619-fd2ecabb874b). All rely on multi-user replay with response-similarity oracles (per BACScan §2.2). Cite as lineage, not as competitors.

---

## 7. Category E (practitioner / open source) and F (commercial)

### E. Open-source practitioner tooling

| # | Tool | Refs | Pipeline / mechanism | Notes for the project |
|---|---|---|---|---|
| E1 ★★ [A] | **Autorize** (Burp) | https://github.com/Quitten/Autorize · https://github.com/PortSwigger/autorize | Browse as a high-privilege user; every request is **replayed with a low-privilege session and with no session**; status = *bypassed / enforced / enforcement-unclear*; an **enforcement detector** (content-length, string/regex fingerprints) tells deny from allow | Manual-assist baseline for the "Manual/Burp checklist". README itself warns of response-comparison FP/FN (same weakness BACScan quantifies). Its detector filters ≈ project's **calibration signatures** (`workflow.md` §5) |
| E2 ★★★ [A] | **AuthMatrix** (Burp) | https://github.com/SecurityInnovation/AuthMatrix (original; fork notes it is unmaintained since 2018) · blog https://blog.securityinnovation.com/solve-the-software-security-authorization-testing-riddle-with-authmatrix-for-burp-suite | Table of **users × roles × requests**, tick which roles may succeed, per-request **success regex**, **chains** for CSRF tokens/new IDs, save/load for **regression** | Exactly the "role-matrix regression" baseline; chains show how new object IDs are fed to other users |
| E3 ★ [V] | **ZAP Access Control Testing add-on** | described in https://www.stackhawk.com/blog/api-security-testing-tools/ (vendor comparison) | user/role rules, per-URL checks | Reported as alpha and needing explicit user/rule setup — verify on the ZAP site before citing |
| E4 ★★ [A] | **Akto** (MIT core) | https://github.com/akto-api-security/akto · tests https://github.com/akto-api-security/tests-library · role-based testing doc https://docs.akto.io/api-security-testing/how-to/conduct-role-based-testing | Traffic-mirroring or Burp/Postman import → API inventory → test library (BOLA by swapping auth token, BFLA by changing method, old-API-version BOLA, etc.) selected per role | Comparable "inventory + tests" pipeline; vendor repositioning toward AI security as of Aug 2026 (per StackHawk), so check maintenance status |
| E5 ★ [V] | **Metlo** (MIT) | cited in the StackHawk roundup | traffic-based discovery + auto-generated OWASP tests | Same roundup reports no substantive code commit since Aug 2023 — low priority |
| E6 ★★★ [A] | **mitmproxy2swagger** | https://github.com/alufers/mitmproxy2swagger | mitmproxy flow or **browser-DevTools HAR** → two-pass OpenAPI 3.0 generation (manual path-template review, then description pass; merges multiple captures) | Directly relevant to **S-A**: reuse or imitate for HAR→operation inventory; note its `--examples` flag can leak secrets into the spec |

### F. Commercial / closed source (lower priority)

> No peer-reviewed papers found for these (only vendor documentation / blogs). Most claims below come from a **competitor-authored** roundup (StackHawk, Aug 2026) and from vendor pages, so treat them as **[V]**.

| # | Product | Public technical material | What it claims on authorization | Access |
|---|---|---|---|---|
| F1 | **StackHawk (HawkScan)** | https://www.stackhawk.com/solutions/business-logic-testing/ · https://docs.stackhawk.com/hawkscan/business-logic-testing/ | **Cross-profile BOLA** (resources discovered by one profile read with another's credentials; compares peers at the same role) and **cross-profile BFLA** (privileged operations mutated by unprivileged profile; `isPrivileged` marks elevated profiles); BOPLA plugins; custom scripts for multi-step flows. Needs OpenAPI, working credentials, ≥ 2 identities. Self-describes as aggressive (create/update/delete) → use staging | Docs public; product commercial |
| F2 | **Wallarm API Security Testing** | via StackHawk roundup | Agentic DAST container in CI; OpenAPI/Postman input; BOLA, BFLA, broken auth and multi-step logic; attaches **reproducible proof of exploit** to findings | Demo-gated, from $3k/yr (per roundup) |
| F3 | **APIsec** | via roundup | Builds an app model, generates and executes attacks, re-runs exploit to verify fixes | Free tier limited to public/test APIs |
| F4 | **42Crunch** | via roundup | OpenAPI audit + conformance/drift scans; **Scan v2 identity tests** for BOLA/IDOR and BFLA (source credential vs target credential per operation) | 14-day trial, enterprise for CI |
| F5 | **Burp Suite Pro / DAST** | https://portswigger.net (not opened) | Manual-centric; extensions (Autorize, AuthMatrix); "Burp AT" agentic capability in beta per roundup | Commercial |
| F6 | **XBOW** | https://xbow.com/blog/xbow-finds-idors-high-accuracy-ambiguous-context (May 2026) | LLM-agent pentester; **multi-account** exploration; "learn what normal access looks like before attacking" (expected-access reasoning) — conceptually similar to the project's inferred-policy idea | Commercial; blog only |
| F7 | **Invicti** | https://www.invicti.com/blog/web-security/how-to-detect-bola-api-vulnerability (blog, accessible) | Methodology: 3–4 accounts (User A source of IDs, User B cross-user, admin, read-only), authorization matrix, test all HTTP verbs and multi-step flows; "proof-based" scanning claim | Whitepapers/product material may be **gated by a contact form — not accessed**; ranked lowest per brief |
| F8 | Salt Security, Imperva, Akamai API Security, Postman/SoapUI | per roundup | Runtime/posture or functional-testing products; Akamai now advertises 200+ pre-production API tests | Not DAST authorization testers; skip unless needed |

---

## 8. Cross-cutting comparison

### 8.1 Capability matrix (only what sources support; `?` = not verified)

| System | Input | Dependency / state model | Multi-actor | Authorization oracle | Policy/ownership source | Open |
|---|---|---|---|---|---|---|
| RESTler | OpenAPI | producer-consumer + feedback | 2 namespaces (checker) | fixed rule: user-namespace | implicit strict isolation | ✔ |
| Morest | OpenAPI | RPG (CRUD + schema) updated by responses | ✘ | ✘ (5xx etc.) | ✘ | ? |
| RestTestGen | OpenAPI | ODG | ✘ (except MA strategy) | mass-assignment oracle | read-only field inference | ✔ |
| Schemathesis | OpenAPI/GraphQL | OpenAPI `links` (optional) | ✘ | generic conformance checks | ✘ | ✔ |
| **EvoMaster (2604.00702)** | OpenAPI + creds ≥ 2 users | test slicing/splicing over fuzz suite | ✔ | 7 access/leak oracles + SQLi/XSS | **inferred from 401/403 + HTTP-semantics heuristics** | ✔ |
| Nautilus | OpenAPI + **manual annotations** | annotated operation relations | ? | injection-type | n/a | partial |
| VoAPI2 | OpenAPI | reverse sequence from RESTler grammar | ✘ | payload + verification server | keyword → vuln-type mapping | partial |
| BOLABuster | OpenAPI 3 | LLM-built dependency tree | ✔ (2 accounts implied) | BOLA only | LLM + heuristics | ✘ (not confirmed) |
| **BACScan** | web app + 3 accounts | **IDDG** (inter-page data dependency) | ✔ | **feedback-driven (effect) + similarity** | none needed | prototype planned |
| Autorize | proxy traffic | none | ✔ (low-priv + unauth) | response compare + enforcement detector | tester-configured fingerprints | ✔ |
| AuthMatrix | manual config | chains | ✔ | per-request success regex per role | **explicit user-defined matrix** | ✔ |
| StackHawk [V] | OpenAPI + ≥ 2 profiles | ? | ✔ | cross-profile BOLA/BFLA | profiles + `isPrivileged` | ✘ |
| **This project** | OpenAPI + HAR + inventory | RSO + normative state graph + invariants | ✔ | differential + property-policy + state-invariant (effect-based) | **reviewed access policy + state graph (versioned)** | — |

**What no surveyed open-source system combines** (to be re-checked once the AU-1 matrix is redone): reviewed/versioned normative policy **and** state graph as oracle input · effect evidence for every verdict · actor-aware sequence planner · hard safety gateway/DSL · benign-twin ground truth. This supports the *composition* formulation already used in `survey_and_boundary.md` §11, but not any claim that a single capability is absent from all tools.

### 8.2 Oracle catalogue (what each family of tools treats as "violation")

| Oracle style | Examples | Weakness reported in the literature | Our counterpart |
|---|---|---|---|
| Fixed security rule on status codes | RESTler namespace rule | too strict for legitimate cross-user rights | differential oracle uses reviewed policy |
| Status-code pattern + HTTP-semantics heuristic | EvoMaster (missed check, ignore-anonymous…) | noise when API returns 200 with error body; requires prior 2xx | calibration probes + effect evidence |
| Response similarity | Autorize, EvoCrawl, Rennhard et al. | unreliable for modifications (BACScan) | readback by affected party |
| **Feedback / effect-driven** | BACScan (token on status page) | needs data-dependency discovery; integer params | `workflow.md` §5.1 + footprint hashing |
| Role-matrix + regex | AuthMatrix | manual setup; regex brittle | RSO + `access_policy.yaml` |
| Metamorphic comparison | EDEFuzz | needs related request pairs | property-policy diff |
| Payload + callback/time | VoAPI2, EvoMaster SQLi | non-goal for us | — |

### 8.3 Pipeline-stage coverage (rough)

| Stage (`workflow.md`) | Strong prior art | Gap left for us |
|---|---|---|
| S-A ingest (OpenAPI + HAR) | mitmproxy2swagger, RESTSpecIT, APIF (proxy) | untrusted-HAR hardening, actor labelling |
| S-B dependency graph / flows | RESTler, Morest, RestTestGen ODG, AutoRestTest SPDG | typed ownership/tenant edges |
| S-C seed planting / sessions | EvoMaster slicing, AuthMatrix chains, BACScan re-insertion for DELETE | known-owner planting with reset isolation |
| S-C2 inference (effects/footprints) | BACScan IDDG/token, EDEFuzz metamorphic | footprint hashing + destructiveness tags |
| S-D model synthesis + freeze | Nautilus annotations (manual) | evidence-tiered, versioned, human-promoted model |
| S-E/F probes | EvoMaster, StackHawk, Autorize, RestTestGen-MA | taxonomy-driven templates F1–F5 |
| S-G safety gateway | **none in academic tools**; vendors only warn | main engineering contribution |
| S-H oracle | EvoMaster, BACScan | policy-grounded, effect-based, benign twins |
| Phase-2 planner | ARAT-RL, DeepREST, APIRL, AutoRestTest, BOLABuster | objective = valid violations under budget with HITL feedback |

---

## 9. Audit of project decisions against this literature

Severity: **H** = changes a claim or a result; **M** = fix before M1/M2 review; **L** = housekeeping. "Evidence" cites the project file and the source.

| ID | Sev | Finding | Evidence | Recommended action |
|---|---|---|---|---|
| **AU-1** | **H** | The **non-overlap matrix** (`survey_and_boundary.md` §10.2) lists only WSTG, RESTler, Schemathesis, crAPI. It omits the closest prior art: EvoMaster access-policy oracles, BACScan, Nautilus, VoAPI2, RestTestGen mass assignment, AuthMatrix/Autorize and commercial cross-profile testers. Two cells are contestable: RESTler "Multi-Actor … Limited/Unsupported" and "Differential Authorization Oracle: Plugin-dependent" (RESTler ships a user-namespace checker, ICST 2020). | §3 A1, A6, C1, D1, E1–E2 | Rebuild the matrix with §8.1; replace "No" with "partial/heuristic" where applicable; keep the *composition* gap statement |
| **AU-2** | **H** | `research_gaps.md` Gap 2 claims schema-based DAST has "no" ownership/session awareness. Overstated: RESTler has a namespace rule; EvoMaster tests with ≥ 2 users. The defensible gap is: they **infer policy heuristically from status codes** or assume strict isolation, have **no normative policy/state model, no effect evidence, no safety DSL**, and optimise coverage/5xx, not valid violations. | 2604.00702 §2–3 | Rewrite Gap 2 accordingly; cite the EvoMaster limitation text |
| **AU-3** | **M** | WSTG mapping errors: (a) the survey says `WSTG-ATHZ-02` covers privilege escalation, schema bypass **and** IDOR — in WSTG these are **ATHZ-02 (bypass authorization schema), ATHZ-03 (privilege escalation), ATHZ-04 (IDOR)**. (b) The "Testing Methodology" source row and claim **C02** link to the **WSTG-INFO-01** (search-engine reconnaissance) page, not an authorization page. (c) Missing mappings: **WSTG-APIT-03** (excessive data exposure ↔ API3:2023) and business-logic tests **WSTG-BUSL-02 (forge requests), BUSL-05 (limits on function use)** for F5. | WSTG index listings found in search | Fix IDs and URLs; add APIT-03/BUSL entries to `families.yaml` mapping |
| **AU-4** | **H** | **Cyber-range target inconsistency.** The survey freezes **crAPI** as "primary Cyber Range benchmark" and as the frozen threat-model target; `families.yaml` says crAPI has **no tenants** (F4 needs custom apps); `GroundTruth_Metrics_Coverage.md` §9 and the tests show the real range is the **custom mock (TenantDesk/ShopFlow)**. | files cited | Update the boundary freeze: primary = custom apps, crAPI = external validation only; record the decision with a version |
| **AU-5** | **M** | (a) `families.yaml` has `status: frozen` while its `decisions:` block says "pending confirmation by the team" and every `cwe_status: unverified`. (b) **D3** declares 401/403/404 equivalent safe outcomes; EvoMaster treats **403-vs-404 existence leakage** and **authenticated-user-gets-401** as distinct findings/usability faults. | families.yaml; 2604.00702 §3.1–3.2 | Either confirm decisions and drop "frozen" until then, or freeze with an explicit note: "existence leakage = out of scope / reported as `ineffective_attempt` sub-class". Decide before M1 |
| **AU-6** | **M** | `Taxonomy/README.md` `Oracle_BOLA` pseudocode flags only when actor ≠ owner **AND** actor tenant ≠ object tenant, so **same-tenant non-owner access (F1, the horizontal case its own text describes) is never flagged**; it also flags on 2xx alone (already noted as R1 in `workflow.md`). | README §3.1 | Fix the logic (`OR`/separate F1 vs F4 branches) or mark the README as superseded by `families.yaml` |
| **AU-7** | **H (P2 planning)** | The Phase-2 hypothesis (≥ 20 % precision@budget over the **best baseline**) will realistically face **EvoMaster + its security phase**, not just RESTler/Schemathesis-style baselines. Its security phase is cheap (median ≈ 14 s) and open source. | 2604.00702 §5.6 | Add EvoMaster (black-box, ≥ 2 users) and RestTestGen-MassAssignment to the baseline list now; pre-register metric alignment (AU-8) before any run |
| **AU-8** | **L/M** | Fault counting in the literature is **per failing endpoint** and uses **WFC fault codes** (F2xx security, F9xx work-in-progress) and a WFC YAML format for auth info. Our metrics count planted cases. | 2604.00702 §5.4 | Provide a mapping table family→WFC code; export auth config in WFC format so baselines run on identical credentials |
| **AU-9** | **Opp.** | BACScan's **unique-token injection + status-page discovery** is a ready technique for `workflow.md` [C2.1/C2.2] (relation module: which read reflects which write) and for F3-W readback. Its documented blind spot (integer-only parameters) should be noted. | §6 D1 | Add as optional probe in [C2]; mark as `inferred` footprint source |
| **AU-10** | **M** | **Credential-mutating endpoints** (crAPI, capital, VAmPI) invalidate fuzzer logins in black-box runs; reset-capable white-box runs avoid this. Relevant to decision D2 (broken authentication out of scope), actor liveness checks (§12) and reset policy. | 2604.00702 §5.4 | Keep "actor liveness before tests" as CORE, not deferred; add the credential-mutating operations to destructiveness tag `session_affecting` explicitly |
| **AU-11** | **L** | **References in the project description:** [7] "RestFuzz … ASE" could not be verified; [8] and [9] are generic venue names, not citable papers; [6] QuickREST is confirmed (ICST 2020). | project description | Replace [7]–[9] with verified entries from §13 (e.g. Golmohammadi survey, Zhang & Arcuri comparison, Nautilus, VoAPI2) |
| **AU-12** | **L** | Claim **C05** (Schemathesis lacks multi-actor tracking) cites "documentation" without a link; the paper's own scope statement is about schema-derived properties, not authorization. | survey §10.1 | Cite arXiv 2112.10328 plus the specific checks list from the docs; phrase as "does not provide" not "cannot" |
| **AU-13** | **L** | `docs/research_questions.md` contains a **splice**: RQ3's analysis stops mid-sentence ("A simple HTTP-status check is insufficient."), then RQ1 starts again, and the file ends with a dangling "## 5." | file content | Re-merge the two drafts; keep the Phase-1 boundary table |
| **AU-14** | **Info** | **Safety positioning is defensible:** none of the academic systems in §3–6 describe an allowlist/budget/kill-switch gateway or a restricted action DSL; vendors only advise "use staging". LLM-based BOLA work is criticised for unclear oracles and hallucinated findings — consistent with the project's grounding and replay-evidence rule. | 2604.00702 §2; StackHawk | Keep these as headline contributions; cite the criticism |

**Incidental findings from the code scaffold (outside this survey, flagged for the owners):**
- `src/gateway/engine.py::decide()` returns **allow by default**, contradicting DR6/default-deny and the KPI "0 requests outside allowlist"; acceptable only while it is a stub — add a failing test to prevent live use.
- `src/common/redaction.py::redact_payload()` is a **pass-through placeholder** while the store contract (Architecture §6.1 rule 3) assumes events arrive redacted; add the "hash-before-redact" test before any real capture.

---

## 10. Proposed amendments for `workflow.md` / `architecture.md` (for the owner to merge)

1. **Add §"Prior-art baselines"** listing RESTler (user-namespace checker), EvoMaster (security phase), RestTestGen-MassAssignment, Schemathesis, AuthMatrix/Autorize-style role-matrix regression; mark which are runnable against the lab with identical credentials.
2. **R2 resolution proposal:** when no confirmed policy exists, run **policy-free heuristics** as *candidate generators only* (verdict `needs_review`): (i) two of PUT/PATCH/DELETE denied but one allowed; (ii) anonymous 2xx on mutating methods; (iii) 2xx without credentials after 401/403 with credentials; (iv) undeclared verb accepted. Provenance = `heuristic`, never promoted without human confirmation.
3. **[C2] relation discovery:** add the optional **unique-token probe** (BACScan) and the **test slicing/splicing** construction (EvoMaster) as ways to obtain self-contained sequences from HAR templates.
4. **Calibration:** add the case "200 with application-level error body" as a named signature class (`status_unreliable`), citing the Norwegian-API example in 2604.00702.
5. **Findings model:** add sub-classes `existence_leakage` and `wrong_401` (reported separately, excluded from precision unless the family decision says otherwise).
6. **Taxonomy:** extend mapping with WSTG-ATHZ-02/03/04, WSTG-APIT-03, WSTG-BUSL-02/05; correct the README oracle (AU-6).
7. **Metrics:** add an interoperability table to WFC fault codes (AU-8); keep ground truth and metric definitions frozen before baselines are run.
8. **Input contract:** document `mitmproxy2swagger`-style HAR→inventory as the reference for S-A, including the secret-leak caveat for `--examples`.

---

## 11. Reading order & adoption list

**Tier 1 — read in full before the boundary freeze (≈ 1 week):**
1. arXiv 2604.00702 (EvoMaster security oracles) — already read; re-read §3–§5 with AU-1/2/5/7 in mind.
2. BACScan (CCS 2025) — already read; extract the oracle comparison tables.
3. RESTler ICST 2020 checkers.
4. Mass assignment (ICSE 2023).
5. Golmohammadi survey + Zhang & Arcuri comparison.

**Tier 2 — Phase-2 planner/ranker:** ARAT-RL, AutoRestTest, DeepREST, APIRL, LlamaRestTest, BOLABuster, Karate-BOLA-Guard.

**Tier 3 — module-specific:** EDEFuzz/Mockingbird (F3-R), Morest (graph update rules), EvoCrawl/Black Widow (crawler), Nautilus/VoAPI2 (annotation, function→vuln mapping), RESTSpecIT (spec inference).

**Adopt / reuse candidates (license permitting):**
| Need | Candidate | Note |
|---|---|---|
| Baseline fuzzers | RESTler, Schemathesis, EvoMaster, RestTestGen | all open source |
| Role-matrix baseline reference | AuthMatrix, Autorize | Burp-based; use as procedure reference or run manually for the "manual/Burp" baseline |
| HAR → inventory | mitmproxy2swagger | review output manually; strip examples |
| External corpora | WFD, crAPI, VAmPI | for validation, not ground truth |
| Auth config + fault codes | Web Fuzzing Commons (WFC) | interoperability with EvoMaster |

---

## 12. Not found / not verified / excluded

- **Not found:** an open-source tool that combines normative policy + state-graph oracle + safety gateway + benign-twin evaluation (consistent with the project's gap, but absence of evidence — re-search before the final report).
- **Not opened ([C]):** RESTGPT, NLP2REST, ARTE, QuickREST, RestCT, bBOXRT, MINER, ResTest, Pythia, APIF, TrailBlazer, AuthScope, DetLogic, LogicScope, SBFT'26 competition report, the Petri-net BOLA paper.
- **Unverified claims:** Morest repository location; Nautilus code release; BACScan open-sourcing; BOLABuster peer-review/code; ZAP add-on maturity; Metlo/Akto status (all taken from vendor roundup).
- **Gated/commercial:** Invicti whitepapers (not accessed), Wallarm/APIsec/42Crunch deep docs, Burp product pages.
- **Excluded:** runtime-protection and posture platforms (Salt, Imperva) and functional-testing tools (Postman, SoapUI) — not dynamic authorization testers.
- **Quality caveat:** the StackHawk comparison is written by a competitor; use it only to locate products, not to judge them.

---

## 13. Reference index

**Surveys / comparisons**
- Golmohammadi, Zhang, Arcuri. *Testing RESTful APIs: A Survey.* TOSEM 2023. https://arxiv.org/pdf/2212.14604
- Zhang, Arcuri. *Open Problems in Fuzzing RESTful APIs: A Comparison of Tools.* https://arxiv.org/pdf/2205.05325

**A — General generators**
- RESTler: https://github.com/microsoft/restler-fuzzer · ICSE'19 https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing · ICST'20 https://patricegodefroid.github.io/public_psfiles/icst2020.pdf · MSR-TR-2019-1 https://www.microsoft.com/en-us/research/publication/checking-security-properties-of-cloud-services-rest-apis/
- Morest: https://arxiv.org/abs/2204.12148 · https://sites.google.com/view/restful-morest/home
- RestTestGen: https://github.com/SeUniVr/RestTestGen · https://profs.scienze.univr.it/~ceccato/papers/2022/icsme2022.pdf · https://profs.scienze.univr.it/ceccato/papers/2022/stvr2022.html
- RESTest: https://github.com/isa-group/RESTest · https://idus.us.es/handle/11441/133642
- Schemathesis: https://github.com/schemathesis/schemathesis · https://arxiv.org/abs/2112.10328
- EvoMaster: https://github.com/WebFuzzing/EvoMaster · https://arxiv.org/pdf/1901.01538 · https://arxiv.org/pdf/2604.00702 · https://github.com/WebFuzzing/Dataset
- WuppieFuzz: https://github.com/TNO-S3/WuppieFuzz · https://www.alphaxiv.org/abs/2512.15554.md

**B — Learning / LLM**
- ARAT-RL: arXiv 2309.04583 · DeepREST: https://arxiv.org/abs/2408.08594 · APIRL: arXiv 2412.15991 · AutoRestTest: https://arxiv.org/abs/2411.07098 · LlamaRestTest: https://arxiv.org/abs/2501.08598 · KAT: https://www.arxiv.org/pdf/2407.10227 · RESTSpecIT: https://arxiv.org/abs/2402.05102

**C — Security**
- Mass assignment: https://arxiv.org/abs/2301.01261 · https://zenodo.org/records/10000153
- Nautilus: https://www.usenix.org/conference/usenixsecurity23/presentation/deng-gelei · https://www.usenix.net/system/files/usenixsecurity23-deng-gelei.pdf
- VoAPI2: https://www.usenix.org/conference/usenixsecurity24/presentation/du · https://github.com/acciomerlin/VoAPI2-test
- BOLABuster: https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
- Karate-BOLA-Guard / SOCO: see §5 C2.2 URLs
- EDEFuzz thesis: https://minerva-access.unimelb.edu.au/server/api/core/bitstreams/086995d8-4055-40af-8ddf-eef34b8cc9bd/content · Mockingbird: https://github.com/NeoSunJZ/Mockingbird-JS
- OWASP WSTG-APIT-03: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Testing_for_Excessive_Data_Exposure

**D — Web BAC**
- BACScan: https://yuanxzhang.github.io/paper/bacscan-ccs25.pdf · BACFuzz: https://arxiv.org/html/2507.15984v1 · EvoCrawl: https://ndss-symposium.org/wp-content/uploads/2025-366-paper.pdf · Black Widow: https://www.cse.chalmers.se/research/group/security/black-widow

**E/F — Tools & vendors**
- Autorize: https://github.com/Quitten/Autorize · AuthMatrix: https://github.com/SecurityInnovation/AuthMatrix · Akto: https://github.com/akto-api-security/akto · mitmproxy2swagger: https://github.com/alufers/mitmproxy2swagger
- StackHawk roundup (vendor): https://www.stackhawk.com/blog/api-security-testing-tools/ · XBOW: https://xbow.com/blog/xbow-finds-idors-high-accuracy-ambiguous-context · Invicti blog: https://www.invicti.com/blog/web-security/how-to-detect-bola-api-vulnerability