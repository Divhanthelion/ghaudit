# Privacy-Preserving Security Analysis for LLM-Based Code Tools

**No single solution fully protects proprietary code when using external LLMs—but practical, layered defenses exist today.** The most effective approach combines local-first analysis using quantized code LLMs (CodeLlama, StarCoder2) for sensitive processing, code abstraction via AST/CPG transformations before any cloud submission, and streaming/incremental architectures that never persist full repositories. Homomorphic encryption remains impractical for LLM inference (**$5,000+ per token**), while code embeddings offer partial privacy but can be reconstructed with up to **92% accuracy**—though defenses like product quantization can completely eliminate this risk with no utility loss.

Organizations must treat source code as potentially personal data under GDPR when it contains developer identifiers, implement proper Data Processing Agreements with LLM providers, and establish clear boundaries between local and cloud processing tiers. This report synthesizes cutting-edge research and production-ready tools across seven technical domains to provide an implementation roadmap for privacy-preserving security analysis.

---

## Homomorphic encryption cannot yet protect LLM-based code analysis

The mathematical promise of homomorphic encryption—computing on encrypted data without decryption—has captured significant research attention, but practical application to LLM inference remains **orders of magnitude too expensive**. According to Zama's analysis, the current cost per token for fully encrypted LLM inference is approximately **$5,000**, requiring a **500,000× improvement** to reach the $0.01/token threshold needed for viability. Each token requires roughly 1 billion large-precision programmable bootstrapping operations, while current CPU throughput achieves only ~200 8-bit PBS/second.

The most mature FHE libraries include **OpenFHE** (DARPA-supported, multiple schemes), **Microsoft SEAL** (BFV, BGV, CKKS), **TFHE-rs** from Zama (programmable bootstrapping, GPU support), and **Concrete ML** (scikit-learn/PyTorch APIs for encrypted ML). GPU acceleration via frameworks like CAT has achieved up to 2173× speedup on NVIDIA 4090, and recent research from IBM (PowerSoftmax, ICLR 2025) demonstrated the first encrypted models with **1+ billion parameters**—but inference speed remains impractical for interactive use.

For smaller neural networks, encrypted inference is becoming viable: MNIST classification now runs in **0.04-10 seconds** depending on implementation, and GPU-accelerated TFHE achieves 0.04 seconds for basic image classification. However, the critical bottleneck for code analysis lies in the non-polynomial operations that transformers require. Standard Softmax, GELU, and LayerNorm activations require polynomial approximations that degrade accuracy, while the quadratic attention complexity of transformers compounds the computational burden exponentially with sequence length.

The most feasible current approach is **split-model hybrid inference**, demonstrated by Zama's Concrete ML: clients run token embedding layers locally, encrypt intermediate states for server processing of specific attention head computations, then decrypt and continue locally. For GPT-2 with sequence length 6, this requires approximately 11,622 PBS operations per attention head with 4-bit quantization maintaining ~96% of original accuracy. A practical implementation achieving **1.61 seconds/token** inference has been demonstrated using ChatGLM2-6B with CKKS encryption and LoRA fine-tuning.

For code analysis specifically, only research prototypes exist. A notable paper demonstrated pointer analysis on encrypted programs using somewhat homomorphic encryption with O(log m) complexity for m pointer variables—but comprehensive AST processing, pattern matching, and semantic analysis remain impractical. Organizations should consider homomorphic encryption as a future technology rather than a current solution, while monitoring developments from Zama, IBM, and Google's HEIR compiler project.

---

## Code abstraction preserves security patterns while removing proprietary identifiers

The most immediately practical approach to privacy-preserving analysis involves transforming code into abstract representations that preserve security-relevant patterns while stripping proprietary information. This technique leverages the insight that vulnerability detection depends on **structural and flow patterns**, not identifier names or specific implementation details.

**Abstract Syntax Trees (AST)** form the foundation of most abstraction approaches. Tools like **Tree-sitter** (supporting 81+ languages via WASM) and **srcML** (XML-based representation) parse source code into tree structures where nodes represent constructs (variables, functions, expressions) and edges capture relationships. Security-relevant patterns—SQL injection via method calls involving user input, taint flow from sources to sinks, dangerous coding patterns—remain fully detectable in AST form even after identifier normalization. The transformation pipeline typically replaces `calculateDiscount()` with `FUNC_001()` and `username` with `VAR_001`, maintaining consistent mapping throughout the codebase while destroying proprietary naming conventions.

**Code Property Graphs (CPGs)**, which combine AST, Control Flow Graph, and Program Dependence Graph into a unified representation, provide even richer abstraction for security analysis. **Joern**, the leading open-source CPG platform, generates queryable graphs for C/C++, Java, JavaScript, Python, and Kotlin that naturally abstract away naming while preserving the data flow and control flow relationships essential for vulnerability detection. Research has demonstrated that CPG-based methods achieve state-of-the-art results—SCGformer (2023) achieved **94.36% accuracy** for smart contract vulnerability detection using CFG + Transformer architectures.

For ML/LLM pipelines specifically, **path-based representations** like those used by **code2vec** decompose code into collections of AST paths represented as triplets of (start_token, AST_path, end_token). The statement `x = 7` becomes `⟨x, (NameExpr ↑ AssignExpr ↓ IntegerLiteralExpr), 7⟩`. These path-contexts aggregate via attention mechanisms into fixed-length code vectors suitable for neural network processing without exposing raw source. GraphCodeBERT extends this by incorporating data flow information, achieving 0.3% accuracy improvement over CodeBERT for vulnerability detection while operating entirely on graph representations.

A practical anonymization pipeline should proceed through five stages: parsing (Tree-sitter/srcML generates AST), identifier extraction (variable names, function names, class names, string literals, comments), sensitive data detection (Microsoft Presidio for PII patterns, regex for API keys and credentials, custom recognizers for proprietary terms), transformation (consistent normalization while preserving types, control flow, and data flow), and output generation (anonymized source, serialized AST, or code embeddings with mapping file for potential de-anonymization). The key principle is that security patterns depend on **what** code does, not **what things are called**.

---

## Local-first architectures with quantized code LLMs provide practical privacy today

The rapid maturation of efficient, open-source code LLMs has made local-first security analysis genuinely practical. A **Mac Mini M4 Pro with 64GB unified memory** (approximately $1,400) can run 32B parameter models at 11-12 tokens/second—sufficient for real-time code security scanning without any data leaving the device. The key enabler is **4-bit quantization** in GGUF format, which reduces memory requirements by ~75% with less than 2% quality degradation.

The most capable local code models for security analysis include **CodeLlama** (7B-70B parameters, 53.7% HumanEval, fill-in-middle capability), **StarCoder2** (3B-15B parameters, 80+ language support, 8K-16K context), **Qwen2.5-Coder** (7B-32B parameters, **86.6% HumanEval** on Python), and **DeepSeek Coder** (1.3B-33B parameters, strong reasoning from 2T training tokens). Research has validated these for security tasks: fine-tuned CodeLlama achieves **0.62 F1-score improvement** in vulnerability detection, while StarChat demonstrates superior semantic understanding for malware analysis.

For deployment, **Ollama** provides the simplest user experience with automatic model management and REST API, while **llama.cpp** offers maximum performance with GGUF format support and GPU/CPU flexibility. **LM Studio** adds a GUI with no telemetry for privacy-conscious users, and **vLLM** enables production-grade serving with continuous batching and PagedAttention for teams deploying to multiple users.

The optimal hybrid architecture implements **confidentiality-tiered processing**: highly sensitive data (credentials, PII, proprietary algorithms) receives local-only processing; moderate sensitivity data (sanitized code structure, redacted snippets) can use hybrid cloud queries after anonymization; low sensitivity data (public library usage, generic patterns) can flow to cloud APIs for maximum capability. Decision criteria should include data classification, complexity thresholds (simple patterns local, complex reasoning cloud when acceptable), context window requirements (very large context may require cloud), and confidence scores (low-confidence local results escalate to cloud).

**Federated learning** enables continuous security model improvement without sharing raw code. The **VDBFL framework** (Vulnerability Detection Based on Federated Learning) combines code property graphs for semantic representation with graph neural networks and horizontal federated learning—multiple parties contribute to model training without sharing source code. Research demonstrates VDBFL **outperforms centralized methods** across multiple metrics while maintaining data privacy. Related frameworks like VulFL and FedGAT extend these principles to specific use cases including smart contract security (FedVuln achieves **95.04% accuracy** with federated aggregation).

Production hybrid deployments show compelling economics: a fintech company reduced costs from $47k/month (GPT-4o Mini) to **$8k/month** using Claude Haiku plus self-hosted 7B models, an 83% reduction while improving privacy. The breakeven point for self-hosting typically occurs around 2 million tokens/day, after which local infrastructure costs less than API pricing while providing complete data control.

---

## Differential privacy can protect aggregate security findings but faces unique challenges

Differential privacy provides mathematically rigorous guarantees that individual records cannot be distinguished from aggregate statistics—highly valuable for vulnerability databases and security metrics dashboards. However, applying DP to security data presents unique challenges that limit direct application, and **no privacy-preserving CVE/NVD standard currently exists** despite the clear need.

The core mechanisms for security data include the **Laplace mechanism** (adds noise from Laplace distribution with scale Δf/ε, suitable for numeric counts like vulnerability tallies) and **Gaussian mechanism** (adds noise from N(0,σ²), better for high-dimensional data and composition). Real-world epsilon (privacy budget) values provide guidance: the US Census 2020 used ε=19.61 total, LinkedIn uses ε=14.4 over 3 months, Google RAPPOR uses ε=2 per upload with ε=8-9 lifetime, and Apple macOS uses ε=6 for system telemetry.

For security-specific applications, recommended epsilon values scale with sensitivity: **ε ≤ 1** for highly sensitive vulnerability data (zero-days, unpatched issues), **ε = 1-5** for organization-specific metrics, **ε = 5-15** for industry-wide statistics, and **ε = 10-20** for historical/patched vulnerabilities. The fundamental trade-off is that lower epsilon provides stronger privacy but adds more noise—for vulnerability counts, a true count of 150 with ε=1.0 yields approximately 150 ± 2.5 with 95% confidence.

**PRACIS** (Privacy-preserving Aggregatable Cybersecurity Information Sharing) represents the state-of-the-art for security-specific implementations, combining format-preserving and homomorphic encryption with STIX threat intelligence format. It can aggregate **10,000 security incidents in 2.1 seconds** with 13.5 kbps transmission overhead. For secure aggregation without a trusted curator, the **Prio protocol** (deployed by Firefox and Apple exposure notifications) uses secret sharing across multiple aggregators—each client shares data fragments such that aggregators can compute only the sum without seeing individual values.

Cloudflare's **Distributed Aggregation Protocol (DAP)** implementation demonstrates three randomization approaches with different privacy/trust trade-offs: central DP (collector adds noise post-aggregation, requires trusted collector), local DP (clients add noise before submission, strongest privacy but 10-100× more noise needed), and aggregator randomization (each aggregator adds noise to shares, recommended balance). Their Network Error Logging implementation uses discrete Gaussian/Laplace mechanisms through the open-source Daphne implementation.

Key challenges specific to security data include **rare vulnerability types** (low-frequency events have high relative error—one zero-day plus Laplace(1) noise yields 0-2, a 50% relative error), **organization re-identification** (aggregate statistics may reveal which org reported if only one uses affected software), **temporal patterns** (sequential releases enable differencing attacks), and **code location sensitivity** (file paths and function names are quasi-identifiers even in aggregated reports). The most significant barrier is that security reporting mandates (SOC 2, PCI-DSS) often require exact counts rather than noisy estimates, limiting where DP can apply.

Open-source implementations include **OpenDP** (comprehensive Rust/Python/R framework with vetted algorithms), **Google DP Library** (C++/Go/Java with bounded aggregations), **Tumult Analytics** (high-level API with budget management), and **TensorFlow Privacy** (DP-SGD for model training). For security metrics dashboards, organizations should implement quarterly budgets of approximately ε=10 for interactive queries with per-query tracking and caching to avoid budget exhaustion on repeated queries.

---

## Streaming analysis enables security scanning without persisting repositories

The principle of compositional analysis—analyzing procedures independently and storing only summaries rather than source—provides a proven foundation for privacy-preserving security tooling. **Facebook Infer** demonstrates this at scale: running in diff-time mode (analyzing only changed code rather than entire codebases) improved developer fix rates from near-zero to **70%+** while targeting 15-20 minute completion times for PR analysis.

Infer's architecture translates code to **SIL (Smallfoot Intermediate Language)**, then uses bi-abduction for compositional program analysis. The key insight is that changing one procedure does not necessitate re-analyzing all others—only procedures with affected dependencies require recomputation. Summaries containing pre/post conditions can be stored and reused without exposing original source code, enabling up to **80% time savings** compared to full recomputation while the ephemeral analysis zone processes source that is immediately destroyed.

**Semgrep** provides diff-aware scanning with `--baseline-commit` for CLI scans and `SEMGREP_BASELINE_REF` environment variable for CI/CD. Cross-file analysis is available with the `--pro` flag, and `--diff-depth` controls how deep differential analysis extends into the call graph. The pattern-based approach scans only changes between baseline and current commit, dramatically reducing both processing time and data exposure. For secrets specifically, **detect-secrets** runs periodic comparisons against heuristically crafted regex without scanning entire git histories, while **TruffleHog** supports `--since-commit` for incremental scanning.

The research frontier includes **CodeQL incremental analysis**, currently not production-supported but studied in GitHub's research prototype. Findings from ESEC/FSE 2023 demonstrate that small commits lead to small changes in analysis results—greater than 10% change rates only occur for commits affecting more than 1000 lines. The hybrid approach combining incremental evaluation (Viatra Queries) with non-incremental CodeQL achieves ~15 minute initialization and ~20GB memory usage, compared to fully incremental (~15 second updates but 70GB memory and 1+ hour initialization).

**Partial program analysis** enables security scanning without access to complete codebases. The **GRAPA approach** locates approximate JAR files matching partial program versions to resolve unknown bindings, achieving **98.5% resolution** in evaluations. The Sable McGill PPA Framework transforms incomplete Java source into typed AST suitable for analysis. Most practically, **intraprocedural analysis** (examining code within a single procedure) requires no access to the broader codebase—Google's finding that "almost all [production] analyzers are intraprocedural" reflects the practical trade-off between analysis power and data minimization.

The recommended architecture implements an ephemeral analysis zone: git diff stream flows to temporary containers running incremental analysis (Infer reactive mode, Semgrep diff-aware), source code is destroyed immediately after processing, and only analysis summaries, finding hashes, and vulnerability reports persist to permanent storage. This pattern can be implemented with serverless functions or short-lived containers, just-in-time secret provisioning with automated cleanup, and in-memory-only processing without disk persistence of source material.

---

## Code embeddings offer partial privacy but require defensive measures

Code embeddings—dense vector representations capturing semantic meaning—enable efficient similarity matching and vulnerability detection, but research demonstrates they provide **no inherent privacy protection**. The Vec2Text attack (Morris et al., EMNLP 2023) recovers **92% of 32-token text** from GTR-base embeddings using iterative T5-based decoding with 50 correction steps—and this attack does NOT require access to embedding model weights. For longer sequences and code specifically, recovery rates decrease but remain substantial; the fundamental finding is that "embedding outputs contain as much information with respect to risks of leakage as the underlying sensitive data itself."

The most capable code embedding models include **CodeBERT** (Microsoft, RoBERTa-based, vulnerability detection achieving 93.06% accuracy on DiverseVul), **GraphCodeBERT** (extends CodeBERT with data flow graphs for enhanced semantic understanding), **UniXcoder** (768-dimensional embeddings supporting encoder-only, decoder-only, and encoder-decoder modes across 9 languages), and **StarEncoder** (BigCode, 125M parameters, 86 programming languages including PII detection capability). For binary analysis, **SAFE** (self-attentive function embeddings) and **UniASM** enable cross-architecture vulnerability discovery.

Privacy risks vary significantly by embedding design. **Mean pooling is MORE vulnerable** than CLS token representations—attackers can exploit the richer information captured by averaging all token embeddings. Bottleneck pre-training (like SimLM) increases vulnerability to **94.4% BLEU recovery**, while cosine similarity distance metrics leak more than dot product. Higher embedding dimensions contain more recoverable information.

Fortunately, multiple defensive techniques effectively mitigate these risks:

**Product quantization** completely eliminates reconstruction (0.0% exact match recovery) with essentially no retrieval performance degradation—768 sub-vectors reduce index size from 61GB to 16GB while maintaining 0.749 Top-10 retrieval compared to 0.748 baseline. This represents the best privacy/utility trade-off currently available.

**Embedding transformation** applies a secret linear transformation specific to each user or API key: `φ_transformed(x) = f(φ(x))`. This guarantees identical retrieval effectiveness with complete reconstruction degradation, suitable for embedding API services.

**Noise injection** at λ=0.1 prevents Vec2Text reconstruction for GTR-base embeddings with modest retrieval degradation, though the BeamClean attack (2025) can partially overcome noise by jointly estimating noise parameters.

**Dimensionality reduction** from 768 to 256 dimensions reduces exact match from 43.0% to 5.9% while maintaining 0.731 Top-10 retrieval (versus 0.748).

**Homomorphic encryption** on embeddings (CKKS scheme) allows computation on encrypted vectors for classification tasks, though computational overhead remains substantial.

For privacy-sensitive security analysis using embeddings, the practical recommendation is: use CLS token representation rather than mean pooling, apply product quantization to stored embeddings, implement user-specific embedding transformations for defense in depth, and consider homomorphic encryption only for the highest sensitivity requirements where computational cost is acceptable.

---

## GDPR compliance requires treating code as potentially personal data

Source code can constitute personal data under GDPR Article 4(1) when it identifies individuals directly or indirectly—through developer names in comments, variable names referencing people, email addresses in configurations, git commit history with author information, or code designed to identify, evaluate, or influence users. The CNIL (French DPA) Developer Guide explicitly warns organizations to "review source code contents to make sure that no personal data, passwords or other secrets are present" before sharing or publishing. Even absent obvious identifiers, the **indirect identification test** applies: if code combined with reasonably available information (GitHub profiles, employee databases) can identify individuals, it constitutes personal data.

Security analysis tools typically rely on **legitimate interest** (Article 6(1)(f)) as their lawful basis—detecting vulnerabilities and improving code security qualify as legitimate interests. However, EDPB Opinion 28/2024 requires a three-step test: identifying a legitimate, specific interest; demonstrating necessity with no less intrusive alternative; and balancing against data subject rights. This assessment should be documented before deployment.

When using LLM APIs, the provider acts as a **data processor** under Article 28, requiring a written Data Processing Agreement covering subject matter and duration, nature and purpose of processing, types of personal data and categories of data subjects, documented instruction requirements, confidentiality commitments, Article 32 security measures, sub-processor authorization procedures, data subject rights assistance, breach notification assistance, and audit rights. **OpenAI** provides DPAs via online form with 30-day maximum data retention and SOC 2 Type 2 certification; **Anthropic** offers DPAs for commercial terms (API, Claude for Work, Enterprise) with no training on commercial data and zero data retention agreements available for some enterprise customers.

For international transfers to US-based LLM providers, the **EU-US Data Privacy Framework** (adopted July 2023) provides an adequacy decision allowing transfers to DPF-certified organizations without Standard Contractual Clauses. Organizations should verify provider certification at dataprivacyframework.gov/list. OpenAI processes EEA/Swiss data through OpenAI Ireland Ltd with DPF coverage. However, potential "Schrems III" invalidation remains a risk following NOYB challenges—organizations should prepare SCC fallback options.

Critical compliance requirements include: executing DPAs with LLM providers before processing personal data, using business/enterprise accounts (consumer accounts lack GDPR-compliant DPAs and often train on inputs by default), implementing code anonymization to remove names, emails, and credentials before LLM submission, stripping git history metadata, conducting DPIAs for high-risk processing, and updating privacy policies to disclose LLM provider names, data residency locations, retention periods, and training data usage.

Best practices for security analysis tool privacy policies include clear disclosure that code is sent to external AI services with named providers, data residency information, retention specifics (e.g., "30 days for OpenAI API"), confirmation of training data opt-out, and automated decision-making disclosures per Article 22 where applicable. Easy consent withdrawal mechanisms should not block service for non-essential processing.

---

## A practical implementation roadmap for privacy-preserving security analysis

The research across these seven domains converges on a layered architecture that organizations can implement today:

**Tier 1: Local processing (highest sensitivity)** deploys quantized CodeLlama-13B or StarCoder2-7B via Ollama on developer workstations (requiring ~$1,500 hardware investment) for all code containing credentials, PII, proprietary algorithms, or trade secrets. All source remains on-device with no external transmission.

**Tier 2: Abstracted cloud processing (moderate sensitivity)** implements a Tree-sitter parsing → identifier normalization → Presidio PII detection → anonymized submission pipeline for code that benefits from more capable cloud models. Execute DPAs with providers, use business accounts, and maintain de-anonymization mappings locally.

**Tier 3: Differential aggregation (security metrics)** deploys OpenDP or Tumult Analytics for privacy-preserving security dashboards with ε=5-10 for industry statistics and ε=1-5 for organization-specific metrics, using quarterly budget management.

**Tier 4: Federated improvement (model training)** implements VDBFL-style federated learning using code property graphs to improve detection models across organizations without sharing source code.

The streaming/incremental foundation underpins all tiers: Semgrep with `--baseline-commit` for diff-aware CI/CD scanning, Infer in reactive mode for memory safety analysis, ephemeral container execution destroying source post-analysis, and summary-only persistence (Infer analysis objects, hashed findings) rather than source storage.

For code embeddings used in similarity search or pattern matching, apply product quantization before storage and implement user-specific embedding transformations—these provide complete reconstruction protection with negligible utility loss. Reserve homomorphic encryption for future consideration as the technology matures toward practical LLM inference costs.

The fundamental insight is that **privacy-preserving security analysis is not a single technology but an architectural pattern**: minimize what data leaves local control, abstract what must be transmitted, protect aggregates mathematically, and design for ephemeral processing that never persists sensitive source. The tools exist today; the challenge is thoughtful integration.