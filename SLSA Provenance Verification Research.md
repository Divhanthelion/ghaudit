# **Scaling Trust: A Comprehensive Analysis of SLSA Provenance Verification in High-Velocity Ecosystems**

## **1\. Introduction: The Epistemological Crisis in Software Supply Chains**

The modern software supply chain exists in a state of precarious trust. Developers implicitly trust that the artifacts they download from public registries—crates.io, npm, PyPI—correspond exactly to the source code they inspect on platforms like GitHub or GitLab. For decades, this trust was rooted in the assumption that the registry account holder was the only entity capable of publishing a package. However, the sophisticated threat landscape of 2025 and 2026 has shattered this assumption. The industrialization of supply chain attacks, exemplified by the proliferation of self-replicating worms like "Shai-Hulud" in the npm ecosystem 1, has demonstrated that identity theft and pipeline compromise are not edge cases but systemic inevitabilities.

In response, the industry has coalesced around the Supply-chain Levels for Software Artifacts (SLSA) framework as a mechanism to assert and verify the provenance of software. The core proposition of SLSA is simple yet profound: unforgeable metadata linking a binary artifact back to its source repository and build environment. Yet, the implementation of this framework at the scale of modern dependency trees—where a single Rust application might pull in over 1,000 transitive crates—presents formidable engineering challenges.

This report addresses the specific operational and architectural hurdles in implementing SLSA verification for the Rust ecosystem, specifically within the context of the src/provenance/slsa.rs logic. It bridges the gap between the theoretical specifications of SLSA and the messy reality of ecosystem adoption, network latency, and transitive trust propagation. By synthesizing data from 2024–2026 ecosystem reports, deep technical analysis of the Sigstore/Rekor infrastructure, and emerging graph-based security paradigms like GUAC, we provide a roadmap for engineering a high-performance, robust verification system.

### **1.1 The Provenance Gap**

The provided code snippet attestation\_url: None, // crates.io doesn't have attestations yet encapsulates a historical limitation that is rapidly becoming a technical debt. As of July 2025, crates.io has officially launched "Trusted Publishing," enabling the cryptographic binding of CI identities to published artifacts.3 This transition marks the end of the "wild west" era of API tokens and the beginning of the provenance era. However, the mere existence of a feature does not equate to ecosystem-wide security. The verification logic must now evolve from a placeholder to a sophisticated engine capable of discovering, fetching, and validating attestations that may reside in disparate locations (registry metadata, OCI registries, or transparency logs).

### **1.2 The Scale Challenge**

The central tension in this research is the conflict between security rigor and build performance. Verifying a single artifact via the Sigstore infrastructure involves cryptographic checks and network round-trips to the Rekor transparency log. When multiplied across a dependency tree of 1,000+ packages, a naive implementation of verification could introduce minutes of latency to a build process, rendering the security control unusable in practice. The "performance impact of Rekor lookups at scale" is thus not a secondary optimization concern but a primary functional requirement.

This report argues that the solution to this scaling problem lies in a fundamental architectural shift: moving from on-demand, linear verification to a tiered approach utilizing the new Rekor v2 tile-based architecture, aggressive local caching, and asynchronous graph-based policy enforcement.

## **2\. Ecosystem Adoption Landscape: A Comparative Analysis (2025-2026)**

To design an effective verifier, one must first understand the distribution and availability of the data it is intended to verify. The landscape of provenance adoption is highly heterogeneous, with distinct maturity levels, incentives, and adoption curves across the three major ecosystems: Python (PyPI), JavaScript (npm), and Rust (crates.io).

### **2.1 The Python Ecosystem (PyPI): The Gold Standard of Adoption**

PyPI serves as the benchmark for successful provenance adoption. Having introduced Trusted Publishing in April 2023, the ecosystem has had nearly three years to mature by early 2026\.5

#### **2.1.1 Adoption Statistics and Drivers**

Data from late 2025 indicates that approximately **25% of all files uploaded to PyPI in a given month** are now published using Trusted Publishing credentials.7 This statistic is significant because it represents a "crossing of the chasm" from early adopters to the early majority.

The primary driver for this adoption was not an abstract desire for "supply chain security" among maintainers, but rather the tangible improvement in Developer Experience (DX). By allowing maintainers to exchange long-lived, risky API tokens for short-lived, automated OIDC tokens bound to GitHub Actions, PyPI aligned security incentives with usability incentives.8 The friction of managing secrets was removed, and provenance was generated as a byproduct.

#### **2.1.2 Implications for Verification**

For a verifier tool, the high adoption rate in PyPI implies that a "fail-open" policy (where missing provenance is a warning, not an error) is slowly becoming viable to switch to a "fail-closed" policy for critical packages. The ecosystem has reached a critical mass where the absence of provenance on a popular package is a signal of risk rather than just a lack of feature adoption.

### **2.2 The JavaScript Ecosystem (npm): High Volume, High Chaos**

In stark contrast to PyPI, the npm ecosystem represents a challenging environment for verification. Despite being the largest registry with 4.8 million projects and experiencing 70% year-over-year download growth 10, reliable provenance adoption remains statistically low.

#### **2.2.1 The Provenance Deficit**

Reports from late 2025 suggest that while native support for npm provenance exists, the vast majority of packages—particularly the "long tail" of dependencies that constitute the bulk of the ecosystem—lack verifiable attestations. Estimates place adoption at less than 5% of the total corpus, although coverage is higher among the top 1% of most-downloaded packages.11

#### **2.2.2 The "Shai-Hulud" Incident and Forced Evolution**

The urgency for verification in npm is driven by active exploitation. The "Shai-Hulud" worm, active in late 2025, compromised over 500 packages by exploiting the lack of provenance and the reliance on ambient credentials.1 This worm specifically targeted the gap between the source code and the published artifact. In response, npm has begun to aggressively push for mandatory 2FA and is exploring mandates for Trusted Publishing for high-impact maintainers.12

For our research, this indicates that an npm verifier must be robust against *malicious* provenance—attestations that are technically valid (signed) but generated by compromised accounts. This necessitates checking not just *if* a package is signed, but *who* signed it (the specific GitHub repository and workflow).

### **2.3 The Rust Ecosystem (Crates.io): The Awakening Giant**

The Rust ecosystem, the specific focus of the user's slsa.rs implementation, is in the early stages of this transition.

#### **2.3.1 The Trusted Publishing Launch (July 2025\)**

Crates.io officially launched Trusted Publishing support in July 2025\.3 This feature mirrors the PyPI implementation, utilizing OIDC tokens from CI providers (initially GitHub Actions) to authenticate publish operations.

#### **2.3.2 Current Adoption and "Bootstrapping"**

As of early 2026, the adoption rate is in the "bootstrapping" phase. Unlike PyPI, which has had years of runway, Crates.io is seeing adoption primarily among security-conscious library authors and major ecosystem projects. A significant friction point identified is the requirement that the *first* release of a crate must be manual to establish the project namespace before Trusted Publishing can be configured.13 This manual step acts as a filter, ensuring that only intentional, authenticated projects enter the trusted tier, but it also slows down automated adoption for new projects.

The current code comment in slsa.rs (attestation\_url: None) reflects the pre-July 2025 reality. The immediate task for the codebase is to update this to support the resolution of attestations that are now being generated.

### **2.4 Comparative Data Summary**

The following table synthesizes the adoption metrics and ecosystem characteristics relevant to designing a universal or ecosystem-specific verifier.

| Metric | PyPI (Python) | npm (JavaScript) | Crates.io (Rust) |
| :---- | :---- | :---- | :---- |
| **Trusted Publishing Launch** | April 2023 | April 2023 (Beta) | July 2025 |
| **Provenance Adoption (est.)** | \~25% of new uploads 7 | \<5% of total packages 11 | \<1% (Early adoption phase) |
| **Verification Latency Risk** | Moderate (fewer deps per project) | Critical (massive dependency trees) | High (large compilation trees) |
| **Primary Threat Vector** | Typosquatting, Malware | Account Takeover, Worms | Build Script Compromise |
| **Attestation Storage** | Integrated in Registry | Integrated in Registry | **Split-View** (GitHub Releases) |

## **3\. The Architecture of Trust: Sigstore and Rekor at Scale**

To verify provenance, we rely on the Sigstore infrastructure. Understanding the architectural nuances of Sigstore—specifically the Rekor transparency log—is prerequisite to solving the "1000+ dependency" performance question.

### **3.1 The Mechanism of Verification**

A SLSA attestation generated via Sigstore consists of:

1. **The Envelope:** A JSON document (in-toto statement) containing the predicate (build details).  
2. **The Signature:** A cryptographic signature over the envelope, created by an ephemeral key.  
3. **The Certificate:** An X.509 certificate issued by Fulcio, binding the ephemeral key to an OIDC identity (e.g., https://github.com/owner/repo).  
4. **The Transparency Log Entry:** A proof that the signature was recorded in Rekor.

Verification requires checking the signature against the certificate, checking the certificate's validity (expiry, issuer), and, crucially, verifying the **inclusion proof** from Rekor. The inclusion proof ensures that the certificate exists in the public ledger, protecting against split-view attacks where a compromised CA issues a "secret" certificate to sign malware.

### **3.2 The Performance Impact of Rekor Lookups**

The query asks: *"What's the performance impact of Rekor lookups at scale (1000+ dependencies)?"*

#### **3.2.1 The Rekor v1 Bottleneck (Linear Scaling)**

In the legacy Rekor v1 architecture, verifying an inclusion proof required dynamic interaction with the Rekor API.

* **Query:** GET /api/v1/log/entries?hash=...  
* **Proof:** GET /api/v1/log/proof?index=...

For a dependency tree of 1,000 packages, this implies a worst-case scenario of 1,000 to 2,000 HTTP requests. Even with aggressive parallelism (e.g., 50 concurrent connections), network latency (RTT) and server-side processing limits become dominant.

* *Mathematical Model:* If $T\_{req} \= 50ms$ (optimistic RTT) and $N \= 1000$, sequential execution takes 50 seconds. With parallelism factor $P=50$, $T\_{total} \\approx \\frac{N \\times T\_{req}}{P} \+ T\_{overhead}$.  
* This results in a theoretical minimum of \~1-2 seconds, but in practice, rate limiting (HTTP 429\) and TCP connection overhead often inflate this to 10-30 seconds. For a developer running cargo build, a 30-second pause for verification is a significant degradation of the feedback loop.

#### **3.2.2 The Rekor v2 Solution: Tile-Based Tlogs**

Recognizing this bottleneck, the Sigstore project introduced **Rekor v2 (Rekor-on-Tiles)**, which reached General Availability in late 2025\.14 This architectural shift is the key to solving the scaling problem.

Architecture of Rekor v2:  
Instead of a dynamic API, Rekor v2 organizes the Merkle tree into fixed-size "tiles" (e.g., contiguous blocks of leaves).

* **Static Assets:** Fully populated tiles are immutable static files.  
* **Cacheability:** Because they are immutable, they can be cached indefinitely by CDNs and local clients using standard HTTP Cache-Control headers (e.g., max-age=31536000, immutable).15  
* **Batch Efficiency:** A single tile (e.g., size 256\) contains the hashes for 256 different log entries. If a project pulls in dependencies that were published around the same time (a common occurrence when frameworks update), multiple dependencies will map to the *same tile*.

Impact on Verification at Scale:  
With Rekor v2, the client downloads the necessary tiles to compute the root hash locally.

1. **Deduplication:** Verifying 1,000 artifacts does not require 1,000 distinct downloads if they share tiles.  
2. **Local Cache:** Once a tile is downloaded for one project, it is available for *all* projects on the developer's machine.  
3. **Bandwidth vs. Latency:** The constraint shifts from latency (round-trips) to bandwidth (downloading small binary tiles). Given the small size of tiles (kilobytes), this is a massive performance win.

### **3.3 Latency Analysis: The 1000+ Dependency Case**

To quantify the performance impact, we can model the expected behavior using the sigstore-verification crate's v2 implementation.

* **Scenario:** Clean build, 1,000 dependencies with SLSA attestations.  
* **Cold Cache:** The verifier must fetch the "Checkpoint" (signed tree head) and the relevant tiles.  
  * *Request Volume:* Assuming random distribution across the log's recent history, we might fetch 50-100 tiles.  
  * *Latency:* Parallel fetching of 100 static files from a CDN is extremely fast (\< 2 seconds on broadband).  
* **Warm Cache:** The verifier finds the tiles on disk.  
  * *Request Volume:* 1 request (fetch latest Checkpoint to ensure tree freshness).  
  * *Latency:* \< 100ms.  
  * *CPU Load:* Computing 1,000 SHA256 hashes and ECDSA verifications. Modern CPUs can handle thousands of verifications per second. Rust's ring or rust-crypto libraries are highly optimized for this.17

**Conclusion:** The transition to Rekor v2 reduces the performance penalty of "at scale" verification from an exponential/linear bottleneck to a near-constant-time operation (for warm caches) or a bandwidth-bound operation (for cold caches). This makes strict provenance verification viable for everyday development.

## **4\. Engineering the Solution: Caching and Precomputation**

The research question *"Can we cache/precompute provenance data?"* is answered affirmatively by the properties of the data itself. Provenance is immutable; once a specific version of a package is signed, that signature does not change.

### **4.1 Designing the Provenance Cache**

A robust cache design for src/provenance/slsa.rs should operate on two layers: the **Infrastructure Layer** (Rekor Tiles) and the **Verdict Layer** (Application Logic).

#### **4.1.1 The Infrastructure Layer (Tile Cache)**

This is handled by the sigstore-verification library, provided the client is configured correctly.

* **Storage:** \~/.cargo/sigstore/tiles/  
* **Structure:** A content-addressable store of tile files.  
* **TTL:**  
  * Full Tiles: Infinite/Immutable.  
  * Partial Tile (Tree Head): Short TTL (e.g., 1 hour), governed by the Signed Tree Head (STH) frequency.  
* **Logic:** The client checks the local disk for the required tile index. If missing, it fetches from the Rekor CDN.

#### **4.1.2 The Verdict Cache (Precomputation)**

The "Verdict Cache" stores the *result* of the verification policy. Even if cryptographic verification is fast, parsing JSON attestations and evaluating Rego/CUE policies takes non-zero time.

* **Key:** \`SHA256(Artifact\_Content) |

| Policy\_Hash\`

* **Value:** Verified { timestamp: u64, slsa\_level: u8, builder: String }  
* **Storage:** A localized SQLite database or a simple binary format (e.g., redb or sled in Rust).  
* **TTL:** Indefinite. A valid signature is valid forever unless revoked.  
* **Revocation Check:** The cache entry must be re-validated against a vulnerability/revocation database (like OSV) periodically, but the cryptographic signature verification does not need to be repeated.

### **4.2 Precomputing Trust at the Registry Level**

To further optimize, we can move verification upstream. The registry (crates.io) can perform the verification upon crate upload.

1. **Upload:** User uploads crate \+ attestation.  
2. **Registry Verification:** Crates.io verifies the Sigstore bundle and checks the policy.  
3. **Registry Attestation:** Crates.io signs a new statement: *"I, crates.io, verified that this crate meets SLSA Level 3."*  
4. **Client Verification:** The client only verifies the Registry's signature.  
* *Benefit:* Reduces $N$ verifications (one per dependency) to 1 verification (the registry's integrity).  
* *Trade-off:* Centralizes trust in the registry. A compromise of crates.io signing keys would compromise the entire ecosystem. Therefore, a hybrid model is best: clients verify the registry's signature for speed but occasionally audit the raw proofs for security.

## **5\. Implementation Strategy: Rust Verification Logic**

The provided code snippet in src/provenance/slsa.rs requires modernization. We must replace the placeholder with active resolution logic utilizing the sigstore-verification crate.

### **5.1 The sigstore-verification Crate**

The sigstore-verification crate 19 is the native Rust solution, replacing the need to shell out to the cosign CLI (which introduces process overhead and portability issues).

* **Key Features:** Native implementation of Rekor v2 verification, support for Fulcio certificates, and configurable trust roots.  
* **Integration:** It allows the verifier to be embedded directly into the cargo process or a library.

### **5.2 Addressing the "Split-View" Problem**

A unique challenge for crates.io is that, unlike npm or PyPI, the attestation is not yet fully integrated into the registry metadata in a standardized way. Often, the crate is on crates.io, but the provenance attestation (.intoto.jsonl) is attached to the GitHub Release.

**Proposed Logic for slsa.rs:**

Rust

// Pseudocode Design for src/provenance/slsa.rs

use sigstore\_verification::{verify\_bundle, Policy, SigstoreBundle};

pub async fn verify\_crate\_provenance(crate\_name: &str, version: &str, crate\_digest: &str) \-\> Result\<VerificationStatus\> {  
    // 1\. Discovery Phase  
    // Currently, we must heuristically find the attestation.  
    // Check crate metadata for "repository" field.  
    let repo\_url \= get\_crate\_repository(crate\_name, version)?;  
      
    // Attempt to fetch attestation from GitHub Releases  
    // Pattern: https://github.com/{owner}/{repo}/releases/download/v{version}/provenance.intoto.jsonl  
    let attestation\_url \= format\!("{}/releases/download/v{}/provenance.intoto.jsonl", repo\_url, version);  
    let attestation\_bundle \= fetch\_url(attestation\_url).await?;

    if attestation\_bundle.is\_none() {  
        return Ok(VerificationStatus::Missing("No attestation found in release assets".into()));  
    }

    // 2\. Verification Phase (using sigstore-verification crate)  
    // Verify the bundle's signature, certificate, and Rekor inclusion.  
    let bundle: SigstoreBundle \= serde\_json::from\_slice(\&attestation\_bundle.unwrap())?;  
      
    // 3\. Policy Check  
    // Does the certificate identity match the repository URL?  
    // This prevents "repo hijacking" where a valid signature is generated for the wrong repo.  
    let policy \= Policy::new()  
       .require\_certificate\_subject(repo\_url)  
       .require\_issuer("https://token.actions.githubusercontent.com"); // Trusted Publishing Issuer

    match verify\_bundle(\&bundle, crate\_digest, \&policy).await {  
        Ok(\_) \=\> Ok(VerificationStatus::Verified),  
        Err(e) \=\> Ok(VerificationStatus::Failed(e.to\_string())),  
    }  
}

### **5.3 Handling the Gap**

The code must handle the transition period.

* **Fail Open:** If attestation\_url is None or returns 404, the verifier should log a warning (e.g., "Provenance not available") rather than failing the build.  
* **Opt-In Strict Mode:** Allow users to define a policy (e.g., in Cargo.toml) that mandates provenance for specific high-risk dependencies.

## **6\. Transitive Trust and The Graph (GUAC)**

The final research question asks about "trust propagation": If A is verified and depends on B, what does that imply?  
This highlights the limitation of SLSA: SLSA is not transitive. Verifying that Package A was built securely does not verify that Package A didn't download a malicious Package B during its build process.

### **6.1 The Limits of Local Verification**

Recursive verification (verifying A, then B, then C...) is computationally expensive and logically complex (handling cycles, build-time vs run-time dependencies).

### **6.2 GUAC: The Systemic Solution**

The industry solution to this is **GUAC (Graph for Understanding Artifact Composition)**.21 GUAC functions as a centralized intelligence graph.

* **Ingestion:** It ingests SBOMs, SLSA attestations, and vulnerability data from the entire ecosystem.  
* **Synthesis:** It links these disparate pieces of data into a graph: Node(Crate A) \-\> Edge(Depends On) \-\> Node(Crate B).  
* **Policy at Scale:** Instead of the local client verifying the tree, the client queries a GUAC instance: *"Is the subgraph rooted at Crate A compliant with Policy X?"*

### **6.3 Integration Roadmap**

For the immediate term, the verifier in slsa.rs should focus on **direct provenance** (verifying the artifact in hand). However, the roadmap should include a "Governance" mode where it queries a public or private GUAC instance to assess the risk of the deeper dependency tree. This offloads the heavy lifting of transitive analysis to a specialized backend service.

## **7\. Strategic Recommendations and Roadmap**

Based on the ecosystem analysis and architectural constraints, we propose the following strategic roadmap for implementing provenance verification at scale.

### **7.1 Immediate Actions (0-6 Months)**

1. **Code Modernization:** Update src/provenance/slsa.rs to utilize the sigstore-verification crate. Implement the "heuristic discovery" logic to find attestations on GitHub Releases until registry support improves.  
2. **Performance Engineering:** Enable Rekor v2 support in the verification client. Implement a local filesystem cache for Rekor tiles to ensure 1000+ dependency verification completes in seconds, not minutes.  
3. **Bootstrapping Incentives:** Implement a "Badge" system in the local tooling (e.g., cargo audit \--provenance) to highlight verified packages. Visibility drives adoption.

### **7.2 Mid-Term Actions (6-12 Months)**

1. **Registry Integration:** Work with the crates.io team to support first-class hosting of attestations (similar to PyPI). This removes the fragility of the GitHub Releases fallback.  
2. **Verdict Caching:** Implement a persistent local database of verified artifacts to allow offline builds and instant re-verification.

### **7.3 Long-Term Vision (12+ Months)**

1. **GUAC Integration:** Integrate GUAC queries into the resolution process to handle transitive trust policies.  
2. **Policy Enforcement:** Transition from "Fail Open" to "Fail Closed" for critical ecosystem crates, mandating provenance for the foundational libraries of the Rust ecosystem.

## **8\. Conclusion**

The "ecosystem gap" identified in the user's code is closing rapidly. The launch of Trusted Publishing on crates.io in July 2025 provided the necessary infrastructure; the task now is to build the verification client that makes this infrastructure usable. By leveraging the performance characteristics of Rekor v2 and adopting a caching-first architecture, it is possible to verify supply chain provenance at the scale of thousands of dependencies without sacrificing the developer experience. The technology is no longer the bottleneck; the challenge is now one of implementation and ecosystem mobilization.

## **9\. Citations Table**

| ID | Source | Relevance |
| :---- | :---- | :---- |
| 10 | Sonatype 2024 Report | Ecosystem statistics (npm/PyPI growth) |
| 7 | PyPI Blog | Trusted Publishing adoption rates (25%) |
| 19 | sigstore-verification | Crate features and limitations |
| 14 | Rekor v2 Docs | Tile-based log architecture and caching |
| 1 | CISA Alert | Shai-Hulud attack details and impact |
| 2 | StepSecurity Blog | Analysis of npm worm attacks and mitigation |
| 22 | OpenSSF Blog | GUAC v1.0 release and graph analysis capabilities |
| 11 | Academic Paper | npm provenance adoption statistics (\<5%) |
| 6 | Socket.dev | Crates.io Trusted Publishing launch context |
| 3 | Socket.dev | Crates.io Trusted Publishing launch details (July 2025\) |
| 4 | Rust Blog | Crates.io development update (July 2025\) |
| 17 | Benchmark Data | Cryptographic verification performance in Rust |
| 16 | MDN Web Docs | HTTP Cache-Control headers for immutable data |

#### **Works cited**

1. Widespread Supply Chain Compromise Impacting npm Ecosystem \- CISA, accessed January 6, 2026, [https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)  
2. Shai-Hulud: Self-Replicating Worm Compromises 500+ NPM Packages \- StepSecurity, accessed January 6, 2026, [https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)  
3. Crates.io Implements Trusted Publishing Support \- Socket.dev, accessed January 6, 2026, [https://socket.dev/blog/crates-launches-trusted-publishing](https://socket.dev/blog/crates-launches-trusted-publishing)  
4. crates.io: development update | Rust Blog, accessed January 6, 2026, [https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/)  
5. New Guide for Package Repositories to Adopt Trusted Publishers, accessed January 6, 2026, [https://openssf.org/blog/2024/08/05/new-guide-for-package-repositories-to-adopt-trusted-publishers/](https://openssf.org/blog/2024/08/05/new-guide-for-package-repositories-to-adopt-trusted-publishers/)  
6. npm Adopts OIDC for Trusted Publishing in CI/CD Workflows \- ... \- Socket.dev, accessed January 6, 2026, [https://socket.dev/blog/npm-trusted-publishing](https://socket.dev/blog/npm-trusted-publishing)  
7. Trusted Publishing is popular, now for GitLab Self-Managed and Organizations, accessed January 6, 2026, [https://blog.pypi.org/posts/2025-11-10-trusted-publishers-coming-to-orgs/](https://blog.pypi.org/posts/2025-11-10-trusted-publishers-coming-to-orgs/)  
8. Publishing to PyPI with a Trusted Publisher, accessed January 6, 2026, [https://docs.pypi.org/trusted-publishers/](https://docs.pypi.org/trusted-publishers/)  
9. Pre-PEP: Exposing Trusted Publisher provenance on PyPI \- Standards \- Python Discussions, accessed January 6, 2026, [https://discuss.python.org/t/pre-pep-exposing-trusted-publisher-provenance-on-pypi/42337](https://discuss.python.org/t/pre-pep-exposing-trusted-publisher-provenance-on-pypi/42337)  
10. 2024 Software Supply Chain Report | Scale of Open Source \- Sonatype, accessed January 6, 2026, [https://www.sonatype.com/state-of-the-software-supply-chain/2024/scale](https://www.sonatype.com/state-of-the-software-supply-chain/2024/scale)  
11. Dirty-Waters: Investigation of the Software Supply Chain of JavaScript Cryptocurrency Wallets \- DiVA portal, accessed January 6, 2026, [http://www.diva-portal.org/smash/get/diva2:1955574/FULLTEXT01.pdf](http://www.diva-portal.org/smash/get/diva2:1955574/FULLTEXT01.pdf)  
12. Our plan for a more secure npm supply chain \- The GitHub Blog, accessed January 6, 2026, [https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)  
13. crates.io: Trusted Publishing \- Simon Willison's Weblog, accessed January 6, 2026, [https://simonwillison.net/2025/Jul/12/cratesio-trusted-publishing/](https://simonwillison.net/2025/Jul/12/cratesio-trusted-publishing/)  
14. sigstore/rekor-tiles: Signature Transparency Log designed for ease of use, low cost, and minimal maintenance \- GitHub, accessed January 6, 2026, [https://github.com/sigstore/rekor-tiles](https://github.com/sigstore/rekor-tiles)  
15. Rekor v2 GA \- Cheaper to run, simpler to maintain \- Sigstore Blog, accessed January 6, 2026, [https://blog.sigstore.dev/rekor-v2-ga/](https://blog.sigstore.dev/rekor-v2-ga/)  
16. Cache-Control header \- HTTP \- MDN Web Docs, accessed January 6, 2026, [https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)  
17. Making SLH-DSA 10x-100x Faster \- Conduition, accessed January 6, 2026, [https://conduition.io/code/fast-slh-dsa/](https://conduition.io/code/fast-slh-dsa/)  
18. Accelerating file hashing in Rust with parallel processing | Transloadit, accessed January 6, 2026, [https://transloadit.com/devtips/accelerating-file-hashing-in-rust-with-parallel-processing/](https://transloadit.com/devtips/accelerating-file-hashing-in-rust-with-parallel-processing/)  
19. sigstore-verification \- crates.io: Rust Package Registry, accessed January 6, 2026, [https://crates.io/crates/sigstore-verification](https://crates.io/crates/sigstore-verification)  
20. sigstore\_verification \- Rust \- Docs.rs, accessed January 6, 2026, [https://docs.rs/sigstore-verification](https://docs.rs/sigstore-verification)  
21. guac, accessed January 6, 2026, [https://guac.sh/](https://guac.sh/)  
22. GUAC 1.0 is Now Available \- Open Source Security Foundation, accessed January 6, 2026, [https://openssf.org/blog/2025/06/12/guac-1-0-is-now-available/](https://openssf.org/blog/2025/06/12/guac-1-0-is-now-available/)