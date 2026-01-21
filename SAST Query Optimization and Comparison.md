# **Operational Efficacy and Architectural Evolution of Tree-sitter Based Static Analysis: A Comprehensive Benchmarking and Optimization Study**

## **1\. Executive Summary**

The efficacy of Static Application Security Testing (SAST) is currently undergoing a paradigm shift, moving away from simple syntactic pattern matching toward deep semantic analysis and AI-augmented rule generation. The subject of this operational review is a proprietary SAST engine leveraging over 40 Tree-sitter queries across four distinct programming languages. Designed heuristically, these queries currently lack a formal foundation in coverage analysis, raising significant concerns regarding their precision, recall, and ability to compete with established market leaders such as Semgrep and CodeQL.

This comprehensive research report evaluates the current architectural stance of the engine, benchmarking its capabilities against the rigorous standards of the NIST Software Assurance Reference Dataset (SARD) and the Juliet Test Suite. The analysis reveals a critical "Syntactic Ceiling"—a performance limit inherent to Abstract Syntax Tree (AST) matching where the absence of data flow and control flow context results in an unacceptably high rate of False Positives (FPs) for complex vulnerability classes like Injection (CWE-79, CWE-89) and Taint-Style issues.

Comparatively, the report dissects the operational mechanics of Semgrep and CodeQL. While Semgrep’s Open Source Software (OSS) engine shares a similar AST-based lineage, its evolution into utilizing "Local Taint" and the "Pro" engine’s inter-file capabilities highlights the precise trajectory required for the proprietary engine: the adoption of intermediate graph representations. The integration of tree-sitter-graph and stack-graphs (specifically given the engine’s Rust-based src/analyzer architecture) is identified as the primary vector for architectural remediation.

Furthermore, the research explores the frontier of Machine Learning (ML) in static analysis. It details the "AutoGrep" methodology—a pipeline for transforming CVE-labeled patches into high-fidelity detection rules using Large Language Models (LLMs)—and proposes a localized implementation. This approach mitigates the labor-intensive nature of manual query writing and addresses the "Data Deficit" of heuristic design by grounding rules in empirical vulnerability data.

The strategic roadmap delineates a phased evolution: immediate benchmarking using a custom harness for the Juliet suite to establish ground truth metrics; the integration of graph-based semantic layers to bridge the context gap; and the deployment of an automated ML pipeline to scale the rule corpus from 40 to hundreds, directly challenging the coverage of commercial tools.

## **2\. The Theoretical Limits of Heuristic Query Design**

### **2.1 The Heuristic Trap in Static Analysis**

In the initial development phases of static analysis tools, engineering teams often fall into the "Heuristic Trap." This occurs when detection logic is derived from ad-hoc observations of vulnerability patterns rather than a systematic model of code semantics. The current engine, utilizing roughly 40 queries defined in src/analyzer/queries.rs, exemplifies this stage.

A heuristic query typically targets the *manifestation* of a vulnerability rather than its *cause*. For example, a query might target the usage of the strcpy function in C/C++ due to its association with Buffer Overflow (CWE-120).

* **Syntactic Match:** (call\_expression function: (identifier) @name (\#eq? @name "strcpy"))  
* **Operational Outcome:** This query functions as a "linter." It flags *every* occurrence of strcpy.  
* **The Deficit:** It fails to discern whether the source buffer is larger than the destination buffer, or if the input string is statically defined and safe.

Without formal coverage analysis, such queries operate in a vacuum. They presume that the presence of a "dangerous function" is equivalent to a vulnerability. In modern software assurance, this assumption is flawed. Secure coding practices often involve wrapping dangerous primitives in safe abstractions. A heuristic engine will flag these safe wrappers as vulnerabilities (False Positives), gradually eroding developer trust until the tool is disabled or ignored.1

### **2.2 The Syntactic Ceiling: AST vs. Semantics**

The core limitation of the current Tree-sitter implementation is its reliance on the Abstract Syntax Tree (AST) as the sole source of truth. The AST represents the grammatical structure of the code but discards its execution semantics.

#### **2.2.1 Intra-procedural Blindness**

Consider a standard SQL Injection (CWE-89) scenario.

Java

// Vulnerable Pattern  
String query \= "SELECT \* FROM users WHERE name \= '" \+ userInput \+ "'";  
statement.execute(query);

A Tree-sitter query can easily detect the concatenation of a variable into a SQL string. However, consider the following:

Java

// Secure Pattern  
String query \= "SELECT \* FROM users WHERE name \= '" \+ sanitize(userInput) \+ "'";  
statement.execute(query);

Unless the query explicitly lists sanitize as an exception, the AST pattern remains identical: *Variable Concatenation inside String*. The AST does not "know" what sanitize does. It only sees a function call. To solve this, the engine needs **Data Flow Analysis (DFA)**—specifically Taint Tracking—to understand that the data flowing from userInput has been modified (cleansed) before reaching the sink.2

#### **2.2.2 Inter-procedural Blindness**

The limitation is exacerbated when data crosses function boundaries.

Java

public void verifyUser(String input) {  
    runQuery(input);  
}

private void runQuery(String sql) {  
    db.execute("SELECT... " \+ sql);  
}

An AST-based query looking at runQuery sees a concatenation of the argument sql. It has no visibility into verifyUser. It cannot determine if input came from a trusted configuration file or a hostile web request. This requires **Call Graph Analysis**, which maps the relationships between function definitions and invocations across the entire codebase.4 The current engine’s "file-level" view (implied by typical Tree-sitter usage) is blind to these cross-file dependencies, a feature that distinguishes "Pro" commercial tools from basic linters.

### **2.3 The Necessity of Formal Baselines**

Because heuristic queries are often written based on anecdotal evidence (e.g., "I saw this bug once"), they suffer from spotty coverage. One developer might write a query for subprocess.call in Python but forget subprocess.Popen or os.system.

Formal benchmarking against a standardized dataset like NIST SARD or the Juliet Test Suite provides a "coverage map." It highlights exactly which variations of a vulnerability are detected and which are missed. For an engine with only 40 queries, this mapping is critical to prioritize development. If the benchmark reveals that the engine detects 100% of Command Injections but 0% of Path Traversals, the roadmap becomes clear. Without this data, optimization is guesswork.5

## **3\. Benchmarking Architectures: NIST SARD and Juliet**

To quantitatively answer the research question regarding False Positive/Negative rates, we must establish a rigorous benchmarking harness. This section details the architecture of the NIST Software Assurance Reference Dataset (SARD) and the methodology for automating it against the current engine.

### **3.1 Anatomy of the Juliet Test Suite**

The Juliet Test Suite is the industry-standard synthetic benchmark for SAST tools. It was developed by the NSA's Center for Assured Software (CAS) and is hosted by NIST.7

#### **3.1.1 Scale and Structure**

The suite is massive, designed to be exhaustive.

* **C/C++ Version:** Contains over 64,000 test cases covering 118 different CWEs.9  
* **Java Version:** Contains over 28,000 test cases covering 112 CWEs.10  
* **Organization:** The files are structured by CWE ID (e.g., CWE89\_SQL\_Injection). This naming convention is the primary key for automated analysis.

#### **3.1.2 The "Good" vs. "Bad" Paradigm**

The defining feature of Juliet is its paired testing methodology.

* **Bad Functions:** Each test case includes a function (typically named bad()) that contains the specific vulnerability. Detection here is a **True Positive (TP)**.  
* **Good Functions:** The test case also includes one or more good() functions. These mimic the flow of the bad function but apply a fix (e.g., input validation, bounds checking). Detection here is a **False Positive (FP)**.5

This structure allows us to measure precision precisely. A tool that flags the bad() function but ignores the good() function is demonstrating semantic understanding. A tool that flags both is demonstrating simple pattern matching.

### **3.2 Constructing the Automation Harness**

Since the current engine is proprietary (src/analyzer), we cannot simply download a pre-made adapter. We must construct a harness based on the juliet.py and juliet-run.sh scripts provided in the Juliet repository.12

#### **3.2.1 The Build Requirement**

While Tree-sitter operates on source code, compiling the test cases is often necessary to resolve dependencies or generate build artifacts that some analysis logics might require (though strictly for Tree-sitter, source parsing is sufficient). However, the manifest.xml provided with Juliet links source files to their logical test cases.

* **Manifest Parsing:** The harness must parse manifest.xml. This file maps every source file to its Test Case ID and indicates which functions are vulnerable.  
  * *Element:* \<testcase id="12345"...\>  
  * *Element:* \<file path="CWE121\_Stack\_Based\_Buffer\_Overflow/..." \>  
  * *Attribute:* flaw="true" or flaw="false".11

#### **3.2.2 Harness Logic**

The harness should operate as follows:

1. **Iterate:** Loop through every test case in the manifest.xml.  
2. **Execution:** Invoke the SAST engine (via src/analyzer/sast.rs) on the specific source files associated with the test case.  
3. **Result Capture:** Capture the engine's output. The output must be parsed to identify the line number and function name of the alert.  
4. **Correlation:**  
   * If an alert corresponds to a file/line marked as flaw="true" in the manifest $\\rightarrow$ **True Positive**.  
   * If an alert corresponds to a file/line marked as flaw="false" $\\rightarrow$ **False Positive**.  
   * If no alert is generated for a flaw="true" location $\\rightarrow$ **False Negative**.  
   * If no alert is generated for a flaw="false" location $\\rightarrow$ **True Negative**.

#### **3.2.3 Output Standardization: SARIF**

To facilitate comparison with commercial tools, the harness should convert the engine's native output into **SARIF (Static Analysis Results Interchange Format)**.13

* **Why SARIF?** GitHub Code Scanning, VS Code extensions, and many CI/CD dashboards natively consume SARIF.  
* **Structure:** The SARIF JSON schema defines runs, results, locations, and rules. Mapping the engine's internal QueryMatch struct to SARIF result objects is a prerequisite for modern integration.13

### **3.3 Challenges with Synthetic Data**

While Juliet is excellent for baseline regression, it has limitations that the research must account for.

* **Artificial Complexity:** The code is synthetic. It does not reflect the "messiness" of real production code—spaghetti code, weird macro expansions (in C++), or complex framework dependency injection (in Java/Spring).  
* **The "PrimeVul" Alternative:** Recent research suggests that tools optimized solely for Juliet may fail on real-world vulnerabilities. Datasets like **PrimeVul** or **CVEBenchmarks** are constructed from actual Open Source project commits (Git diffs of fixes). These datasets introduce the noise and complexity of real development environments.16  
* **Recommendation:** Use Juliet to verify that the 40 queries *functionally work* (i.e., they can detect the bug in a vacuum). Use CVE-based datasets to tune them for False Positives in real code.

## **4\. Quantitative Analysis: Metrics and Interpretations**

### **4.1 False Positive/Negative Rate Analysis**

The research question asks for the rates of FPs and FNs. Based on literature analyzing similar AST-based tools against Juliet, we can project the performance profile of the current engine.

#### **4.1.1 Projected Recall (Sensitivity)**

AST-based tools typically achieve **moderate to high Recall** on specific CWEs where the vulnerability is syntactic.

* *Projected Recall:* \~60-80% for CWEs like Buffer Overflow (using dangerous functions) or Hardcoded Credentials.  
* *Reasoning:* The patterns are distinct. A call to strcpy is always a call to strcpy.  
* *Caveat:* For data-flow heavy CWEs (XSS, SQLi), Recall often drops to \~20-30% because the tool misses complex data paths.18

#### **4.1.2 Projected Precision (Reliability)**

This is where AST tools typically fail.

* *Projected Precision:* \< 30%.  
* *Reasoning:* Without data flow, the tool cannot distinguish between safe and unsafe usage. In the Juliet suite, specifically designed to test this distinction, the False Positive rate will be high. For every actual bug, there is a "good" function mimicking it. The engine will likely flag both, leading to a precision of 50% (random guess) or lower if the test case has multiple safe variations.1

#### **4.1.3 The Base Rate Fallacy in Production**

It is crucial to understand that a 30% precision on Juliet (where 50% of code is buggy) translates to near-zero precision in a real codebase (where 0.01% of code is buggy).

* *Bayesian Implication:* If a tool has a 5% False Positive rate (specificity of 95%) and the prevalence of bugs is 1 in 1000, then for every 1 true alert, there will be 50 false alarms. This "Alert Fatigue" is the primary barrier to adoption for heuristic tools.1

### **4.2 Comparative Benchmarking: The Marketplace**

| Metric | Current Engine (Tree-sitter) | Semgrep (OSS) | CodeQL (GitHub) |
| :---- | :---- | :---- | :---- |
| **Parsing Tech** | Tree-sitter (Incremental AST) | Tree-sitter (Optimized AST) | Proprietary Extractor (Database) |
| **Analysis Scope** | Single File (Intra-procedural) | Single File \+ Local Taint | Whole Program (Inter-procedural) |
| **Data Flow** | None (Pure Syntax) | Constant Propagation, Local Taint | Deep Global Taint, Points-to Analysis |
| **Rule Corpus** | \~40 Custom Queries | \~3,000+ Community Rules 19 | \~400+ Standard Queries 20 |
| **Speed** | Ultra-Fast (\>100k LOC/sec) | Fast (\~20-100k LOC/sec) | Slow (Build \+ Query Time) |
| **Language Support** | 4 Languages | 30+ Languages 21 | \~9 Major Languages 22 |
| **Customizability** | High (Rust/S-expressions) | High (YAML/Pattern syntax) | Moderate (QL Learning Curve) |

#### **4.2.1 Comparison vs. Semgrep**

Semgrep is the most direct comparison. It also uses Tree-sitter. However, Semgrep has solved the usability problem by allowing rules to be written in the target language syntax (e.g., exec($X) matches exec(variable)).

* **Gap:** The current engine uses raw S-expressions, which are harder to write and maintain.  
* **Advantage:** Semgrep OSS includes "Constant Propagation." If x \= "string"; exec(x), Semgrep knows x is a string literal. The current engine likely does not, unless explicitly coded in the query.  
* **Registry:** Semgrep's registry of 3,000+ rules serves as a massive knowledge base. Comparing the current 40 queries against this corpus will reveal huge coverage gaps, particularly in modern framework support (React, Spring Boot, Django).23

#### **4.2.2 Comparison vs. CodeQL**

CodeQL operates on a fundamentally different level. It builds a relational database of the code.

* **Gap:** CodeQL can find a vulnerability where the input enters in Controller.java and the injection happens in Database.java three layers deep. Neither Tree-sitter nor Semgrep OSS can do this reliably.  
* **Trade-off:** CodeQL requires a build environment. It cannot run on a snippet of code or a dirty working directory. The current engine *can*, giving it a unique value proposition for "IDE-time" feedback (linting as you type).4

## **5\. Bridging the Gap: Semantic Analysis with Graphs**

To move the FP/FN rates from "Linter" territory to "SAST" territory, the engine must adopt semantic capabilities. Since the engine is written in Rust (src/analyzer), two specific Rust libraries offer a path forward: tree-sitter-graph and stack-graphs.

### **5.1 tree-sitter-graph: From Trees to Graphs**

The tree-sitter-graph library allows developers to define a Domain Specific Language (DSL) that constructs arbitrary graphs from the AST.25

#### **5.1.1 Implementation Mechanism**

Instead of querying the AST directly for vulnerabilities, the engine would execute a "Construction Phase."

1. **Parse:** Tree-sitter generates the CST (Concrete Syntax Tree).  
2. **Graph Construction:** A .tsg (Tree-sitter Graph) file defines rules.  
   * *Rule:* (function\_definition name: (identifier) @n) \-\> (node definition), (edge @n \-\> definition)  
   * This builds a graph where nodes represent logical entities (Functions, Variables) rather than syntax tokens.  
3. **Data Flow Edges:** Rules can create edges representing data flow. x \= y creates a flow edge from y to x.  
4. **Querying the Graph:** The vulnerability query then traverses this graph. "Is there a path from a UserSource node to a SqlSink node?"

This effectively allows the implementation of **Local Taint Tracking** similar to Semgrep, dramatically reducing False Positives caused by safe variable usage.

### **5.2 stack-graphs: Solving the Import Problem**

One of the hardest problems in static analysis is "Jump to Definition" across files. If file A calls function foo() defined in file B, an AST parser on file A knows nothing about foo().

stack-graphs (also by GitHub/Tree-sitter) provides **incremental name resolution**.27

* **Mechanism:** It creates a graph structure for each file with "incomplete" edges (stubs) for imported symbols.  
* **Merging:** When multiple files are analyzed, stack-graphs merges these graphs, connecting the "call site" in File A to the "definition" in File B.  
* **Scope Stacks:** It manages variable shadowing and scoping rules (e.g., local variables vs global) using a stack-based path-finding algorithm.

**Strategic Value:** Integrating stack-graphs would allow the engine to perform **Inter-procedural Analysis** without the massive overhead of a CodeQL-style database build. It preserves the incremental, fast nature of Tree-sitter while unlocking deep visibility.27

## **6\. Machine Learning and Automated Rule Generation**

The research question "Can we use machine learning to generate or refine tree-sitter queries?" can be answered with a definitive **Yes**. The labor-intensive process of writing 40 queries can be scaled to hundreds using Generative AI.

### **6.1 The "AutoGrep" Pipeline Methodology**

Research into "AutoGrep" demonstrates a viable pipeline for converting vulnerability patches into static analysis rules.29

#### **6.1.1 Data Ingestion: The CVE Feed**

The pipeline begins by ingesting data from NVD (National Vulnerability Database) or tracking commits in open-source repositories that reference "Fix CVE-..."

* **Input:** A git diff showing the code *before* (vulnerable) and *after* (secure).

#### **6.1.2 Semantic Extraction with LLMs**

An LLM (like GPT-4 or Claude 3.5 Sonnet) acts as the reasoning engine.

* **Task:** Identify the *logical* change. Did the developer add a null check? Did they replace eval() with literal\_eval()?  
* **Abstraction:** The LLM must be prompted to ignore irrelevant changes (whitespace, comments) and focus on the structural transformation.

#### **6.1.3 Prompt Engineering for Tree-sitter**

Writing raw Tree-sitter S-expressions is difficult for humans and LLMs alike due to the strict parenthesis matching and specific node names.

* **Strategy:** Use "Few-Shot Learning." The prompt must include the specific grammar of the target language (e.g., "In Java, a function call is method\_invocation, not call\_expression") and examples of valid queries.29  
* **Prompt Template Example:**"You are an expert in Tree-sitter. Generate a query that matches the code in Snippet A (Vulnerable) but DOES NOT match the code in Snippet B (Fixed). Use the \#eq? predicate to filter function names. Output only the S-expression."

#### **6.1.4 Automated Verification (The Filter)**

LLMs hallucinate. They might generate invalid syntax or queries that match nothing.

* **Validation Loop:** The pipeline must immediately test the generated query against the original before and after files.  
  * *Pass Condition:* Matches before AND does not match after.  
  * *Fail Condition:* Syntax error OR matches both OR matches neither.  
* **Refinement:** If it fails, feed the error message back to the LLM (Self-Correction) to regenerate the query.31

### **6.2 ML-Driven Query Refinement**

Beyond generating new rules, ML can optimize the existing 40 queries.

* **Optimization:** An LLM can analyze an existing query and the False Positives it generated (from the Juliet benchmark).  
* **Prompt:** "This query produced a False Positive on this code snippet. Modify the S-expression to exclude this pattern while preserving the original detection capabilities."  
* **Result:** This creates a feedback loop where the engine becomes tighter and more precise over time without manual intervention.32

## **7\. Strategic Roadmap & Implementation**

To bridge the gap between the current heuristic engine and commercial-grade tools, a phased execution strategy is proposed.

### **Phase 1: Establish Ground Truth (Months 1-2)**

* **Action:** Build the Python/Shell benchmarking harness described in Section 3.2.  
* **Target:** Run the harness against the full Juliet Test Suite (C/C++ and Java).  
* **Deliverable:** A "Coverage Heatmap" detailing Precision/Recall for each of the 40+ queries. This will likely reveal high FN rates in Data Flow CWEs, confirming the "Syntactic Ceiling."

### **Phase 2: Semantic Foundation (Months 3-5)**

* **Action:** Integrate tree-sitter-graph into the Rust analyzer src/analyzer.  
* **Implementation:** Define basic graph construction rules for "Variable Definition" and "Reference."  
* **Target:** Re-implement the top 5 highest-noise queries (likely SQLi or Command Injection) using the graph-based data flow approach.  
* **Deliverable:** demonstrable reduction in False Positives on the Juliet "Good" test cases.

### **Phase 3: Scaling with ML (Months 6-9)**

* **Action:** Deploy the "AutoGrep" style pipeline.  
* **Target:** Ingest the top 50 critical CVEs from the last year for the supported languages. Generate queries automatically.  
* **Deliverable:** Expansion of the rule corpus from 40 to \~100+ queries with minimal engineering hours.

### **Phase 4: Inter-procedural Reach (Year 1+)**

* **Action:** Adopt stack-graphs for supported languages (Rust, Python, Java).  
* **Target:** Enable "Jump to Definition" across files.  
* **Deliverable:** Ability to compete with Semgrep Pro and CodeQL on complex, multi-file vulnerability patterns.

## **8\. Conclusion**

The current SAST engine stands at a crossroads. Its reliance on heuristic Tree-sitter queries provides a foundation of speed and simplicity, ideal for "linting" capabilities. However, the lack of formal coverage analysis and semantic depth places it at a severe disadvantage regarding accuracy. The high False Positive rates inherent in pure AST matching are a barrier to serious adoption in security-critical environments.

By rigorously benchmarking against the Juliet suite, the organization will quantify this deficit. More importantly, by pivoting the architecture to embrace graph-based representations (tree-sitter-graph, stack-graphs) and leveraging the generative power of LLMs for rule creation, the engine can transcend its current limitations. This evolution—from Syntactic Pattern Matching to Semantic Vulnerability Analysis—is the requisite path to offering a tool that is not just fast, but trusted.

## ---

**9\. Appendix: Technical Reference**

### **9.1 Juliet Test Suite Automation Logic**

The following pseudocode outlines the logic required to adapt the juliet-run.sh script for the proprietary engine, incorporating the manifest.xml parsing logic.12

Python

\# Pseudocode for Benchmarking Harness  
import xml.etree.ElementTree as ET  
import subprocess  
import json

def run\_benchmark(manifest\_path, engine\_binary):  
    tree \= ET.parse(manifest\_path)  
    root \= tree.getroot()  
      
    results \= {  
        "TP": 0, "FP": 0, "FN": 0, "TN": 0  
    }

    for testcase in root.findall('testcase'):  
        cwe\_id \= testcase.get('cwe')  
        \# Filter for CWEs supported by current queries  
        if cwe\_id not in SUPPORTED\_CWES: continue

        for file in testcase.findall('file'):  
            path \= file.get('path')  
            is\_flawed \= file.get('flaw') \== 'true'  
              
            \# Execute Engine  
            \# Engine must output JSON/SARIF  
            cmd \= \[engine\_binary, "scan", path, "--format=json"\]  
            process \= subprocess.run(cmd, capture\_output=True, text=True)  
            output \= json.loads(process.stdout)  
              
            has\_alert \= len(output\['results'\]) \> 0  
              
            if is\_flawed and has\_alert:  
                results \+= 1  
            elif is\_flawed and not has\_alert:  
                results\["FN"\] \+= 1  
                print(f"Missed Vulnerability: {path}")  
            elif not is\_flawed and has\_alert:  
                results\["FP"\] \+= 1  
                print(f"False Alarm: {path}")  
            elif not is\_flawed and not has\_alert:  
                results \+= 1

    calculate\_metrics(results)

def calculate\_metrics(r):  
    precision \= r / (r \+ r\["FP"\]) if (r \+ r\["FP"\]) \> 0 else 0  
    recall \= r / (r \+ r\["FN"\]) if (r \+ r\["FN"\]) \> 0 else 0  
    print(f"Precision: {precision:.2f}, Recall: {recall:.2f}")

### **9.2 Comparison of Rule Syntax**

To visualize the usability gap discussed in Section 4.2.1.

**Current Engine (Tree-sitter S-Expression):**

Scheme

(call\_expression  
  function: (identifier) @func\_name  
  arguments: (argument\_list  
    (string\_literal) @arg\_val)  
  (\#eq? @func\_name "exec")  
  (\#match? @arg\_val "^bash")  
)

*Complexity:* Requires understanding of AST node names (call\_expression, argument\_list). Brittle if the language grammar changes.

**Semgrep Rule (YAML):**

YAML

rules:  
  \- id: detect-exec-bash  
    patterns:  
      \- pattern: exec("bash...")  
    message: "Avoid direct calls to bash"  
    languages: \[python\]  
    severity: ERROR

*Simplicity:* Uses the target language syntax. The abstraction layer handles the mapping to AST nodes.

### **9.3 Table of Recommended Graph Libraries**

| Library | Purpose | Integration Point | Benefit |
| :---- | :---- | :---- | :---- |
| **tree-sitter-graph** | Construct arbitrary graphs from AST | src/analyzer (Rust) | Enables local taint tracking and data flow analysis. |
| **stack-graphs** | Incremental Name Resolution | src/analyzer (Rust) | Enables cross-file "Jump to Definition" and inter-procedural analysis. |
| **tree-sitter-c** | Grammar definition | Build Script | Ensures correct parsing of C/C++ (Juliet Suite). |
| **tree-sitter-java** | Grammar definition | Build Script | Ensures correct parsing of Java (Juliet Suite). |

#### **Works cited**

1. Human Factors in Evaluating Static Analysis Tools \- GrammaTech, accessed January 6, 2026, [https://www.grammatech.com/learn/human-factors-in-evaluating-static-analysis-tools/](https://www.grammatech.com/learn/human-factors-in-evaluating-static-analysis-tools/)  
2. Tracing a Stack Overflow Bug Through Taint Analysis: A Deep Dive Into Data Flow Graphs, accessed January 6, 2026, [https://blog.byteray.co.uk/tracing-a-stack-overflow-bug-through-taint-analysis-a-deep-dive-into-data-flow-graphs-ec98ca8dffea](https://blog.byteray.co.uk/tracing-a-stack-overflow-bug-through-taint-analysis-a-deep-dive-into-data-flow-graphs-ec98ca8dffea)  
3. Static Taint Analysis in Rust, accessed January 6, 2026, [https://projekter.aau.dk/projekter/files/421583418/Static\_Taint\_Analysis\_in\_Rust.pdf](https://projekter.aau.dk/projekter/files/421583418/Static_Taint_Analysis_in_Rust.pdf)  
4. Compare Semgrep to CodeQL, accessed January 6, 2026, [https://semgrep.dev/docs/faq/comparisons/codeql](https://semgrep.dev/docs/faq/comparisons/codeql)  
5. Spring Framework Benchmarking Utility for Static Application Security Testing (SAST) Tools \- IEEE Xplore, accessed January 6, 2026, [https://ieeexplore.ieee.org/iel8/6488907/11231115/11124241.pdf](https://ieeexplore.ieee.org/iel8/6488907/11231115/11124241.pdf)  
6. Using Static Code Analysis Tools for Detection of Security Vulnerabilities \- NASA, accessed January 6, 2026, [https://www.nasa.gov/wp-content/uploads/2016/10/01-11\_using\_static\_code\_analysis\_tools\_0.pdf](https://www.nasa.gov/wp-content/uploads/2016/10/01-11_using_static_code_analysis_tools_0.pdf)  
7. SARD Acknowledgments and Test Suites Descriptions | NIST, accessed January 6, 2026, [https://www.nist.gov/itl/ssd/software-quality-group/sard-acknowledgments-and-test-suites-descriptions](https://www.nist.gov/itl/ssd/software-quality-group/sard-acknowledgments-and-test-suites-descriptions)  
8. Juliet Test Suite v1.2 for C/C++ User Guide | SAMATE | NIST, accessed January 6, 2026, [https://samate.nist.gov/SARD/resources/Juliet\_Test\_Suite\_v1.2\_for\_C\_Cpp\_-\_User\_Guide.pdf](https://samate.nist.gov/SARD/resources/Juliet_Test_Suite_v1.2_for_C_Cpp_-_User_Guide.pdf)  
9. Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE Detection \- arXiv, accessed January 6, 2026, [https://arxiv.org/html/2503.09433v1](https://arxiv.org/html/2503.09433v1)  
10. Juliet and OWASP Benchmark Results: How CAST Tests Against 2 Most Important Application Security Standards in 2019, accessed January 6, 2026, [https://www.castsoftware.com/pulse/juliet-and-owasp-benchmark-results-how-cast-tests](https://www.castsoftware.com/pulse/juliet-and-owasp-benchmark-results-how-cast-tests)  
11. The Software Assurance Reference Dataset (SARD) \- NIST Technical Series Publications, accessed January 6, 2026, [https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8561.pdf](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8561.pdf)  
12. arichardson/juliet-test-suite-c \- GitHub, accessed January 6, 2026, [https://github.com/arichardson/juliet-test-suite-c](https://github.com/arichardson/juliet-test-suite-c)  
13. SARIF support for code scanning \- GitHub Docs, accessed January 6, 2026, [https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)  
14. Static Analysis Results Interchange Format (SARIF) Version 2.0 \- Index of / \- OASIS Open, accessed January 6, 2026, [https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html](https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html)  
15. SARIF Home, accessed January 6, 2026, [https://sarifweb.azurewebsites.net/](https://sarifweb.azurewebsites.net/)  
16. False Positives, Real Problems: Evaluating Static Analysis Tools \- DiVA portal, accessed January 6, 2026, [http://www.diva-portal.org/smash/get/diva2:1968169/FULLTEXT01.pdf](http://www.diva-portal.org/smash/get/diva2:1968169/FULLTEXT01.pdf)  
17. Comparison and Evaluation on Static Application Security Testing (SAST) Tools for Java \- Sen Chen's, accessed January 6, 2026, [https://sen-chen.github.io/img\_cs/pdf/fse2023-sast.pdf](https://sen-chen.github.io/img_cs/pdf/fse2023-sast.pdf)  
18. On the capability of static code analysis to detect security vulnerabilities, accessed January 6, 2026, [https://community.wvu.edu/\~kagoseva/Papers/IST-2015.pdf](https://community.wvu.edu/~kagoseva/Papers/IST-2015.pdf)  
19. Semgrep vs Github Advanced Security, accessed January 6, 2026, [https://semgrep.dev/resources/semgrep-vs-github/](https://semgrep.dev/resources/semgrep-vs-github/)  
20. CodeQL 2.22.3 (2025-08-06) \- GitHub, accessed January 6, 2026, [https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.22.3/](https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.22.3/)  
21. Semgrep Community Edition, accessed January 6, 2026, [https://semgrep.dev/products/community-edition/](https://semgrep.dev/products/community-edition/)  
22. About code scanning with CodeQL \- GitHub Docs, accessed January 6, 2026, [https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql)  
23. Manage rules and policies \- Semgrep, accessed January 6, 2026, [https://semgrep.dev/docs/semgrep-code/policies](https://semgrep.dev/docs/semgrep-code/policies)  
24. Rule Writing for CodeQL and Semgrep \- Spaceraccoon's Blog, accessed January 6, 2026, [https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/)  
25. tree-sitter/tree-sitter-graph: Construct graphs from parsed source code \- GitHub, accessed January 6, 2026, [https://github.com/tree-sitter/tree-sitter-graph](https://github.com/tree-sitter/tree-sitter-graph)  
26. tree\_sitter\_graph \- Rust \- Docs.rs, accessed January 6, 2026, [https://docs.rs/tree-sitter-graph](https://docs.rs/tree-sitter-graph)  
27. stack\_graphs \- Rust \- Docs.rs, accessed January 6, 2026, [https://docs.rs/stack-graphs/\*/stack\_graphs/](https://docs.rs/stack-graphs/*/stack_graphs/)  
28. Rust implementation of stack graphs \- GitHub, accessed January 6, 2026, [https://github.com/github/stack-graphs](https://github.com/github/stack-graphs)  
29. Autogrep: Automated Generation and Filtering of Semgrep Rules ..., accessed January 6, 2026, [https://lambdasec.github.io/AutoGrep-Automated-Generation-and-Filtering-of-Semgrep-Rules-from-Vulnerability-Patches/](https://lambdasec.github.io/AutoGrep-Automated-Generation-and-Filtering-of-Semgrep-Rules-from-Vulnerability-Patches/)  
30. Prompt Engineering of LLM Prompt Engineering : r/PromptEngineering \- Reddit, accessed January 6, 2026, [https://www.reddit.com/r/PromptEngineering/comments/1hv1ni9/prompt\_engineering\_of\_llm\_prompt\_engineering/](https://www.reddit.com/r/PromptEngineering/comments/1hv1ni9/prompt_engineering_of_llm_prompt_engineering/)  
31. Automatically Generating Rules of Malicious Software Packages via Large Language Model, accessed January 6, 2026, [https://arxiv.org/html/2504.17198v1](https://arxiv.org/html/2504.17198v1)  
32. How we built an AppSec AI that security researchers agree with 96% of the time | Semgrep, accessed January 6, 2026, [https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/)