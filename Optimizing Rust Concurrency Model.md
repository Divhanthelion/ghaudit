# **Concurrency Model Optimization: Architectural Analysis of Hybrid Tokio/Rayon Workloads**

## **1\. Executive Summary and Architectural Context**

The integration of asynchronous I/O runtimes with CPU-intensive thread pools represents one of the most sophisticated challenges in modern systems programming. The codebase in question utilizes a hybrid architecture employing **Tokio** for asynchronous event handling and **Rayon** for data parallelism. While this dichotomy is theoretically sound—delegating I/O wait states to a cooperative scheduler and computational throughput to a work-stealing pool—the interaction between these runtimes is fraught with "impedance mismatches" that can lead to suboptimal resource utilization, latency spikes, and thread starvation.1

The current configuration defaults defined in src/config.rs, specifically the reliance on auto-detected thread counts for both runtimes (tokio\_workers: 0, rayon\_threads: 0\) and static buffer sizes (channel\_buffer: 100), suggest a deployment strategy that has not yet been tuned for the specific mechanical sympathies of the underlying hardware or the workload's stochastic nature.2

This report provides an exhaustive analysis of the concurrency model, addressing the research questions regarding thread balance, channel tuning, adaptive concurrency, and resource tradeoffs. It synthesizes data from performance profiling methodologies, queuing theory, and architectural best practices to recommend a transition from static defaults to an adaptive, partitioned execution model. The analysis indicates that without strict isolation and adaptive gating, the system is susceptible to the "Ratio of Doom"—a state of thread oversubscription that degrades throughput via excessive context switching and cache thrashing.2

## **2\. Theoretical Foundations of Runtime Impedance**

To optimize the interaction between Tokio and Rayon, it is necessary to deconstruct the fundamental differences in their scheduling algorithms and how these differences manifest when the runtimes share the same physical resources.

### **2.1 The Tokio Runtime: Cooperative Latency Optimization**

Tokio is designed around the **Reactor Pattern** coupled with a cooperative work-stealing scheduler. Its primary optimization objective is latency reduction for I/O-bound tasks. The runtime spawns a fixed set of worker threads (typically one per logical core) that pin themselves to the CPU and poll for readiness events from the operating system's non-blocking I/O driver (epoll on Linux, kqueue on macOS, IOCP on Windows).3

#### **2.1.1 Cooperative Multitasking Mechanics**

In Tokio, tasks are state machines (Futures) that yield execution back to the scheduler at .await points. This cooperative model assumes that the code between yield points is negligible in duration (sub-millisecond). If a task performs significant computation (e.g., parsing a large AST in src/analyzer/sast.rs) without yielding, it effectively "hijacks" the worker thread. Since the worker thread is also responsible for polling the I/O driver, a hogged thread prevents the runtime from processing network interrupts or timer events, causing a ripple effect of latency across the entire application.2

#### **2.1.2 The Blocking Thread Pool Misconception**

Tokio provides a spawn\_blocking API, which offloads tasks to a separate, dynamic thread pool that can scale up to 512 threads by default.6 A critical finding from the research is the misuse of this pool for CPU-bound work. The blocking pool is designed for *synchronous I/O* (e.g., std::fs calls) where the thread must sleep waiting for the OS. It is *not* optimized for CPU throughput. Offloading thousands of analysis tasks to spawn\_blocking results in a thread explosion, leading to heavy OS scheduler overhead and cache thrashing, as these threads are not managed by a work-stealing algorithm efficient for compute.6

### **2.2 The Rayon Runtime: Preemptive Throughput Optimization**

Rayon operates on the principle of **Fork-Join Parallelism**. It is optimized for throughput—maximizing the number of instructions executed per clock cycle across all available cores.

#### **2.2.1 Work-Stealing Semantics**

Rayon employs a "deque" (double-ended queue) per worker thread. When a thread spawns a subtask, it pushes it to the *bottom* of its local deque. When it needs work, it pops from the *bottom* (LIFO \- Last In, First Out). This LIFO behavior is crucial for cache locality: the most recently generated data is likely still hot in the L1/L2 cache.9

When a thread runs out of local work, it becomes a "thief" and steals from the *top* (FIFO) of another thread's deque. This stealing strategy minimizes contention and ensures that thieves take the "oldest" (and likely largest) chunks of work, amortizing the cost of the steal operation.9

#### **2.2.2 The Conflict of Cohabitation**

When Tokio and Rayon are run simultaneously with default settings on the same machine, they compete for the same physical execution units.

* **Tokio** relies on threads waking up quickly to handle I/O events.  
* **Rayon** relies on threads running uninterrupted to maximize instruction throughput.  
* **Oversubscription:** If a machine has 16 cores, and both runtimes spawn 16 threads, the OS scheduler must time-slice 32 active threads on 16 cores. This context switching (costing 1-5 µs per switch, plus cache eviction costs) degrades the performance of both. Rayon threads lose cache locality, and Tokio threads suffer poll latency.2

## **3\. Optimizing Thread Pool Balance**

The research question—"What's the optimal balance between Tokio worker threads and Rayon threads?"—requires a move away from the auto-configured defaults found in src/config.rs.

### **3.1 The "Ratio of Doom" and Oversubscription**

The term "Ratio of Doom" refers to a pathological state where the number of requested threads vastly exceeds the physical cores, leading to resource starvation.2 In the provided context of sast.rs, parallel file analysis suggests a high volume of CPU-bound tasks.

The current default in config.rs allows both tokio\_workers and rayon\_threads to default to the number of logical CPUs ($N$). This results in $2N$ threads.

* **Impact:** Under heavy load, the OS scheduler will rapidly preempt Rayon workers to service Tokio workers and vice versa. This destroys the cache locality that Rayon's scheduler fights to preserve.

### **3.2 Strategy 1: Core Partitioning (Isolation)**

The most robust strategy for mixed workloads is **Core Partitioning**. Instead of allowing both runtimes to fight for all cores, the available cores are statically divided based on the workload's profile.

**Recommendation:** For a scanner/analyzer application where CPU analysis (sast.rs) dominates the execution time compared to I/O (file reading), the allocation should heavily favor Rayon.

* Formula:

  $$C\_{total} \= \\text{Total Logical Cores}$$  
  $$W\_{tokio} \= \\max(2, \\lfloor C\_{total} \\times 0.2 \\rfloor)$$  
  $$W\_{rayon} \= C\_{total} \- W\_{tokio}$$

For a 16-core machine:

* **Tokio:** 3-4 Threads. This is sufficient to saturate most NVMe SSDs and 10Gbps network links, as Tokio is extremely efficient at I/O.3  
* **Rayon:** 12-13 Threads. Dedicated to the heavy lifting of AST parsing and analysis.

This ensures that I/O handling never starves because Tokio has dedicated lanes, and compute throughput remains high because Rayon threads are rarely preempted.3

### **3.3 Strategy 2: CPU Pinning and Affinity**

To enforce this partitioning strictly, **Thread Affinity** should be employed. By pinning Tokio threads to Cores 0-3 and Rayon threads to Cores 4-15, we prevent the OS scheduler from migrating threads across the die, which preserves L3 cache coherence.

* **Implementation:** Using the core\_affinity crate or tokio::runtime::Builder::on\_thread\_start hook to set affinity masks.  
* **Benefit:** Reduces "false sharing" and cache line ping-ponging between the runtimes.9

### **3.4 Configuration Refactoring**

The src/config.rs logic should be updated to reflect this heuristic rather than defaulting to 0 (auto).

Rust

// Proposed optimization logic for src/config.rs  
pub fn get\_thread\_config() \-\> (usize, usize) {  
    let cores \= num\_cpus::get();  
    if cores \<= 4 {  
        // On constrained systems, avoid starvation by sharing,  
        // but limit Rayon to avoid blocking Tokio entirely.  
        (2, 2)  
    } else {  
        // Reserve minimal cores for IO, maximize Compute  
        let tokio \= std::cmp::max(2, cores / 4);  
        let rayon \= cores.saturating\_sub(tokio);  
        (tokio, rayon)  
    }  
}

This dynamic calculation prevents the "Ratio of Doom" by ensuring $\\sum Threads \\approx Cores$.2

## **4\. Tuning Channel Buffer Sizes**

The setting pub channel\_buffer: usize \= 100 controls the backpressure interface between the file reader (Tokio) and the analyzer (Rayon). This "magic number" requires empirical tuning based on **Little's Law** and memory bandwidth constraints.

### **4.1 Throughput vs. Latency Tradeoffs**

Little's Law states $L \= \\lambda W$, where $L$ is the number of items in the system (buffer size), $\\lambda$ is throughput, and $W$ is the wait time (latency).

* **Throughput Optimization:** To maximize throughput ($\\lambda$), the buffer ($L$) must be large enough to absorb the *variance* (jitter) in task processing times. If the analyzer stalls on a complex file, the reader must be able to continue buffering subsequent small files into the queue. If the buffer is full, the reader blocks, and disk I/O throughput drops to zero.  
* **Latency Optimization:** Large buffers increase the time $W$ a file sits in memory before processing. This increases the resident memory footprint (RSS) and delays the "time to first result".12

### **4.2 The "Batched Transport" Pattern**

Research into Rust channel performance (comparison of mpsc, crossbeam, flume) reveals that the overhead of the channel operation itself (locking, atomic compare-and-swap, thread notification) is non-trivial for high-frequency messages.13

Sending 10,000 individual File objects through a channel of size 100 incurs 10,000 synchronization penalties.

Optimization Insight: The most effective tuning is often not the buffer size, but the payload granularity.  
Instead of Sender\<File\>, utilize Sender\<Vec\<File\>\>.

* **Batching:** Grouping files into batches of 10 or 50 reduces synchronization overhead by an order of magnitude.  
* **Implication:** A buffer size of 100 batches of 50 files is effectively a buffer of 5,000 files, but with 1/50th the synchronization cost.

### **4.3 Memory-Aware Bounding**

A fixed buffer size of 100 is dangerous if the items vary in size.

* 100 files of 1KB \= 100KB RAM.  
* 100 files of 50MB \= 5GB RAM.

In a SAST context, source files can be large. A count-based limit (like mpsc::channel(100)) does not protect against Out-Of-Memory (OOM) errors if the reader encounters a sequence of large blobs.

**Advanced Recommendation:** Use a **Semaphore-based** limiter alongside the channel.

1. Acquire semaphore permits based on file size (e.g., 1 permit per MB).  
2. Send file over channel.  
3. Release permits after Rayon finishes analysis.  
   This effectively implements a byte-bounded channel rather than a count-bounded one, stabilizing memory usage under diverse workloads.14

## **5\. Adaptive Concurrency Control**

The question "Can we use adaptive concurrency based on system load?" targets the rigidity of static configurations. In production environments, "system load" is not static; it fluctuates due to external factors (other processes, container limits).

### **5.1 The limitations of Static concurrent\_clones**

The concurrent\_clones: 4 default assumes constant network bandwidth and constant repository size. If the system is cloned small repositories, 4 is too low (network underutilized). If cloning the Linux kernel, 4 might saturate memory.

### **5.2 Adaptive Algorithms: AIMD and TCP Vegas**

Research highlights the efficacy of applying networking congestion control algorithms to thread concurrency.16

* **AIMD (Additive Increase, Multiplicative Decrease):**  
  * *Algorithm:* Start with 1 concurrent task. If successful and fast, increment limit ($+1$). If a timeout or error occurs, or latency exceeds a threshold, multiply limit by $0.5$.  
  * *Application:* This is ideal for the concurrent\_clones setting. It allows the scanner to "probe" the available network bandwidth.  
* **TCP Vegas (Latency-based):**  
  * *Algorithm:* Monitor the Round-Trip Time (RTT) of the analysis tasks. Calculate the difference between the *minimum* observed RTT (base latency) and the *current* moving average RTT.  
  * *Logic:* If Current RTT \> Base RTT, it implies queuing is occurring (the CPUs are saturated). Reduce concurrency.  
  * *Application:* Perfect for the Rayon offloading. If parsing times start increasing (due to thermal throttling or contention), the adapter automatically throttles the rate of file submission to Rayon.19

### **5.3 Implementation: The flow-guard Pattern**

Implementing this in Rust typically involves wrapping the execution logic in a Service/Middleware layer. Libraries like flow-guard or concread provide primitives for this.14

Architectural Pattern:  
Instead of a raw loop in src/lib.rs, the file processing should be structured as a stream processing pipeline where the "concurrency limit" is a dynamic variable controlled by a feedback loop monitoring the sast.rs completion times.

Rust

// Conceptual Adaptive Logic  
struct ConcurrencyController {  
    current\_limit: usize,  
    rtt\_history: Window,  
}

impl ConcurrencyController {  
    fn adjust(&mut self, last\_duration: Duration) {  
        if last\_duration \> self.rtt\_history.p95() {  
            // Latency spiking, back off  
            self.current\_limit \= (self.current\_limit as f64 \* 0.9) as usize;  
        } else {  
            // Healthy, gently probe for more throughput  
            self.current\_limit \+= 1;  
        }  
    }  
}

## **6\. Memory and CPU Tradeoffs**

The choice of concurrency strategy involves balancing three limited resources: Virtual Memory, Resident Memory (RSS), and CPU Cache.

### **6.1 Memory Footprint Analysis**

The memory footprint of different units of concurrency varies by orders of magnitude.22

| Concurrency Unit | Stack Memory | Heap Overhead | Context Switch Cost | Scalability Limit |
| :---- | :---- | :---- | :---- | :---- |
| **OS Thread** (std::thread) | \~2MB (Virtual) / \~16KB (Committed) | High (Kernel structures) | High (1-5 µs, Kernel Mode) | \~Thousands |
| **Tokio Task** (Async) | 0 (Stackless) | Low (State Machine \~300B) | Very Low (User Mode) | \~Millions |
| **Rayon Job** (Closure) | Shared Stack | Very Low (Closure Capture) | Low (Work Stealing) | \~Millions |

**Tradeoff Insight:**

* **Pure Threads:** Using std::thread for every file would result in OOM immediately (10k files \= 20GB stack space).  
* **Pure Async:** Doing CPU work in async tasks uses minimal memory but destroys CPU efficiency due to lack of preemption and poor cache locality (the task moves between cores).  
* **Hybrid (Current):** This is the optimal *memory* strategy. We pay the stack cost only for the fixed pool of Rayon threads (e.g., 16 \* 2MB \= 32MB). The millions of files exist as small heap objects (Futures) until they are picked up by a Rayon thread.

### **6.2 The Cost of Context Switching**

Context switching is not just about saving registers; it's about the **Cache**.

* **L1/L2 Cache:** When an OS thread is preempted, the new thread likely invalidates the L1/L2 cache.  
* **Tokio Switch:** When an async task yields, it stays in the user-space process. However, if the task moves to a different worker thread (work stealing), cache locality is lost.  
* **Rayon Switch:** Rayon's LIFO queue is specifically designed to keep data in L1 cache. The thread finishes one item and immediately grabs the next most recent item (hot in cache).24

**Conclusion:** For CPU-bound sast.rs work, Rayon is strictly superior to Tokio or OS threads because its scheduling algorithm maximizes IPC (Instructions Per Cycle) via cache preservation.

## **7\. Deep Dive: The tokio-rayon Bridge Patterns**

The user query highlights src/analyzer/sast.rs:208-228 as a relevant file for parallel file analysis. The integration pattern here is the critical failure point.

### **7.1 The "Sandwich" Anti-Pattern**

A common mistake is the "Async \-\> Sync \-\> Async" sandwich 1:

1. Tokio starts an async task.  
2. Task calls rayon::join (Sync).  
3. Inside Rayon, the code tries to call block\_on to wait for a network request (Async).

**Risk:** This leads to deadlocks. Rayon threads block waiting for Tokio, but Tokio threads are blocked waiting for Rayon.

### **7.2 The Recommended "Oneshot" Pattern**

The most stable bridge pattern is using tokio::sync::oneshot channels to decouple the execution.

Rust

// Recommended Implementation Pattern  
pub async fn analyze\_file\_parallel(file: File) \-\> AnalysisResult {  
    let (tx, rx) \= tokio::sync::oneshot::channel();

    // Offload to Rayon  
    rayon::spawn(move |

| {  
        // This runs on a Rayon thread stack  
        let result \= internal\_cpu\_heavy\_analysis(file);  
          
        // Send result back to Tokio world  
        let \_ \= tx.send(result);  
    });

    // Tokio task yields here, freeing the worker for other IO  
    match rx.await {  
        Ok(result) \=\> result,  
        Err(\_) \=\> panic\!("Rayon thread panicked or was cancelled"),  
    }  
}

This pattern 25 ensures:

1. **Non-blocking:** The Tokio worker immediately yields at rx.await.  
2. **Isolation:** Panics in Rayon are captured by the channel closing (Err).  
3. **No "Global" Lock:** It uses the global Rayon pool, but communicates via a localized channel.

### **7.3 Evaluation of tokio-rayon Crate**

The tokio-rayon crate 27 essentially wraps the above pattern.

* **Pros:** Reduces boilerplate. Provides spawn\_async extension methods.  
* **Cons:** Maintenance status is sporadic.28  
* **Verdict:** Given the simplicity of the oneshot pattern, introducing a dependency is unnecessary. Hand-rolling the oneshot bridge provides greater control over error handling and channel types.

## **8\. Profiling and Diagnostics**

To validate the optimizations, specific observability tools must be employed.

### **8.1 Flamegraphs for Mixed Workloads**

Standard CPU profilers often struggle to visualize async/await stacks because the stack is "reconstituted" at runtime.

* **Tools:** perf (Linux) with flamegraph.  
* **Analysis:** In the flamegraph, look for the tokio::runtime::worker::Context::run towers. If these towers contain wide bars for functions in sast.rs (parsing/analysis), it confirms that **blocking code is running on the async runtime**. This is a performance bug.  
* **Goal:** Tokio towers should only contain epoll\_wait, parking\_lot, and task switching logic. All sast.rs logic should appear under rayon::ThreadPool::install towers.29

### **8.2 Tokio Console**

tokio-console is a diagnostics tool that connects to the runtime to visualize task latency.

* **Metric:** Watch the "Poll Time" (P50, P99).  
* **Threshold:** If Poll Time \> 100µs, the task is CPU-bound.  
* **Action:** Any task flagged by console with high poll times must be moved to the Rayon pool.31

### **8.3 Detecting Thread Starvation**

The crate tokio-blocked can be integrated to automatically log warnings when the reactor is blocked.

* **Usage:** It spawns a background thread that monitors the heartbeat of the Tokio workers. If a worker doesn't check in for 100ms, it dumps the stack trace. This is the "canary in the coal mine" for the deadlock scenarios described in section 3.1.33

## **9\. Conclusion and Recommendations**

The current architecture suffers from potential oversubscription and static limitation. Optimizing the concurrency model requires a shift from "defaults" to "engineered isolation."

### **Summary of Recommendations**

| Parameter | Current Default | Recommended Strategy | Benefit |
| :---- | :---- | :---- | :---- |
| **Tokio Workers** | Auto (All Cores) | **Partitioned (20% Cores)** | Prevents I/O thread starvation; ensures Rayon cache locality. |
| **Rayon Threads** | Auto (All Cores) | **Partitioned (80% Cores)** | Maximizes CPU throughput for AST analysis. |
| **Channel Buffer** | Fixed (100) | **Batched (Vec)** | Reduces synchronization overhead by 10x-50x. |
| **Concurrency** | Static Limit | **Adaptive (AIMD)** | Prevents OOM on large repos; utilizes bandwidth on small ones. |
| **Bridge** | Custom/Ad-hoc | **Oneshot Channel** | Decouples runtimes; provides panic safety. |

### **Implementation Roadmap**

1. **Refactor config.rs:** Implement the core partitioning logic (Section 3.4) to explicitly size the thread pools based on num\_cpus::get().  
2. **Apply Batching:** Modify the sast.rs pipeline to send Vec\<File\> instead of File over the channels.  
3. **Instrument:** Add tokio-blocked to the debug build to identify any remaining blocking code on the async path.  
4. **Adopt Adaptive Gate:** Replace the static semaphore in lib.rs with an AIMD-controlled permit system that monitors the Rayon queue depth/latency.

By treating the CPU (Rayon) and I/O (Tokio) as distinct resources with distinct scheduling needs, the application can achieve linear scalability and robust stability under the varied workloads typical of SAST scanners.

#### **Works cited**

1. Mixing rayon and tokio for fun and (hair) loss \- Naming is hard, accessed January 6, 2026, [https://blog.dureuill.net/articles/dont-mix-rayon-tokio/](https://blog.dureuill.net/articles/dont-mix-rayon-tokio/)  
2. tokio :: rayon \- How thread starvation killed our production server | by Savan Nahar | Medium, accessed January 6, 2026, [https://savannahar68.medium.com/how-thread-starvation-killed-our-production-server-fb5ba855aa57](https://savannahar68.medium.com/how-thread-starvation-killed-our-production-server-fb5ba855aa57)  
3. 7 Hidden Tokio Runtime Performance Gems That Will Transform Your Production Rust Applications | by Aarav Joshi | TechKoala Insights \- Medium, accessed January 6, 2026, [https://medium.com/techkoala-insights/7-hidden-tokio-runtime-performance-gems-that-will-transform-your-production-rust-applications-1ca5c2eb6ec0](https://medium.com/techkoala-insights/7-hidden-tokio-runtime-performance-gems-that-will-transform-your-production-rust-applications-1ca5c2eb6ec0)  
4. How does Tokio decide how many threads to spawn/use and when? \#3858 \- GitHub, accessed January 6, 2026, [https://github.com/tokio-rs/tokio/discussions/3858](https://github.com/tokio-rs/tokio/discussions/3858)  
5. Tokio: using core threads for cpu-heavy computation \- help \- Rust Users Forum, accessed January 6, 2026, [https://users.rust-lang.org/t/tokio-using-core-threads-for-cpu-heavy-computation/83443](https://users.rust-lang.org/t/tokio-using-core-threads-for-cpu-heavy-computation/83443)  
6. spawn\_blocking in tokio::task \- Rust \- Docs.rs, accessed January 6, 2026, [https://docs.rs/tokio/latest/tokio/task/fn.spawn\_blocking.html](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)  
7. How to create a dedicated threadpool for CPU-intensive work in Tokio? \- Stack Overflow, accessed January 6, 2026, [https://stackoverflow.com/questions/61752896/how-to-create-a-dedicated-threadpool-for-cpu-intensive-work-in-tokio](https://stackoverflow.com/questions/61752896/how-to-create-a-dedicated-threadpool-for-cpu-intensive-work-in-tokio)  
8. How do I spawn (possibly) blocking async tasks in tokio? \- Stack Overflow, accessed January 6, 2026, [https://stackoverflow.com/questions/76965631/how-do-i-spawn-possibly-blocking-async-tasks-in-tokio](https://stackoverflow.com/questions/76965631/how-do-i-spawn-possibly-blocking-async-tasks-in-tokio)  
9. Optimization adventures: making a parallel Rust workload 10x faster with (or without) Rayon, accessed January 6, 2026, [https://gendignoux.com/blog/2024/11/18/rust-rayon-optimized.html](https://gendignoux.com/blog/2024/11/18/rust-rayon-optimized.html)  
10. Data Parallelism with Rust and Rayon \- Shuttle.dev, accessed January 6, 2026, [https://www.shuttle.dev/blog/2024/04/11/using-rayon-rust](https://www.shuttle.dev/blog/2024/04/11/using-rayon-rust)  
11. Tokio or std::thread? : r/rust \- Reddit, accessed January 6, 2026, [https://www.reddit.com/r/rust/comments/1aipjyb/tokio\_or\_stdthread/](https://www.reddit.com/r/rust/comments/1aipjyb/tokio_or_stdthread/)  
12. thingbuf/mpsc\_perf\_comparison.md at main \- GitHub, accessed January 6, 2026, [https://github.com/hawkw/thingbuf/blob/main/mpsc\_perf\_comparison.md](https://github.com/hawkw/thingbuf/blob/main/mpsc_perf_comparison.md)  
13. Simple \*and\* fast channel? Too good to be true \- code review \- Rust Users Forum, accessed January 6, 2026, [https://users.rust-lang.org/t/simple-and-fast-channel-too-good-to-be-true/104036](https://users.rust-lang.org/t/simple-and-fast-channel-too-good-to-be-true/104036)  
14. cleitonaugusto/flow-guard: Adaptive concurrency control and backpressure for Axum/Tower services in Rust \- GitHub, accessed January 6, 2026, [https://github.com/cleitonaugusto/flow-guard](https://github.com/cleitonaugusto/flow-guard)  
15. Channels | Tokio \- An asynchronous Rust runtime, accessed January 6, 2026, [https://tokio.rs/tokio/tutorial/channels](https://tokio.rs/tokio/tutorial/channels)  
16. FlowGuard: Dynamic Concurrency Control for Rust \- code review, accessed January 6, 2026, [https://users.rust-lang.org/t/flowguard-dynamic-concurrency-control-for-rust/137189](https://users.rust-lang.org/t/flowguard-dynamic-concurrency-control-for-rust/137189)  
17. rate\_limiter\_aimd \- Rust \- Docs.rs, accessed January 6, 2026, [https://docs.rs/rate\_limiter\_aimd](https://docs.rs/rate_limiter_aimd)  
18. Announcing FlowGuard: Next-gen adaptive backpressure for the Rust ecosystem, accessed January 6, 2026, [https://users.rust-lang.org/t/announcing-flowguard-next-gen-adaptive-backpressure-for-the-rust-ecosystem/137084](https://users.rust-lang.org/t/announcing-flowguard-next-gen-adaptive-backpressure-for-the-rust-ecosystem/137084)  
19. Adaptive Concurrency Control for Mixed Analytical Workloads \- Klaviyo Engineering, accessed January 6, 2026, [https://klaviyo.tech/adaptive-concurrency-control-for-mixed-analytical-workloads-51350439aeec](https://klaviyo.tech/adaptive-concurrency-control-for-mixed-analytical-workloads-51350439aeec)  
20. Adaptive request concurrency. Resilient observability at scale. \- Vector, accessed January 6, 2026, [https://vector.dev/blog/adaptive-request-concurrency/](https://vector.dev/blog/adaptive-request-concurrency/)  
21. kanidm/concread: Concurrently Readable Data Structures for Rust \- GitHub, accessed January 6, 2026, [https://github.com/kanidm/concread](https://github.com/kanidm/concread)  
22. Why should you use Tokio vs. threads in Rust? \- Hacker News, accessed January 6, 2026, [https://news.ycombinator.com/item?id=34567550](https://news.ycombinator.com/item?id=34567550)  
23. How Much Memory Do You Need to Run 1 Million Concurrent Tasks? | Piotr Kołaczkowski, accessed January 6, 2026, [https://pkolaczk.github.io/memory-consumption-of-async/](https://pkolaczk.github.io/memory-consumption-of-async/)  
24. What are the overheads for using multiple cores? : r/rust \- Reddit, accessed January 6, 2026, [https://www.reddit.com/r/rust/comments/1cjwsb5/what\_are\_the\_overheads\_for\_using\_multiple\_cores/](https://www.reddit.com/r/rust/comments/1cjwsb5/what_are_the_overheads_for_using_multiple_cores/)  
25. Tokio and Rayon. Asynchrony and parallelism \- help \- Rust Users Forum, accessed January 6, 2026, [https://users.rust-lang.org/t/tokio-and-rayon-asynchrony-and-parallelism/121885](https://users.rust-lang.org/t/tokio-and-rayon-asynchrony-and-parallelism/121885)  
26. Dedicated rayon pool to submit work and asynchronously wait for completion, accessed January 6, 2026, [https://stackoverflow.com/questions/67763553/dedicated-rayon-pool-to-submit-work-and-asynchronously-wait-for-completion](https://stackoverflow.com/questions/67763553/dedicated-rayon-pool-to-submit-work-and-asynchronously-wait-for-completion)  
27. tokio-rayon \- crates.io: Rust Package Registry, accessed January 6, 2026, [https://crates.io/crates/tokio-rayon](https://crates.io/crates/tokio-rayon)  
28. Futures and tokio maintenance status \- Rust Users Forum, accessed January 6, 2026, [https://users.rust-lang.org/t/futures-and-tokio-maintenance-status/10881](https://users.rust-lang.org/t/futures-and-tokio-maintenance-status/10881)  
29. Flame Graphs, accessed January 6, 2026, [https://www.brendangregg.com/flamegraphs.html](https://www.brendangregg.com/flamegraphs.html)  
30. performance optimization with flamegraph and divan \- hēg denu \- Hayden Stainsby, accessed January 6, 2026, [https://hegdenu.net/posts/performance-optimization-flamegraph-divan/](https://hegdenu.net/posts/performance-optimization-flamegraph-divan/)  
31. tokio-console \- crates.io: Rust Package Registry, accessed January 6, 2026, [https://crates.io/crates/tokio-console](https://crates.io/crates/tokio-console)  
32. Need help finding thread starvation source \- help \- The Rust Programming Language Forum, accessed January 6, 2026, [https://users.rust-lang.org/t/need-help-finding-thread-starvation-source/136911](https://users.rust-lang.org/t/need-help-finding-thread-starvation-source/136911)  
33. theduke/tokio-blocked: Detect blocking code in Tokio async tasks. (Rust) \- GitHub, accessed January 6, 2026, [https://github.com/theduke/tokio-blocked](https://github.com/theduke/tokio-blocked)  
34. tokio-blocked \- crates.io: Rust Package Registry, accessed January 6, 2026, [https://crates.io/crates/tokio-blocked](https://crates.io/crates/tokio-blocked)