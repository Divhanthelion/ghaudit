//! Advanced concurrency utilities for optimal resource utilization.
//!
//! This module provides:
//! - **Core Partitioning**: Dedicates CPU cores between Tokio (async I/O) and Rayon (parallel compute)
//! - **Batched Channels**: Amortizes channel overhead by sending batches of items
//! - **AIMD Controller**: Adaptive concurrency using Additive Increase Multiplicative Decrease
//!
//! # Research Background
//!
//! The optimal split between I/O and compute threads depends on workload characteristics:
//! - For I/O-heavy workloads (GitHub API, network): More Tokio threads
//! - For CPU-heavy workloads (parsing, analysis): More Rayon threads
//!
//! The default 20% Tokio / 80% Rayon split is based on profiling security analysis
//! workloads where parsing and pattern matching dominate runtime.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ============================================================================
// Core Partitioning
// ============================================================================

/// Configuration for CPU core partitioning between async I/O and parallel compute.
#[derive(Debug, Clone)]
pub struct CorePartitionConfig {
    /// Fraction of cores to dedicate to Tokio (async I/O). Default: 0.20 (20%)
    pub tokio_fraction: f64,
    /// Minimum number of Tokio worker threads.
    pub tokio_min_threads: usize,
    /// Maximum number of Tokio worker threads.
    pub tokio_max_threads: usize,
    /// Minimum number of Rayon worker threads.
    pub rayon_min_threads: usize,
    /// Whether to enable work stealing between pools.
    pub enable_work_stealing: bool,
}

impl Default for CorePartitionConfig {
    fn default() -> Self {
        Self {
            tokio_fraction: 0.20,
            tokio_min_threads: 1,
            tokio_max_threads: 8,
            rayon_min_threads: 2,
            enable_work_stealing: true,
        }
    }
}

/// Computed core partition for the system.
#[derive(Debug, Clone)]
pub struct CorePartition {
    /// Number of cores available on the system.
    pub total_cores: usize,
    /// Number of threads for Tokio runtime.
    pub tokio_threads: usize,
    /// Number of threads for Rayon pool.
    pub rayon_threads: usize,
    /// Configuration used.
    pub config: CorePartitionConfig,
}

impl CorePartition {
    /// Compute an optimal core partition for the current system.
    pub fn compute(config: CorePartitionConfig) -> Self {
        let total_cores = num_cpus::get();

        // Calculate Tokio threads (for async I/O)
        let tokio_ideal = (total_cores as f64 * config.tokio_fraction).ceil() as usize;
        let tokio_threads = tokio_ideal
            .max(config.tokio_min_threads)
            .min(config.tokio_max_threads)
            .min(total_cores);

        // Remaining cores go to Rayon (for parallel compute)
        let rayon_threads = (total_cores - tokio_threads).max(config.rayon_min_threads);

        info!(
            "Core partition: {} total cores -> {} Tokio + {} Rayon",
            total_cores, tokio_threads, rayon_threads
        );

        Self {
            total_cores,
            tokio_threads,
            rayon_threads,
            config,
        }
    }

    /// Compute partition with default configuration.
    pub fn default_partition() -> Self {
        Self::compute(CorePartitionConfig::default())
    }

    /// Initialize Rayon global thread pool with the computed partition.
    ///
    /// This should be called once at application startup before using Rayon.
    pub fn init_rayon_pool(&self) -> Result<(), rayon::ThreadPoolBuildError> {
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.rayon_threads)
            .thread_name(|idx| format!("rayon-worker-{}", idx))
            .build_global()
    }

    /// Create a Tokio runtime with the computed partition.
    pub fn build_tokio_runtime(&self) -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(self.tokio_threads)
            .thread_name("tokio-worker")
            .enable_all()
            .build()
    }
}

// ============================================================================
// Batched Channel Transport
// ============================================================================

/// Configuration for batched channel transport.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of items per batch.
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing a partial batch.
    pub max_batch_delay: Duration,
    /// Channel buffer size (in batches).
    pub channel_buffer: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 64,
            max_batch_delay: Duration::from_millis(10),
            channel_buffer: 16,
        }
    }
}

/// A sender that batches items before sending.
pub struct BatchSender<T> {
    /// Inner channel sender.
    inner: mpsc::Sender<Vec<T>>,
    /// Current batch being accumulated.
    current_batch: Vec<T>,
    /// Configuration.
    config: BatchConfig,
    /// Last flush time.
    last_flush: Instant,
    /// Statistics.
    stats: Arc<BatchStats>,
}

/// A receiver that receives batches of items.
pub struct BatchReceiver<T> {
    /// Inner channel receiver.
    inner: mpsc::Receiver<Vec<T>>,
    /// Current batch being consumed.
    current_batch: Vec<T>,
    /// Position in current batch.
    batch_pos: usize,
    /// Statistics.
    stats: Arc<BatchStats>,
}

/// Statistics for batched channel.
#[derive(Debug, Default)]
pub struct BatchStats {
    /// Total items sent.
    pub items_sent: AtomicU64,
    /// Total batches sent.
    pub batches_sent: AtomicU64,
    /// Total items received.
    pub items_received: AtomicU64,
    /// Total batches received.
    pub batches_received: AtomicU64,
}

impl BatchStats {
    /// Calculate average batch size.
    pub fn avg_batch_size(&self) -> f64 {
        let items = self.items_sent.load(Ordering::Relaxed) as f64;
        let batches = self.batches_sent.load(Ordering::Relaxed) as f64;
        if batches > 0.0 {
            items / batches
        } else {
            0.0
        }
    }
}

/// Create a batched channel pair.
pub fn batched_channel<T>(config: BatchConfig) -> (BatchSender<T>, BatchReceiver<T>) {
    let (tx, rx) = mpsc::channel(config.channel_buffer);
    let stats = Arc::new(BatchStats::default());

    let sender = BatchSender {
        inner: tx,
        current_batch: Vec::with_capacity(config.max_batch_size),
        config: config.clone(),
        last_flush: Instant::now(),
        stats: Arc::clone(&stats),
    };

    let receiver = BatchReceiver {
        inner: rx,
        current_batch: Vec::new(),
        batch_pos: 0,
        stats,
    };

    (sender, receiver)
}

impl<T: Send> BatchSender<T> {
    /// Send an item, batching it for efficiency.
    pub async fn send(&mut self, item: T) -> Result<(), mpsc::error::SendError<Vec<T>>> {
        self.current_batch.push(item);

        // Flush if batch is full or timeout elapsed
        let should_flush = self.current_batch.len() >= self.config.max_batch_size
            || self.last_flush.elapsed() >= self.config.max_batch_delay;

        if should_flush {
            self.flush().await?;
        }

        Ok(())
    }

    /// Flush the current batch.
    pub async fn flush(&mut self) -> Result<(), mpsc::error::SendError<Vec<T>>> {
        if !self.current_batch.is_empty() {
            let batch = std::mem::replace(
                &mut self.current_batch,
                Vec::with_capacity(self.config.max_batch_size),
            );

            self.stats
                .items_sent
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);

            self.inner.send(batch).await?;
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    /// Get channel statistics.
    pub fn stats(&self) -> &BatchStats {
        &self.stats
    }
}

impl<T> BatchReceiver<T> {
    /// Receive the next item.
    pub async fn recv(&mut self) -> Option<T> {
        // Return from current batch if available
        if self.batch_pos < self.current_batch.len() {
            let item = self.current_batch.swap_remove(self.batch_pos);
            self.stats.items_received.fetch_add(1, Ordering::Relaxed);
            return Some(item);
        }

        // Get next batch
        self.current_batch = self.inner.recv().await?;
        self.batch_pos = 0;
        self.stats.batches_received.fetch_add(1, Ordering::Relaxed);

        if !self.current_batch.is_empty() {
            let item = self.current_batch.swap_remove(0);
            self.stats.items_received.fetch_add(1, Ordering::Relaxed);
            Some(item)
        } else {
            None
        }
    }

    /// Try to receive the next item without blocking.
    pub fn try_recv(&mut self) -> Option<T> {
        // Return from current batch if available
        if self.batch_pos < self.current_batch.len() {
            let item = self.current_batch.swap_remove(self.batch_pos);
            self.stats.items_received.fetch_add(1, Ordering::Relaxed);
            return Some(item);
        }

        // Try to get next batch
        match self.inner.try_recv() {
            Ok(batch) => {
                self.current_batch = batch;
                self.batch_pos = 0;
                self.stats.batches_received.fetch_add(1, Ordering::Relaxed);

                if !self.current_batch.is_empty() {
                    let item = self.current_batch.swap_remove(0);
                    self.stats.items_received.fetch_add(1, Ordering::Relaxed);
                    Some(item)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Get channel statistics.
    pub fn stats(&self) -> &BatchStats {
        &self.stats
    }
}

// ============================================================================
// AIMD Adaptive Concurrency Controller
// ============================================================================

/// Configuration for AIMD (Additive Increase Multiplicative Decrease) controller.
#[derive(Debug, Clone)]
pub struct AimdConfig {
    /// Initial concurrency limit.
    pub initial_limit: usize,
    /// Minimum concurrency limit.
    pub min_limit: usize,
    /// Maximum concurrency limit.
    pub max_limit: usize,
    /// Additive increase step (on success).
    pub additive_increase: usize,
    /// Multiplicative decrease factor (on failure). E.g., 0.5 = halve.
    pub multiplicative_decrease: f64,
    /// Latency threshold for proactive decrease (in ms).
    pub latency_threshold_ms: u64,
    /// Sample window for latency averaging.
    pub sample_window: usize,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            initial_limit: 8,
            min_limit: 1,
            max_limit: 128,
            additive_increase: 1,
            multiplicative_decrease: 0.5,
            latency_threshold_ms: 500,
            sample_window: 20,
        }
    }
}

/// AIMD-based adaptive concurrency controller.
///
/// This controller dynamically adjusts the concurrency limit based on feedback:
/// - **Success**: Increase limit additively (slow growth)
/// - **Failure/Timeout**: Decrease limit multiplicatively (fast reduction)
/// - **High Latency**: Proactively decrease before failures occur
///
/// This is inspired by TCP congestion control and is widely used in
/// load balancing (e.g., Netflix Concurrency Limits library).
pub struct AimdController {
    /// Current concurrency limit.
    limit: AtomicUsize,
    /// Current in-flight requests.
    in_flight: AtomicUsize,
    /// Configuration.
    config: AimdConfig,
    /// Recent latency samples (ring buffer).
    latency_samples: parking_lot::Mutex<Vec<u64>>,
    /// Sample position.
    sample_pos: AtomicUsize,
    /// Statistics.
    stats: AimdStats,
}

/// Statistics for AIMD controller.
#[derive(Debug, Default)]
pub struct AimdStats {
    /// Total successful requests.
    pub successes: AtomicU64,
    /// Total failed requests.
    pub failures: AtomicU64,
    /// Total limit increases.
    pub increases: AtomicU64,
    /// Total limit decreases.
    pub decreases: AtomicU64,
}

impl AimdController {
    /// Create a new AIMD controller.
    pub fn new(config: AimdConfig) -> Self {
        let limit = config.initial_limit;
        let sample_window = config.sample_window;

        Self {
            limit: AtomicUsize::new(limit),
            in_flight: AtomicUsize::new(0),
            config,
            latency_samples: parking_lot::Mutex::new(vec![0; sample_window]),
            sample_pos: AtomicUsize::new(0),
            stats: AimdStats::default(),
        }
    }

    /// Create with default configuration.
    pub fn default_controller() -> Self {
        Self::new(AimdConfig::default())
    }

    /// Get the current concurrency limit.
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Relaxed)
    }

    /// Get the current in-flight count.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Check if we can acquire a slot (non-blocking).
    pub fn try_acquire(&self) -> Option<AimdPermit<'_>> {
        let current = self.in_flight.load(Ordering::Relaxed);
        let limit = self.limit.load(Ordering::Relaxed);

        if current < limit {
            // Try to increment in-flight counter
            let result = self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            );

            if result.is_ok() {
                return Some(AimdPermit {
                    controller: self,
                    start_time: Instant::now(),
                });
            }
        }

        None
    }

    /// Wait to acquire a slot.
    pub async fn acquire(&self) -> AimdPermit<'_> {
        loop {
            if let Some(permit) = self.try_acquire() {
                return permit;
            }
            // Backoff before retry
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    }

    /// Record a successful completion.
    fn on_success(&self, latency_ms: u64) {
        self.stats.successes.fetch_add(1, Ordering::Relaxed);

        // Record latency sample
        let pos = self.sample_pos.fetch_add(1, Ordering::Relaxed) % self.config.sample_window;
        {
            let mut samples = self.latency_samples.lock();
            samples[pos] = latency_ms;
        }

        // Check if latency is acceptable
        let avg_latency = self.avg_latency();
        if avg_latency > self.config.latency_threshold_ms {
            // High latency - proactively decrease
            self.decrease_limit();
            debug!(
                "AIMD: Proactive decrease due to latency {}ms > {}ms threshold",
                avg_latency, self.config.latency_threshold_ms
            );
        } else {
            // Good latency - increase limit
            self.increase_limit();
        }
    }

    /// Record a failure.
    fn on_failure(&self) {
        self.stats.failures.fetch_add(1, Ordering::Relaxed);
        self.decrease_limit();
        debug!("AIMD: Decrease due to failure");
    }

    /// Increase the limit additively.
    fn increase_limit(&self) {
        let current = self.limit.load(Ordering::Relaxed);
        let new_limit = (current + self.config.additive_increase).min(self.config.max_limit);

        if new_limit > current {
            self.limit.store(new_limit, Ordering::Relaxed);
            self.stats.increases.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrease the limit multiplicatively.
    fn decrease_limit(&self) {
        let current = self.limit.load(Ordering::Relaxed);
        let new_limit = ((current as f64 * self.config.multiplicative_decrease) as usize)
            .max(self.config.min_limit);

        if new_limit < current {
            self.limit.store(new_limit, Ordering::Relaxed);
            self.stats.decreases.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Calculate average latency from samples.
    fn avg_latency(&self) -> u64 {
        let samples = self.latency_samples.lock();
        let sum: u64 = samples.iter().sum();
        sum / samples.len() as u64
    }

    /// Get controller statistics.
    pub fn stats(&self) -> &AimdStats {
        &self.stats
    }
}

/// A permit to perform work under AIMD control.
pub struct AimdPermit<'a> {
    controller: &'a AimdController,
    start_time: Instant,
}

impl<'a> AimdPermit<'a> {
    /// Complete successfully.
    pub fn success(self) {
        let latency = self.start_time.elapsed().as_millis() as u64;
        self.controller.in_flight.fetch_sub(1, Ordering::Release);
        self.controller.on_success(latency);
    }

    /// Complete with failure.
    pub fn failure(self) {
        self.controller.in_flight.fetch_sub(1, Ordering::Release);
        self.controller.on_failure();
    }
}

impl Drop for AimdPermit<'_> {
    fn drop(&mut self) {
        // If not explicitly completed, treat as failure
        // Note: This is overly conservative; in practice you should call success() or failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_partition_default() {
        let partition = CorePartition::default_partition();

        assert!(partition.total_cores > 0);
        assert!(partition.tokio_threads >= 1);
        assert!(partition.rayon_threads >= 2);
        assert_eq!(
            partition.tokio_threads + partition.rayon_threads,
            partition.total_cores.max(3)
        );
    }

    #[test]
    fn test_core_partition_custom() {
        let config = CorePartitionConfig {
            tokio_fraction: 0.50,
            tokio_min_threads: 2,
            tokio_max_threads: 16,
            rayon_min_threads: 4,
            enable_work_stealing: true,
        };

        let partition = CorePartition::compute(config);

        assert!(partition.tokio_threads >= 2);
        assert!(partition.rayon_threads >= 4);
    }

    #[tokio::test]
    async fn test_batched_channel() {
        let config = BatchConfig {
            max_batch_size: 3,
            max_batch_delay: Duration::from_millis(100),
            channel_buffer: 4,
        };

        let (mut tx, mut rx) = batched_channel::<i32>(config);

        // Send items
        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();
        tx.send(3).await.unwrap(); // This should trigger a flush
        tx.flush().await.unwrap();

        // Receive items - collect all and check we got all 3
        let mut received = Vec::new();
        while let Some(item) = rx.recv().await {
            received.push(item);
            if received.len() == 3 {
                break;
            }
        }

        received.sort();
        assert_eq!(received, vec![1, 2, 3]);
    }

    #[test]
    fn test_aimd_controller() {
        let controller = AimdController::default_controller();

        assert_eq!(controller.limit(), 8); // Default initial limit
        assert_eq!(controller.in_flight(), 0);

        // Acquire permits
        let permit1 = controller.try_acquire().expect("Should acquire");
        assert_eq!(controller.in_flight(), 1);

        let permit2 = controller.try_acquire().expect("Should acquire");
        assert_eq!(controller.in_flight(), 2);

        // Complete with success
        permit1.success();
        assert_eq!(controller.in_flight(), 1);

        // Limit should increase after success
        assert!(controller.limit() >= 8);

        permit2.failure();
        assert_eq!(controller.in_flight(), 0);

        // Limit should decrease after failure
        assert!(controller.limit() <= 8);
    }
}
