//! Concurrency tests for the OpenFHE bridge worker pool.
//!
//! The bridge is replaced by a tiny shell (`sh` on Unix, PowerShell on Windows) that either
//! echoes a fixed response line per request, swallows requests, or answers garbage. The tests
//! drive the pool from many threads and check the invariants the pool promises: never more
//! live workers than `pool_size`, a worker is reserved by at most one request at a time, stalled
//! or misbehaving workers are replaced without hanging callers, and the spawn accounting
//! returns to zero.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::vector::{
    CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CkksEncryptionInput, CkksParameters,
    CkksPublicMaterial, CkksVectorBackend,
};

enum FakeBridge {
    /// Answer every request line with this line.
    Echo(String),
    /// Read requests forever, never answer.
    Silent,
}

fn valid_response_line() -> String {
    format!(
        r#"{{"version":1,"ciphertext":"AQ","security_profile":"{CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}","security_level_bits":128}}"#
    )
}

#[cfg(unix)]
fn fake_bridge(behavior: FakeBridge) -> CommandOpenFheBackend {
    let script = match behavior {
        FakeBridge::Echo(line) => {
            format!("while IFS= read -r _line; do printf '%s\\n' '{line}'; done")
        }
        FakeBridge::Silent => "while IFS= read -r _line; do :; done".to_string(),
    };
    CommandOpenFheBackend::new_unchecked("sh").with_args(["-c", script.as_str()])
}

#[cfg(windows)]
fn fake_bridge(behavior: FakeBridge) -> CommandOpenFheBackend {
    let body = match behavior {
        FakeBridge::Echo(line) => format!("[Console]::Out.WriteLine('{line}')"),
        FakeBridge::Silent => String::new(),
    };
    let script = format!("while ($null -ne ($line = [Console]::In.ReadLine())) {{ {body} }}");
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let encoded = data_encoding::BASE64.encode(&utf16);
    CommandOpenFheBackend::new_unchecked("powershell").with_args([
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded.as_str(),
    ])
}

/// A cheap program that keeps stdin open and never writes: enough for reservation tests.
fn idle_program() -> CommandOpenFheBackend {
    #[cfg(unix)]
    {
        CommandOpenFheBackend::new_unchecked("cat")
    }
    #[cfg(windows)]
    {
        CommandOpenFheBackend::new_unchecked("findstr").with_args(["never-matches"])
    }
}

fn encrypt_once(backend: &CommandOpenFheBackend, point_id: &str) -> Result<Vec<u8>, CkksError> {
    let parameters = CkksParameters::default();
    let public_material =
        CkksPublicMaterial::new(b"crypto-context".to_vec(), b"public-key".to_vec()).unwrap();
    backend.encrypt(CkksEncryptionInput {
        parameters: &parameters,
        public_material: &public_material,
        collection: "docs",
        point_id,
        vector_name: "text",
        values: &[1.0, 2.0, 3.0],
    })
}

fn live_worker_count(backend: &CommandOpenFheBackend) -> usize {
    backend.workers.lock().unwrap().len()
}

fn reserved_worker_count(backend: &CommandOpenFheBackend) -> usize {
    backend
        .workers
        .lock()
        .unwrap()
        .iter()
        .filter(|worker| worker.reserved.load(Ordering::Acquire))
        .count()
}

#[test]
fn worker_pool_never_exceeds_pool_size_under_contention() {
    const POOL: usize = 3;
    const THREADS: usize = 12;
    const ITERATIONS: usize = 40;

    let backend = Arc::new(idle_program().with_pool_size(NonZeroUsize::new(POOL).unwrap()));
    let barrier = Arc::new(Barrier::new(THREADS));
    let live = Arc::new(AtomicUsize::new(0));
    let max_live = Arc::new(AtomicUsize::new(0));
    let held: Arc<Mutex<HashSet<usize>>> = Arc::new(Mutex::new(HashSet::new()));
    let failures = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            let live = Arc::clone(&live);
            let max_live = Arc::clone(&max_live);
            let held = Arc::clone(&held);
            let failures = Arc::clone(&failures);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..ITERATIONS {
                    let Ok(reservation) = backend.worker_process() else {
                        failures.fetch_add(1, Ordering::SeqCst);
                        continue;
                    };
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    max_live.fetch_max(now, Ordering::SeqCst);
                    let key = Arc::as_ptr(reservation.worker()) as usize;
                    assert!(
                        held.lock().unwrap().insert(key),
                        "one worker was reserved by two requests at once"
                    );
                    assert!(reservation.worker().reserved.load(Ordering::Acquire));
                    thread::sleep(Duration::from_micros(200));
                    assert!(held.lock().unwrap().remove(&key));
                    live.fetch_sub(1, Ordering::SeqCst);
                    drop(reservation);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(
        failures.load(Ordering::SeqCst),
        0,
        "no caller should see an exhausted pool"
    );
    assert!(
        max_live.load(Ordering::SeqCst) <= POOL,
        "more reservations than workers"
    );
    assert!(
        live_worker_count(&backend) <= POOL,
        "pool grew past its size"
    );
    assert_eq!(reserved_worker_count(&backend), 0, "a reservation leaked");
    assert_eq!(
        backend.spawning.load(Ordering::SeqCst),
        0,
        "spawn slot leaked"
    );
    assert!(backend.worker_process().is_ok());
}

#[test]
fn concurrent_requests_share_a_bounded_pool_and_all_succeed() {
    const POOL: usize = 2;
    const THREADS: usize = 6;
    const REQUESTS: usize = 5;

    let backend = Arc::new(
        fake_bridge(FakeBridge::Echo(valid_response_line()))
            .with_pool_size(NonZeroUsize::new(POOL).unwrap())
            .with_timeout(Duration::from_secs(30)),
    );
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|thread_index| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for request in 0..REQUESTS {
                    let point_id = format!("{thread_index}-{request}");
                    let ciphertext = encrypt_once(&backend, &point_id)
                        .unwrap_or_else(|err| panic!("request {point_id} failed: {err}"));
                    assert_eq!(
                        ciphertext,
                        vec![1],
                        "bridge answer must be decoded verbatim"
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    assert!(live_worker_count(&backend) <= POOL);
    assert!(
        live_worker_count(&backend) >= 1,
        "at least one worker served the requests"
    );
    assert_eq!(reserved_worker_count(&backend), 0);
    assert_eq!(backend.spawning.load(Ordering::SeqCst), 0);
    // Every surviving worker has the context registered and is reused, not respawned.
    for worker in backend.workers.lock().unwrap().iter() {
        assert_eq!(worker.registered_contexts.lock().unwrap().len(), 1);
        assert!(
            worker.try_wait().unwrap().is_none(),
            "worker exited unexpectedly"
        );
    }
}

#[test]
fn stalled_bridge_times_out_and_is_replaced_for_every_caller() {
    const THREADS: usize = 3;
    let timeout = Duration::from_millis(1_500);
    let backend = Arc::new(
        fake_bridge(FakeBridge::Silent)
            .with_pool_size(NonZeroUsize::MIN)
            .with_timeout(timeout),
    );

    let first = backend.worker_process().unwrap();
    // Keep the stalled worker alive so a replacement cannot reuse its address and alias the
    // pointer comparison below.
    let first_worker = Arc::clone(first.worker());
    drop(first);

    let started = Instant::now();
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|thread_index| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let point_id = format!("stalled-{thread_index}");
                let err = encrypt_once(&backend, &point_id).expect_err("silent bridge must fail");
                let message = err.to_string();
                assert!(
                    message.contains("timed out")
                        || message.contains("did not accept")
                        || message.contains("exhausted"),
                    "unexpected error: {message}"
                );
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let elapsed = started.elapsed();
    // Each caller needs at most one timeout plus the bounded reservation wait; nothing hangs.
    assert!(
        elapsed >= timeout,
        "a caller returned before its timeout: {elapsed:?}"
    );
    assert!(
        elapsed < timeout * (THREADS as u32 + 1) + WORKER_RESERVATION_WAIT * THREADS as u32,
        "callers serialized far beyond the bounded waits: {elapsed:?}"
    );

    // The stalled worker was discarded; the pool hands out a fresh one and the accounting is clean.
    assert_eq!(reserved_worker_count(&backend), 0);
    assert_eq!(backend.spawning.load(Ordering::SeqCst), 0);
    let replacement = backend.worker_process().unwrap();
    assert!(
        !Arc::ptr_eq(replacement.worker(), &first_worker),
        "the stalled worker must not be handed out again"
    );
    assert!(live_worker_count(&backend) <= 1);
}

#[test]
fn garbage_bridge_output_fails_requests_without_hanging_or_leaking_workers() {
    const THREADS: usize = 4;
    const REQUESTS: usize = 3;

    let backend = Arc::new(
        fake_bridge(FakeBridge::Echo("not json".to_string()))
            .with_pool_size(NonZeroUsize::new(2).unwrap())
            .with_timeout(Duration::from_secs(30)),
    );
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|thread_index| {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for request in 0..REQUESTS {
                    let point_id = format!("garbage-{thread_index}-{request}");
                    let err =
                        encrypt_once(&backend, &point_id).expect_err("garbage must not decode");
                    assert!(
                        !err.to_string().contains("not json"),
                        "bridge output leaked into the error"
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    // A worker that answered garbage is discarded; none stays reserved or half-spawned.
    assert_eq!(reserved_worker_count(&backend), 0);
    assert_eq!(backend.spawning.load(Ordering::SeqCst), 0);
    assert!(live_worker_count(&backend) <= 2);
}
