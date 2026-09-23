//! Concurrency tests for the AEAD invocation budget and shared keyrings.
//!
//! These live next to the implementation because they preset the private invocation counter
//! close to the AES-GCM random-nonce bound instead of running four billion encryptions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use super::*;

fn test_cipher(key_byte: u8) -> AeadCipher {
    AeadCipher::new_with_material_fingerprint(
        "tenant-a:primary",
        SecretKey::from_bytes([key_byte; 32]),
        "tenant-a/primary@v1",
    )
    .unwrap()
}

fn context<'a>(point_id: &'a str) -> EncryptionContext<'a> {
    EncryptionContext::payload_text("docs", point_id, "body")
}

#[test]
fn invocation_budget_is_exact_under_contention() {
    const REMAINING: u64 = 64;
    const THREADS: usize = 16;
    const ATTEMPTS_PER_THREAD: usize = 16;

    // Budgets are shared by key bytes process-wide, so this test owns key byte 0xE2.
    let cipher = Arc::new(test_cipher(0xE2));
    cipher.set_invocations_for_test(AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT - REMAINING);
    let barrier = Arc::new(Barrier::new(THREADS));
    let successes = Arc::new(AtomicU64::new(0));
    let exhausted = Arc::new(AtomicU64::new(0));
    let envelopes = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..THREADS)
        .map(|thread_index| {
            let cipher = Arc::clone(&cipher);
            let barrier = Arc::clone(&barrier);
            let successes = Arc::clone(&successes);
            let exhausted = Arc::clone(&exhausted);
            let envelopes = Arc::clone(&envelopes);
            thread::spawn(move || {
                barrier.wait();
                for attempt in 0..ATTEMPTS_PER_THREAD {
                    let point_id = format!("{thread_index}-{attempt}");
                    match cipher.encrypt(point_id.as_bytes(), context(&point_id)) {
                        Ok(envelope) => {
                            successes.fetch_add(1, Ordering::SeqCst);
                            envelopes.lock().unwrap().push((point_id, envelope));
                        }
                        Err(EncryptionError::KeyUsageExhausted) => {
                            exhausted.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(other) => panic!("unexpected encryption error: {other:?}"),
                    }
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(
        successes.load(Ordering::SeqCst),
        REMAINING,
        "exactly the remaining budget may be spent, never more or less"
    );
    assert_eq!(
        exhausted.load(Ordering::SeqCst),
        (THREADS * ATTEMPTS_PER_THREAD) as u64 - REMAINING
    );
    assert_eq!(cipher.invocations(), AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT);
    assert!(matches!(
        cipher.encrypt(b"one more", context("late")),
        Err(EncryptionError::KeyUsageExhausted)
    ));

    // Every ciphertext produced under contention opens, uses a distinct nonce, and decrypting
    // does not consume budget.
    let envelopes = envelopes.lock().unwrap();
    let mut nonces = std::collections::BTreeSet::new();
    for (point_id, envelope) in envelopes.iter() {
        assert!(
            nonces.insert(envelope.nonce.clone()),
            "nonce reuse under contention"
        );
        assert_eq!(
            cipher.decrypt(envelope, context(point_id)).unwrap(),
            point_id.as_bytes()
        );
    }
    assert_eq!(cipher.invocations(), AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT);
}

#[test]
fn invocation_counter_matches_concurrent_encryptions_exactly() {
    const THREADS: usize = 8;
    const PER_THREAD: u64 = 200;

    let cipher = Arc::new(test_cipher(9));
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let cipher = Arc::clone(&cipher);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..PER_THREAD {
                    cipher.encrypt(b"payload", context("p")).unwrap();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(cipher.invocations(), THREADS as u64 * PER_THREAD);
}

#[test]
fn shared_keyring_serves_active_and_retired_keys_concurrently() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 64;

    let retired = test_cipher(3);
    let retired_envelopes: Vec<_> = (0..PER_THREAD)
        .map(|i| {
            let point_id = format!("retired-{i}");
            let envelope = retired
                .encrypt(point_id.as_bytes(), context(&point_id))
                .unwrap();
            (point_id, envelope)
        })
        .collect();
    let active = AeadCipher::new_with_material_fingerprint(
        "tenant-a:primary",
        SecretKey::from_bytes([4; 32]),
        "tenant-a/primary@v2",
    )
    .unwrap();
    let keyring = Arc::new(AeadKeyring::new(active).with_retired(retired));
    let retired_envelopes = Arc::new(retired_envelopes);
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|thread_index| {
            let keyring = Arc::clone(&keyring);
            let retired_envelopes = Arc::clone(&retired_envelopes);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..PER_THREAD {
                    let (point_id, envelope) = &retired_envelopes[(i + thread_index) % PER_THREAD];
                    assert_eq!(
                        keyring.decrypt(envelope, context(point_id)).unwrap(),
                        point_id.as_bytes()
                    );
                    let fresh_id = format!("active-{thread_index}-{i}");
                    let fresh = keyring
                        .encrypt(fresh_id.as_bytes(), context(&fresh_id))
                        .unwrap();
                    assert_eq!(fresh.material_fingerprint, "tenant-a/primary@v2");
                    assert_eq!(
                        keyring.decrypt(&fresh, context(&fresh_id)).unwrap(),
                        fresh_id.as_bytes()
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}
