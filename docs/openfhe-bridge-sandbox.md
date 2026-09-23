# OpenFHE Bridge Sandbox Deployment

The OpenFHE bridge is part of the qdrant-sec trusted computing base because it
receives plaintext embeddings before producing CKKS ciphertext. The in-process
backend hardening verifies the executable path, owner, permissions, SHA-256 pin,
and optional Ed25519 signature; checked Linux workers also use `no_new_privs`,
core/file-size limits, stripped inherited environment, `/` as cwd, and optional
Landlock write-deny plus network namespace egress-deny rules. The strict
Landlock kinds add a read/execute allow-list (system roots, device files, the
program descriptor and configured `landlock_read_allow_roots`), so a
compromised bridge cannot read storage, configuration or key material.

For production deployments, run the bridge behind an additional host or
container sandbox. The exact profile depends on the bridge binary and OpenFHE
runtime, but the default posture should be deny-by-default with only stdin,
stdout, stderr, executable/library reads, and anonymous memory allowed.

## AppArmor Example

Use a dedicated bridge path and adjust library/cache paths to the actual image.

```apparmor
#include <tunables/global>

profile qdrant-sec-openfhe-bridge /usr/local/bin/openfhe-bridge flags=(attach_disconnected) {
  #include <abstractions/base>

  capability,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny network,
  deny mount,
  deny ptrace,

  /usr/local/bin/openfhe-bridge rix,
  /usr/lib/** r,
  /lib/** r,
  /etc/ld.so.cache r,

  owner /tmp/ r,
  deny /** wklx,
}
```

The profile intentionally denies network and writable filesystem access. If a
specific OpenFHE build needs read-only model/context files, allow only those
absolute paths and keep write access denied.

## Seccomp Container Example

When the bridge is isolated in a sidecar/container, start from Docker's default
seccomp profile and remove broad filesystem, process-control, and networking
surface. A minimal profile normally needs only process startup, memory
management, pipe I/O, time, signal, and exit syscalls. Keep the list explicit
and validate it with the exact bridge binary before rollout.

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    { "names": ["read", "write", "close", "exit", "exit_group"], "action": "SCMP_ACT_ALLOW" },
    { "names": ["brk", "mmap", "munmap", "mprotect", "mremap"], "action": "SCMP_ACT_ALLOW" },
    { "names": ["rt_sigaction", "rt_sigprocmask", "rt_sigreturn"], "action": "SCMP_ACT_ALLOW" },
    { "names": ["futex", "clock_gettime", "getrandom", "arch_prctl"], "action": "SCMP_ACT_ALLOW" },
    { "names": ["openat", "newfstatat", "readlinkat", "pread64"], "action": "SCMP_ACT_ALLOW" }
  ]
}
```

Do not allow socket syscalls unless the bridge has a documented and reviewed
reason to use the network. If dynamic library loading is not needed after
startup, consider a static bridge binary and remove `openat`/`readlinkat` from
the runtime profile.

## Runtime Expectations

- The bridge path configured in qdrant-sec must still be absolute, non-symlink,
  root/qdrant-owned, not group/world writable, and SHA-256 pinned.
- Checked OpenFHE bridge backends require Linux fd-backed `/proc/self/fd`
  execution; non-Linux builds fail closed instead of using a path-based
  validation/hash/exec sequence.
- Prefer `process_landlock_strict_netns` or `process_pool_landlock_strict_netns`
  backend kinds on Linux when the bridge has no legitimate host-network
  dependency; these add Qdrant-managed network namespace isolation to a
  Landlock policy that denies writes and allows reads and execution only under
  `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`, the `/dev/null`,
  `/dev/urandom` and `/dev/random` devices, the bridge program itself and the
  roots listed in `landlock_read_allow_roots`. List only what the bridge needs
  (for example an OpenFHE data directory); a listed root that does not exist
  fails the worker spawn closed. Fall back to `process_landlock_netns` /
  `process_pool_landlock_netns` only when the bridge needs reads outside a
  fixed allow-list, and to `process_landlock` / `process_pool_landlock` (or
  their `_strict` variants) when the host does not permit network namespace
  creation; provide egress denial through AppArmor/seccomp/container policy in
  that case.
- Do not pass Qdrant secrets to the bridge environment. Checked qdrant-sec
  workers strip inherited service environment by default; container launchers
  should do the same.
- Disable core dumps at the container/systemd layer as a second line of defense.
- Treat bridge logs as sensitive. qdrant-sec does not expose bridge stderr in
  returned errors, but external supervisors must still avoid forwarding
  plaintext-bearing bridge output.
