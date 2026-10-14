# OS-level isolation for untrusted code

`happy.ai.sandbox` limits what Python can do (AST scan + builtins allow-list).
That is a language-level fence, not a security boundary. `happy.ai.isolation`
adds the boundary the **kernel** enforces.

## What the jail guarantees

| Property | How |
|---|---|
| No network | empty network namespace / `--network none` |
| No host files | private root containing only the interpreter (`/usr`), read-only |
| Code dir read-only | mounted at `/work` read-only; output is captured outside the jail |
| Own processes only | PID namespace (jail sees 1 process) |
| Unprivileged | uid 65534, all capabilities dropped, `no_new_privs` |
| Whole tree dies on timeout | process-group kill + PID namespace teardown (containers: `rm -f`) |
| No host residue | jail root is a private tmpfs inside the mount namespace |

## Backends (preference order)

1. `docker` / `podman` – `--network none --read-only --cap-drop ALL --pids-limit --memory --cpus --user 65534`, runtime default seccomp, `/tmp` tmpfs `noexec`. Build the pinned image with `deploy/Dockerfile.sandbox`.
2. `bwrap` – bubblewrap, rootless.
3. `namespaces` – `unshare` + private mounts + chroot. Works as root (drops to uid 65534) or rootless via user namespaces.

## Modes

Set `HAPPY_ISOLATION` (or pass `IsolationPolicy`):

- `required` – **fail closed**: refuse to run if no backend is usable. Use in production.
- `auto` (default) – best available backend; otherwise language-level sandbox only.
- `off` – development only.

Asking for a specific backend (`HAPPY_ISOLATION_BACKEND=docker`) never silently
downgrades to another one.

## Verify on your own infrastructure

```
HAPPY_ISOLATION=required python -m happy.ai.isolation
```

Prints which backends work and runs escape probes (read `/etc/passwd`, list
`/home`, write rootfs/workdir, open a socket, `setuid(0)`, PID visibility,
effective capabilities). Exit code 0 = every probe was blocked.

## Known limits (be honest with customers)

- Only the `namespaces` backend was exercised in development (root and rootless). `docker`, `podman` and `bwrap` argument sets are written to their documented flags but must be validated by running the self-test on a host that has them.
- The `namespaces` backend has **no cgroup limits and no seccomp filter** (RLIMITs only). Prefer docker/podman where memory/CPU/pids must be hard-capped, or run under systemd/cgroup v2 limits.
- All backends share the host kernel: a kernel exploit defeats them. For hostile multi-tenant workloads add gVisor (`runsc`) or Firecracker/microVMs and keep the kernel patched.
- Tool callables registered with `ToolRegistry` are Python functions in your process; only code run through `run_sandboxed_python` is jailed. Untrusted tools should be expressed as sandboxed source.
