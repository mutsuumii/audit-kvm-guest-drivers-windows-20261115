# Security audit: virtio-win/kvm-guest-drivers-windows

Date: 2026-11-15 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 31 issue(s): 9 critical, 22 high.

## Findings

### 1. [CRITICAL] Format string vulnerability

**CWE-134** | `vioserial/benchmark/main.cpp` line 9

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
wprintf(L"benchmark <type> <port_name> [-s <request_size>] [-c <concurrency>] [-t <time>]\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 2. [CRITICAL] Format string vulnerability

**CWE-134** | `vioserial/benchmark/main.cpp` line 12

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
wprintf(L"<port_name>      name of the port to use\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 3. [CRITICAL] Format string vulnerability

**CWE-134** | `NetKVM/DebugTools/RSS-Toeplitz/RSS-Toeplitz.cpp` line 81

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("IP calculation failed for data sample %d\n", i);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 4. [CRITICAL] Format string vulnerability

**CWE-134** | `NetKVM/DebugTools/RSS-Toeplitz/RSS-Toeplitz.cpp` line 91

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("TCP calculation failed for data sample %d\n", i);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 5. [CRITICAL] Format string vulnerability

**CWE-134** | `viosock/tcp-bridge/utils.cpp` line 317

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("Service name:\t%S\n", buffer->lpDisplayName);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 6. [CRITICAL] Format string vulnerability

**CWE-134** | `viosock/tcp-bridge/utils.cpp` line 320

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("Start name:\t%S\n", buffer->lpServiceStartName);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 7. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 855

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(databuffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 8. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 875

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 9. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 900

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 10. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 946

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 11. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 990

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(databuffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 12. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 1009

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 13. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 1027

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 14. [HIGH] Use-after-free pattern

**CWE-416** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 1148

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(buffer);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 15. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 843

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
PVOID databuffer = malloc(bufferSize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 16. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 871

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *buf = (char *)malloc(bufsize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 17. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 888

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *buf = (char *)malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 18. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 910

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *buffer = (char *)malloc(bufferSize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 19. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 978

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
PVOID databuffer = malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 20. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 1005

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *buf = (char *)malloc(maxlen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 21. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 1016

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *buf = (char *)malloc(buildsize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 22. [HIGH] Missing NULL check after allocation

**CWE-476** | `NetKVM/DebugTools/NetKVMDumpParser/NetKVMDumpParser.cpp` line 1138

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buffer = malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 23. [CRITICAL] Format string vulnerability

**CWE-134** | `viosock/tests/vsock_perf/vsock_perf.c` line 160

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("RX buffer %llu bytes\n", buf_size_bytes);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 24. [CRITICAL] Format string vulnerability

**CWE-134** | `viosock/tests/vsock_perf/vsock_perf.c` line 161

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("vsock buffer %llu bytes\n", vsock_buf_bytes);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 25. [CRITICAL] Format string vulnerability

**CWE-134** | `viosock/tests/vsock_perf/vsock_perf.c` line 283

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("TX buffer %llu bytes\n", buf_size_bytes);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 26. [HIGH] Use-after-free pattern

**CWE-416** | `viosock/tests/vsock_perf/vsock_perf.c` line 266

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 27. [HIGH] Use-after-free pattern

**CWE-416** | `viosock/tests/vsock_perf/vsock_perf.c` line 340

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 28. [HIGH] Missing NULL check after allocation

**CWE-476** | `viosock/tests/vsock_perf/vsock_perf.c` line 195

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
data = malloc((size_t)buf_size_bytes);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 29. [HIGH] Missing NULL check after allocation

**CWE-476** | `viosock/tests/vsock_perf/vsock_perf.c` line 199

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fprintf(stderr, "'malloc()' failed\n");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 30. [HIGH] Missing NULL check after allocation

**CWE-476** | `viosock/tests/vsock_perf/vsock_perf.c` line 296

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
data = malloc((size_t)buf_size_bytes);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 31. [HIGH] Missing NULL check after allocation

**CWE-476** | `viosock/tests/vsock_perf/vsock_perf.c` line 300

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fprintf(stderr, "'malloc()' failed\n");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---
