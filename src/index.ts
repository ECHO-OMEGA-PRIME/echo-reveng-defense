/**
 * ECHO REVENG DEFENSE — Reverse Engineering Security Detection Engine v1.0.0
 *
 * 7 Security Detection Capabilities:
 *   1. Anti-Debugging Detection    — Detect debugger checks, timing attacks, ptrace guards
 *   2. Anti-Tamper Detection       — Integrity checks, checksum guards, code signing validation
 *   3. Code Obfuscation Analysis   — Control flow flattening, opaque predicates, string encryption
 *   4. License Protection Analysis — License validation, hardware binding, trial enforcement
 *   5. DRM Analysis                — Content protection, key management, media encryption
 *   6. Firmware Security Analysis  — Boot chain, secure boot, TEE, firmware update validation
 *   7. SBOM Analysis               — Dependency inventory, CVE correlation, license compliance
 *
 * Cloudflare Worker — D1 + KV + Service Bindings (Shared Brain, Engine Runtime, Echo Chat)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ECHO_CHAT: Fetcher;
  SHARED_BRAIN: Fetcher;
  ENGINE_RUNTIME: Fetcher;
  ECHO_API_KEY: string;
  WORKER_VERSION: string;
}

interface AnalysisRequest {
  /** Base64-encoded binary or raw text source code */
  sample?: string;
  /** Hex dump of binary */
  hex_dump?: string;
  /** File metadata */
  filename?: string;
  file_size?: number;
  file_type?: string;
  /** Which detectors to run (default: all 7) */
  detectors?: string[];
  /** Natural language query about the sample */
  query?: string;
  /** Disassembly listing */
  disassembly?: string;
  /** String table extracted from binary */
  strings?: string[];
  /** Import table */
  imports?: string[];
  /** Export table */
  exports?: string[];
  /** Section headers */
  sections?: SectionInfo[];
  /** SBOM in CycloneDX or SPDX format */
  sbom_json?: Record<string, unknown>;
  /** Package manifest (package.json, requirements.txt, Cargo.toml, etc.) */
  manifest?: string;
  manifest_type?: string;
}

interface SectionInfo {
  name: string;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  characteristics?: string;
}

interface DetectionResult {
  detector: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  findings: Finding[];
  summary: string;
  recommendations: string[];
  doctrines_applied: string[];
}

interface Finding {
  id: string;
  category: string;
  description: string;
  evidence: string;
  offset?: string;
  severity: string;
  mitre_attack?: string;
  cwe?: string;
}

interface AnalysisResponse {
  analysis_id: string;
  filename: string;
  file_type: string;
  timestamp: string;
  detectors_run: string[];
  results: DetectionResult[];
  overall_risk: string;
  overall_score: number;
  ai_summary?: string;
}

// ═══════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════

function log(level: string, message: string, data: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    worker: 'echo-reveng-defense',
    level,
    message,
    ...data,
  }));
}

// ═══════════════════════════════════════════════════════════════
// DOCTRINE KNOWLEDGE BASE — 7 SECURITY DETECTION DOMAINS
// ═══════════════════════════════════════════════════════════════

interface DoctrineBlock {
  id: string;
  detector: string;
  topic: string;
  keywords: string[];
  conclusion: string;
  reasoning: string;
  indicators: string[];
  mitre_techniques: string[];
  severity_default: string;
  counter_measures: string[];
}

const DOCTRINE_CACHE: DoctrineBlock[] = [
  // ─── 1. ANTI-DEBUGGING DETECTION ───
  {
    id: 'AD-001', detector: 'anti_debugging', topic: 'IsDebuggerPresent API Check',
    keywords: ['IsDebuggerPresent', 'NtQueryInformationProcess', 'CheckRemoteDebuggerPresent', 'PEB.BeingDebugged'],
    conclusion: 'Binary uses Windows API-based debugger detection. IsDebuggerPresent reads the PEB.BeingDebugged flag directly. This is the most common anti-debugging technique and is trivially bypassed by patching the PEB or hooking the API.',
    reasoning: 'PE binaries frequently import IsDebuggerPresent or its NT-level equivalents. Detection involves scanning the import table and cross-referencing with known anti-debug API signatures. Presence indicates intentional debugger evasion.',
    indicators: ['Import of kernel32!IsDebuggerPresent', 'Import of ntdll!NtQueryInformationProcess with ProcessDebugPort (0x7)', 'PEB direct read at fs:[0x30]+0x02 (x86) or gs:[0x60]+0x02 (x64)'],
    mitre_techniques: ['T1622 - Debugger Evasion', 'T1497.001 - System Checks'],
    severity_default: 'medium', counter_measures: ['Patch PEB.BeingDebugged to 0', 'Hook IsDebuggerPresent to return FALSE', 'Use ScyllaHide or TitanHide kernel plugin'],
  },
  {
    id: 'AD-002', detector: 'anti_debugging', topic: 'Timing-Based Anti-Debug',
    keywords: ['rdtsc', 'QueryPerformanceCounter', 'GetTickCount', 'timeGetTime', 'timing check', 'rdtscp'],
    conclusion: 'Binary uses timing measurements to detect debugger presence. Single-stepping or breakpoints introduce measurable delays (typically >100ms) between consecutive timing reads. Threshold comparison triggers evasion behavior.',
    reasoning: 'Timing attacks compare elapsed time between two measurement points. Under normal execution, the delta is microseconds; under a debugger, it is milliseconds to seconds. The binary computes delta and branches on threshold.',
    indicators: ['Consecutive rdtsc instructions with cmp/ja between them', 'QueryPerformanceCounter called twice with delta comparison', 'GetTickCount64 difference checked against threshold (typically 0x100-0x1000)'],
    mitre_techniques: ['T1622 - Debugger Evasion', 'T1497.003 - Time Based Evasion'],
    severity_default: 'medium', counter_measures: ['Hook timing APIs to return consistent values', 'Use hardware breakpoints instead of software BPs', 'Freeze time with kernel driver'],
  },
  {
    id: 'AD-003', detector: 'anti_debugging', topic: 'Exception-Based Anti-Debug',
    keywords: ['SetUnhandledExceptionFilter', 'VEH', 'int 2d', 'int 3', 'EXCEPTION_BREAKPOINT', 'trap flag'],
    conclusion: 'Binary uses structured exception handling to detect debuggers. INT 2D/INT 3 instructions generate exceptions that behave differently under debugger vs normal execution. SEH chain manipulation detects debugger-modified handlers.',
    reasoning: 'Under normal execution, INT 3 raises EXCEPTION_BREAKPOINT handled by the SEH chain. Under a debugger, the debugger intercepts it first. The binary tests which handler runs to determine debugger presence.',
    indicators: ['INT 2D instruction followed by conditional branch', 'SetUnhandledExceptionFilter with anti-debug callback', 'Manual SEH chain with trap flag (TF) manipulation', 'OutputDebugString with GetLastError check'],
    mitre_techniques: ['T1622 - Debugger Evasion'], severity_default: 'medium',
    counter_measures: ['Pass exceptions to application in debugger settings', 'Patch INT 2D/3 instructions with NOPs', 'Handle EXCEPTION_SINGLE_STEP in debugger'],
  },
  {
    id: 'AD-004', detector: 'anti_debugging', topic: 'Hardware Debug Register Detection',
    keywords: ['DR0', 'DR1', 'DR2', 'DR3', 'DR7', 'debug registers', 'GetThreadContext', 'NtGetContextThread'],
    conclusion: 'Binary reads hardware debug registers (DR0-DR3, DR7) to detect hardware breakpoints. Non-zero DR0-DR3 values indicate active hardware breakpoints set by a debugger. DR7 flags reveal breakpoint conditions.',
    reasoning: 'x86/x64 processors have 4 hardware breakpoint registers (DR0-DR3) and a control register (DR7). Analysts use these for non-intrusive breakpoints. The binary reads them via GetThreadContext or direct MOV instructions in kernel mode.',
    indicators: ['GetThreadContext / NtGetContextThread with CONTEXT_DEBUG_REGISTERS flag', 'Direct MOV from DR0-DR7 (kernel drivers)', 'Comparison of DR0-DR3 against 0'],
    mitre_techniques: ['T1622 - Debugger Evasion'], severity_default: 'high',
    counter_measures: ['Clear DR0-DR7 before GetThreadContext returns', 'Use memory breakpoints instead', 'Hook NtGetContextThread'],
  },
  {
    id: 'AD-005', detector: 'anti_debugging', topic: 'Process Environment Anti-Debug',
    keywords: ['NtQuerySystemInformation', 'SystemKernelDebuggerInformation', 'parent process', 'Explorer.exe', 'NtQueryObject'],
    conclusion: 'Binary queries process environment to detect debugging context. Checks include parent process validation (expected: explorer.exe or services.exe), kernel debugger presence, debug object handle count, and process creation flags.',
    reasoning: 'When launched from a debugger, the parent process is the debugger executable instead of explorer.exe. Additionally, the system may report kernel debugger presence or elevated debug privileges.',
    indicators: ['NtQueryInformationProcess with ProcessDebugObjectHandle', 'Parent PID comparison against explorer.exe PID', 'NtQuerySystemInformation with SystemKernelDebuggerInformation', 'ProcessBasicInformation parent PID check'],
    mitre_techniques: ['T1622 - Debugger Evasion', 'T1057 - Process Discovery'], severity_default: 'medium',
    counter_measures: ['Spoof parent PID', 'Hook NtQuerySystemInformation', 'Use debug object removal'],
  },

  // ─── 2. ANTI-TAMPER DETECTION ───
  {
    id: 'AT-001', detector: 'anti_tamper', topic: 'Code Integrity Self-Check (CRC/Hash)',
    keywords: ['CRC32', 'SHA256', 'MD5', 'checksum', 'self-hash', 'code integrity', '.text hash'],
    conclusion: 'Binary computes a hash or CRC of its own code section at runtime and compares against a stored reference. If the values differ, the code has been patched (breakpoints, NOP patches, hook detours). The binary terminates or alters behavior on mismatch.',
    reasoning: 'Software breakpoints (INT 3 / 0xCC) modify the code section in memory. CRC/hash self-checks detect these modifications. Typically computed over the .text section virtual address range.',
    indicators: ['CRC32 computation loop over code section VA range', 'SHA-256 / MD5 of PE .text section', 'Stored hash constant compared against runtime computation', 'Conditional exit/crash on hash mismatch'],
    mitre_techniques: ['T1027.009 - Stripped Payloads', 'T1497 - Virtualization/Sandbox Evasion'], severity_default: 'high',
    counter_measures: ['Use hardware breakpoints only', 'Patch the stored reference hash', 'Hook the hash function to return expected value', 'Memory breakpoint on hash comparison'],
  },
  {
    id: 'AT-002', detector: 'anti_tamper', topic: 'Import Address Table Guard',
    keywords: ['IAT', 'import table', 'hook detection', 'inline hook', 'detour', 'trampoline', 'JMP patch'],
    conclusion: 'Binary validates its Import Address Table against expected function addresses. Detects API hooking by checking if imported function pointers fall within their expected DLL address ranges. Inline hooks are detected by checking the first bytes of imported functions for JMP/CALL detours.',
    reasoning: 'API hooking replaces IAT entries or patches function prologues with JMP instructions. The binary reads the first 5-16 bytes of each critical API function and checks for 0xE9 (JMP rel32), 0xFF25 (JMP [addr]), or other detour signatures.',
    indicators: ['IAT walk comparing function pointers against module base ranges', 'First-byte check of API functions for 0xE9/0xFF/0xEB', 'GetProcAddress + comparison against IAT entry', 'Module base address validation via GetModuleHandle'],
    mitre_techniques: ['T1574.001 - DLL Search Order Hijacking'], severity_default: 'high',
    counter_measures: ['Use syscall stubs to bypass hooks', 'Restore original function bytes from disk', 'Use deeper hook trampoline beyond check range'],
  },
  {
    id: 'AT-003', detector: 'anti_tamper', topic: 'Digital Signature Verification',
    keywords: ['Authenticode', 'WinVerifyTrust', 'certificate', 'code signing', 'sigcheck', 'X.509'],
    conclusion: 'Binary verifies its own Authenticode digital signature at runtime. Uses WinVerifyTrust or manual certificate chain validation to ensure the PE file has not been modified since signing. Unsigned or re-signed binaries are rejected.',
    reasoning: 'Code signing creates a cryptographic hash of the PE file (excluding the signature directory) signed with a private key. Runtime verification ensures no bytes were modified post-signing, including patches, resource modifications, or section additions.',
    indicators: ['WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2', 'CertGetCertificateChain for chain validation', 'Manual PE signature directory parsing', 'Certificate thumbprint comparison against hardcoded value'],
    mitre_techniques: ['T1553.002 - Code Signing'], severity_default: 'high',
    counter_measures: ['Re-sign with your own certificate', 'Patch WinVerifyTrust to return S_OK', 'Remove signature check branch'],
  },
  {
    id: 'AT-004', detector: 'anti_tamper', topic: 'Memory Guard Pages',
    keywords: ['PAGE_GUARD', 'VirtualProtect', 'guard page', 'STATUS_GUARD_PAGE_VIOLATION', 'memory protection'],
    conclusion: 'Binary uses PAGE_GUARD memory protection to detect memory read/write access by analysis tools. Accessing a guard page triggers a one-shot exception. If the exception does not occur (because a debugger consumed it), the binary detects tampering.',
    reasoning: 'VirtualProtect with PAGE_GUARD flag sets up a trap on first access. Memory scanners and debuggers that read protected memory consume the guard page exception, which the binary can detect by checking if the guard was tripped.',
    indicators: ['VirtualProtect with PAGE_GUARD flag (0x100)', 'Exception handler checking for STATUS_GUARD_PAGE_VIOLATION', 'Guard page on critical data sections', 'VirtualQuery to verify guard status after expected access'],
    mitre_techniques: ['T1622 - Debugger Evasion'], severity_default: 'medium',
    counter_measures: ['Set debugger to pass guard page exceptions', 'Re-set guard pages after handling', 'Skip guard page reads in memory scanner'],
  },

  // ─── 3. CODE OBFUSCATION ANALYSIS ───
  {
    id: 'OB-001', detector: 'obfuscation', topic: 'Control Flow Flattening',
    keywords: ['switch dispatch', 'state machine', 'dispatcher', 'CFF', 'flattening', 'OLLVM'],
    conclusion: 'Binary uses control flow flattening (CFF) to obscure the original program logic. All basic blocks are placed at the same nesting level inside a switch-based dispatcher loop. The state variable determines which block executes next, destroying the natural control flow graph.',
    reasoning: 'CFF transforms a function with natural if/else/loop structure into a single while(true) { switch(state) { case N: ... state = M; } } pattern. This makes static analysis extremely difficult as all blocks appear as siblings.',
    indicators: ['Single large switch statement with 20+ cases in one function', 'State variable updated at end of each case', 'while(true) or for(;;) loop wrapping a switch', 'Uniform basic block nesting depth', 'OLLVM-style CFF patterns'],
    mitre_techniques: ['T1027.002 - Software Packing', 'T1027 - Obfuscated Files or Information'], severity_default: 'high',
    counter_measures: ['Symbolic execution to recover original CFG', 'Pattern-based deobfuscation (D-810, SATURN)', 'Trace-based recovery via dynamic execution'],
  },
  {
    id: 'OB-002', detector: 'obfuscation', topic: 'Opaque Predicates',
    keywords: ['opaque predicate', 'dead code', 'always true', 'always false', 'invariant condition', 'tautology'],
    conclusion: 'Binary contains opaque predicates — conditional branches where the outcome is predetermined but statically indeterminate. They insert fake control flow paths that are never taken (or always taken), inflating the CFG and confusing disassemblers.',
    reasoning: 'Opaque predicates exploit mathematical invariants (e.g., x*(x+1) is always even) to create branches that always go one way. The dead path contains junk code or overlapping instructions that confuse linear disassembly.',
    indicators: ['Conditions using number-theoretic identities (x^2 + x always even)', 'Conditional jump to overlapping instruction boundary', 'Dead code paths with invalid instructions', 'Constant propagation reveals always-true/false conditions'],
    mitre_techniques: ['T1027 - Obfuscated Files or Information'], severity_default: 'medium',
    counter_measures: ['Abstract interpretation to resolve predicates', 'Symbolic execution with constraint solving', 'Pattern match known opaque predicate forms'],
  },
  {
    id: 'OB-003', detector: 'obfuscation', topic: 'String Encryption',
    keywords: ['encrypted strings', 'string decryption', 'XOR strings', 'runtime decrypt', 'obfuscated strings', 'FLOSS'],
    conclusion: 'Binary stores strings in encrypted form, decrypting them at runtime only when needed. This defeats static string analysis. Common methods: XOR with rotating key, RC4, AES, custom ciphers, or stack-constructed strings.',
    reasoning: 'Static string analysis reveals API names, URLs, file paths, and debug messages. Encrypting strings forces analysts to run the binary or emulate the decryption routine. Most malware and protected software use this technique.',
    indicators: ['XOR loop over data section with hardcoded key', 'No readable strings in .rdata but runtime string references exist', 'Decryption stub called before every string use', 'Stack-constructed strings (MOV BYTE [esp+N], char repeated)'],
    mitre_techniques: ['T1027.013 - Encrypted/Encoded File', 'T1140 - Deobfuscate/Decode Files'], severity_default: 'medium',
    counter_measures: ['FLOSS automated string extraction', 'Emulate decryption routine in Unicorn/Qiling', 'IDAPython script to decrypt at analysis time', 'Dynamic analysis with API monitoring'],
  },
  {
    id: 'OB-004', detector: 'obfuscation', topic: 'Virtual Machine Obfuscation (VMProtect/Themida)',
    keywords: ['VMProtect', 'Themida', 'VM handler', 'bytecode', 'virtual CPU', 'VM dispatcher', 'pcode'],
    conclusion: 'Binary is protected by a code virtualization engine (VMProtect, Themida, CodeVirtualizer). Original x86/x64 instructions are translated to proprietary bytecode executed by an embedded virtual CPU. Each protected instance uses a unique VM architecture.',
    reasoning: 'VM-based obfuscation is the strongest commercially available protection. The VM interpreter is itself obfuscated, and the bytecode ISA is randomized per build. Recovery requires lifting the VM bytecode back to x86 or analyzing the VM handlers individually.',
    indicators: ['Large opaque dispatcher loop with 50-200+ handler cases', 'Bytecode stream in dedicated section (.vmp, .themida)', 'VM context structure (virtual registers, virtual stack pointer)', 'Known packer signatures (VMP section names, entry point patterns)', 'High entropy (>7.5) in code sections'],
    mitre_techniques: ['T1027.002 - Software Packing', 'T1027 - Obfuscated Files or Information'], severity_default: 'critical',
    counter_measures: ['VMHunt/Automatic VM analysis frameworks', 'Trace-based devirtualization', 'VTIL intermediate representation lifting', 'NoVmp for VMProtect specifically'],
  },
  {
    id: 'OB-005', detector: 'obfuscation', topic: 'Dead Code Injection and Junk Instructions',
    keywords: ['dead code', 'junk code', 'NOP sled', 'metamorphic', 'instruction substitution', 'garbage instructions'],
    conclusion: 'Binary contains injected dead code and junk instructions that do not affect program semantics. These inflate code size, slow analysis, and defeat signature-based detection. Instructions may include NOPs, redundant register operations, or computations whose results are discarded.',
    reasoning: 'Dead code injection increases the number of basic blocks and instructions an analyst must examine. Combined with instruction substitution (e.g., XOR EAX,EAX instead of MOV EAX,0), it creates a metamorphic appearance even for static code.',
    indicators: ['Redundant push/pop pairs with no net effect', 'Arithmetic on registers whose values are immediately overwritten', 'NOP sequences or equivalent NOP patterns (LEA EAX,[EAX+0])', 'Code blocks with no data flow connection to output'],
    mitre_techniques: ['T1027 - Obfuscated Files or Information'], severity_default: 'low',
    counter_measures: ['Dead code elimination pass in decompiler', 'Data flow analysis to identify live instructions', 'Compiler optimization passes on lifted IR'],
  },

  // ─── 4. LICENSE PROTECTION ANALYSIS ───
  {
    id: 'LP-001', detector: 'license_protection', topic: 'Serial Key Validation Algorithm',
    keywords: ['serial key', 'license key', 'registration', 'keygen', 'validation routine', 'checksum key'],
    conclusion: 'Binary implements a serial key validation algorithm. The key format typically involves segments (XXXX-XXXX-XXXX) with mathematical relationships between segments (checksums, modular arithmetic, Luhn algorithm). The validation function computes expected values from key parts and compares.',
    reasoning: 'License key validation is the most basic protection. The validation algorithm can be reversed to create keygens. Key analysis involves locating the validation function (typically near registration UI code), understanding the mathematical constraints, and inverting them.',
    indicators: ['String comparisons near "Registration", "License", "Serial" strings', 'Modular arithmetic (DIV, MOD) on key character values', 'Character-to-integer conversion loops (atoi, strtol)', 'Branch on validation result to "registered" vs "trial" mode', 'Key format parsing with delimiter splitting'],
    mitre_techniques: ['T1588.004 - Obtain Capabilities: Digital Certificates'], severity_default: 'medium',
    counter_measures: ['Asymmetric key validation (RSA/ECDSA signed licenses)', 'Server-side validation', 'Hardware-bound license with TPM attestation'],
  },
  {
    id: 'LP-002', detector: 'license_protection', topic: 'Hardware Fingerprinting for License Binding',
    keywords: ['hardware ID', 'machine ID', 'CPUID', 'MAC address', 'disk serial', 'WMI', 'fingerprint'],
    conclusion: 'Binary generates a hardware fingerprint from system-specific identifiers to bind the license to a specific machine. Common sources: CPUID, disk serial number, MAC address, motherboard serial (WMI), Windows product ID, and SMBIOS UUID.',
    reasoning: 'Hardware binding prevents license sharing across machines. The fingerprint is typically a hash (SHA-256/MD5) of concatenated hardware identifiers. The license file or key contains an expected fingerprint hash, validated at startup.',
    indicators: ['CPUID instruction (EAX=1 for processor info)', 'WMI queries for Win32_BaseBoard, Win32_DiskDrive', 'GetAdaptersInfo / GetAdaptersAddresses for MAC', 'DeviceIoControl with IOCTL_STORAGE_QUERY_PROPERTY for disk serial', 'Concatenation + hash of multiple hardware values'],
    mitre_techniques: ['T1082 - System Information Discovery', 'T1497.001 - System Checks'], severity_default: 'medium',
    counter_measures: ['Virtual machine with cloned hardware IDs', 'Hook WMI/CPUID to return expected values', 'Patch fingerprint comparison'],
  },
  {
    id: 'LP-003', detector: 'license_protection', topic: 'Trial Period Enforcement',
    keywords: ['trial', 'evaluation', 'expiration', 'days remaining', 'FILETIME', 'registry timestamp', 'nag screen'],
    conclusion: 'Binary enforces a trial period using timestamp comparison. Install date stored in registry/file/encrypted blob is compared against current system time. Expiration triggers feature restriction, nag screens, or application shutdown.',
    reasoning: 'Trial enforcement stores the first-run timestamp and computes elapsed days. To prevent clock manipulation, sophisticated implementations also check NTP time, PE compile timestamp delta, or monotonic file system timestamps.',
    indicators: ['Registry read/write under HKCU\\Software\\<vendor>', 'GetSystemTime / GetLocalTime near date arithmetic', 'FILETIME subtraction and division by 864000000000 (100ns per day)', 'Date comparison with conditional UI changes', '"Trial expired" or "days remaining" strings'],
    mitre_techniques: [], severity_default: 'low',
    counter_measures: ['Delete registry entries and reinstall', 'Hook GetSystemTime to return earlier date', 'Patch trial check branch to always pass', 'Patch stored timestamp to future date'],
  },
  {
    id: 'LP-004', detector: 'license_protection', topic: 'Online License Activation',
    keywords: ['activation server', 'license server', 'phone home', 'online validation', 'heartbeat', 'deactivation'],
    conclusion: 'Binary contacts a remote license server for activation and periodic validation. The activation flow involves sending a hardware fingerprint + license key to the server, receiving a signed activation token. Periodic heartbeats revalidate. Server-side revocation is possible.',
    reasoning: 'Online activation is stronger than offline validation because the server controls the authority. However, it creates a single point of failure and can be bypassed by DNS redirection, local server emulation, or response replay.',
    indicators: ['HTTPS requests to vendor domain with license/machine data', 'JSON/XML payload with hardware ID + serial key', 'Certificate pinning on activation endpoint', 'Periodic timer-based revalidation calls', 'Offline grace period with cached token'],
    mitre_techniques: ['T1071.001 - Application Layer Protocol: Web Protocols'], severity_default: 'high',
    counter_measures: ['DNS redirect to local emulated server', 'Replay captured activation response', 'Patch certificate pinning', 'Capture and replay valid activation token'],
  },

  // ─── 5. DRM ANALYSIS ───
  {
    id: 'DRM-001', detector: 'drm', topic: 'Media Content Encryption (Widevine/FairPlay/PlayReady)',
    keywords: ['Widevine', 'FairPlay', 'PlayReady', 'CENC', 'content key', 'CDM', 'EME'],
    conclusion: 'Application uses a commercial DRM system (Widevine L1/L3, Apple FairPlay, Microsoft PlayReady) for media content protection. The Content Decryption Module (CDM) handles key exchange with the license server and decrypts media segments. CENC (Common Encryption) is the standard container format.',
    reasoning: 'Modern streaming DRM uses Encrypted Media Extensions (EME) in browsers or platform CDMs. The license server issues content keys encrypted to the CDM. L1 (hardware TEE) is significantly harder to attack than L3 (software). Key extraction from L3 CDMs is a known attack vector.',
    indicators: ['EME API calls (requestMediaKeySystemAccess, createMediaKeys)', 'Widevine CDM library (widevinecdm.dll / libwidevinecdm.so)', 'PSSH box parsing in MP4/DASH manifest', 'License server communication (typically POST with binary protobuf)', 'Content key storage in process memory during playback'],
    mitre_techniques: ['T1588.001 - Obtain Capabilities: Malware'], severity_default: 'critical',
    counter_measures: ['L3 CDM key extraction tools', 'HDMI capture for L1', 'CDM proxy for key interception', 'Screen recording (quality loss)'],
  },
  {
    id: 'DRM-002', detector: 'drm', topic: 'Game Anti-Cheat / DRM (Denuvo/EAC/BattlEye)',
    keywords: ['Denuvo', 'EasyAntiCheat', 'BattlEye', 'anti-cheat', 'kernel driver', 'ring0', 'game protection'],
    conclusion: 'Application uses a game DRM/anti-cheat system. Denuvo wraps the Steam/Origin DRM stub with VM-based obfuscation. EAC/BattlEye install kernel drivers for integrity monitoring. These systems combine anti-debug, anti-tamper, and kernel-level monitoring.',
    reasoning: 'Game DRM is multi-layered: Denuvo adds VM obfuscation + server triggers, while anti-cheat systems (EAC, BattlEye, Vanguard) use ring-0 kernel drivers for process memory scanning, driver integrity checks, and system call monitoring.',
    indicators: ['Denuvo: Steam API wrapper + large VM-protected code sections', 'EAC: EasyAntiCheat.exe service + EasyAntiCheat.sys kernel driver', 'BattlEye: BEService.exe + BEClient.dll + BEDaisy.sys', 'Kernel driver loading (NtLoadDriver, SCM)', 'Periodic server-side validation calls'],
    mitre_techniques: ['T1027.002 - Software Packing', 'T1014 - Rootkit'], severity_default: 'critical',
    counter_measures: ['Wait for Denuvo removal (publisher often patches it out)', 'Kernel driver bypass requires equivalent ring-0 access', 'Hypervisor-based analysis (VT-x passthrough)'],
  },
  {
    id: 'DRM-003', detector: 'drm', topic: 'eBook / Document DRM (Adobe DRM / Kindle)',
    keywords: ['Adobe DRM', 'ADEPT', 'Kindle DRM', 'AZW', 'PDF DRM', 'document protection', 'ebook encryption'],
    conclusion: 'Document uses publisher DRM for access control. Adobe ADEPT encrypts ePub/PDF with AES-128-CBC, key derivable from Adobe account credentials. Kindle uses a device-specific key derivable from device serial number. Both can be stripped with the correct account/device key.',
    reasoning: 'eBook DRM binds content to an account or device. The encryption key is derived from user credentials (Adobe) or device serial (Kindle). Once the derivation algorithm is known, any authorized device can produce the decryption key, enabling format-shifting.',
    indicators: ['Adobe ADEPT: META-INF/encryption.xml in ePub', 'AES-128-CBC encrypted content with key in rights.xml', 'Kindle: PID-based key in EXTH header', 'PDF: /Encrypt dictionary with Standard security handler'],
    mitre_techniques: [], severity_default: 'medium',
    counter_measures: ['DeDRM tools with account credentials', 'Calibre plugin for format conversion', 'Key extraction from authorized reader application'],
  },

  // ─── 6. FIRMWARE SECURITY ANALYSIS ───
  {
    id: 'FW-001', detector: 'firmware_security', topic: 'Secure Boot Chain Validation',
    keywords: ['secure boot', 'UEFI', 'boot chain', 'root of trust', 'measured boot', 'TPM', 'PCR'],
    conclusion: 'Firmware implements a secure boot chain where each stage cryptographically verifies the next before execution. The root of trust is typically in ROM/OTP. Chain: ROM bootloader → SPL → U-Boot/UEFI → Kernel → Init. Each transition validates a digital signature.',
    reasoning: 'Secure boot prevents execution of unauthorized firmware. Breaking any link in the chain allows persistent malware. Analysis involves examining each stage for signature verification, key storage, rollback protection, and bypass conditions.',
    indicators: ['RSA/ECDSA signature verification at boot stages', 'X.509 certificate chain in firmware image', 'TPM PCR extension at each boot stage', 'UEFI Secure Boot variables (PK, KEK, db, dbx)', 'Anti-rollback counter in OTP/fuses'],
    mitre_techniques: ['T1542.001 - System Firmware', 'T1495 - Firmware Corruption'], severity_default: 'critical',
    counter_measures: ['Verify all boot stage signatures', 'Enable measured boot with TPM attestation', 'Implement anti-rollback protection', 'Use hardware root of trust (OTP-fused key)'],
  },
  {
    id: 'FW-002', detector: 'firmware_security', topic: 'Firmware Update Validation',
    keywords: ['OTA update', 'firmware update', 'signed update', 'update verification', 'downgrade protection'],
    conclusion: 'Firmware update mechanism must validate authenticity and integrity of update packages. Analysis checks: signature verification algorithm, key management (asymmetric required), version rollback protection, update transport security, and recovery/failsafe mechanisms.',
    reasoning: 'Insecure firmware update is one of the most critical IoT vulnerabilities. Attackers who can install arbitrary firmware gain persistent code execution. Common flaws: symmetric-key signing, no version check, plaintext transport, writable key storage.',
    indicators: ['Update package format (header + signature + payload)', 'Signature verification function in update handler', 'Version comparison against stored version counter', 'TLS/DTLS for update download (or lack thereof)', 'Recovery partition and failsafe boot logic'],
    mitre_techniques: ['T1542.001 - System Firmware', 'T1195.002 - Supply Chain Compromise'], severity_default: 'critical',
    counter_measures: ['Asymmetric signature (RSA-2048/ECDSA-P256 minimum)', 'Anti-rollback with monotonic counter', 'Dual-bank A/B update with fallback', 'Encrypted update payload (confidentiality)'],
  },
  {
    id: 'FW-003', detector: 'firmware_security', topic: 'Debug Interface Exposure (JTAG/UART/SWD)',
    keywords: ['JTAG', 'UART', 'SWD', 'debug port', 'serial console', 'debug interface', 'test points'],
    conclusion: 'Firmware device exposes debug interfaces (JTAG, SWD, UART) that allow full memory read/write, CPU halt/step, and firmware extraction. Production devices should disable or lock these interfaces. Exposed UART often provides root shell access.',
    reasoning: 'Debug interfaces are essential during development but devastating in production. JTAG/SWD give full hardware debugger access. UART often boots to a login shell or dumps boot logs with sensitive information. Fuse-based disable is the strongest protection.',
    indicators: ['Unpopulated headers or test pads on PCB', 'JTAG TDI/TDO/TMS/TCK signals on connector', 'UART TX/RX at 115200 baud (most common)', 'SWD SWDIO/SWCLK on ARM Cortex-M devices', 'Boot log output on serial console'],
    mitre_techniques: ['T1200 - Hardware Additions', 'T1542 - Pre-OS Boot'], severity_default: 'high',
    counter_measures: ['Disable JTAG/SWD via fuse or JTAG-lock', 'Require authentication on UART console', 'Remove debug test points from production PCB', 'Use secure debug with certificate-based unlock'],
  },
  {
    id: 'FW-004', detector: 'firmware_security', topic: 'Hardcoded Credentials in Firmware',
    keywords: ['hardcoded password', 'default credentials', 'backdoor', 'firmware password', 'embedded key', 'secret key'],
    conclusion: 'Firmware contains hardcoded credentials (passwords, API keys, private keys, certificates). These are extractable by anyone with access to the firmware binary. Common locations: ELF string table, configuration files in filesystem, environment variables in init scripts.',
    reasoning: 'Hardcoded credentials are consistently in the OWASP IoT Top 10. Firmware extraction (via JTAG, SPI flash read, or update package) reveals all embedded secrets. Once one device is compromised, all devices with the same firmware are compromised.',
    indicators: ['Readable passwords in binary strings output', 'Private keys (BEGIN RSA PRIVATE KEY) in filesystem', 'Default username/password pairs in /etc/shadow or equivalent', 'API tokens or cloud service keys in configuration files', 'Symmetric encryption keys in code constants'],
    mitre_techniques: ['T1552.001 - Credentials In Files', 'T1078.001 - Default Accounts'], severity_default: 'critical',
    counter_measures: ['Use device-unique keys provisioned at manufacturing', 'Store secrets in secure element (TPM, ATECC608)', 'Per-device password derived from hardware ID', 'Remote credential provisioning on first boot'],
  },

  // ─── 7. SBOM ANALYSIS ───
  {
    id: 'SBOM-001', detector: 'sbom', topic: 'Dependency CVE Correlation',
    keywords: ['CVE', 'vulnerability', 'NVD', 'GHSA', 'dependency scan', 'vulnerable component', 'known vulnerability'],
    conclusion: 'SBOM analysis correlates declared dependencies against the NVD (National Vulnerability Database) and GitHub Security Advisories. Each component with version is matched against known CVE entries. Critical and high severity CVEs in direct dependencies require immediate patching.',
    reasoning: 'Software supply chain attacks exploit known vulnerabilities in dependencies. SBOMs enable automated scanning by providing a machine-readable inventory. CPE (Common Platform Enumeration) matching links components to NVD entries.',
    indicators: ['CycloneDX or SPDX format SBOM', 'Package name + version pairs', 'CPE URIs for each component', 'PURL (Package URL) identifiers', 'Dependency tree with transitive dependencies'],
    mitre_techniques: ['T1195.001 - Supply Chain Compromise: Compromise Software Dependencies', 'T1190 - Exploit Public-Facing Application'], severity_default: 'high',
    counter_measures: ['Automated CVE scanning in CI/CD (Snyk, Trivy, Grype)', 'Dependency pinning with lock files', 'Regular dependency updates', 'Vulnerability disclosure monitoring'],
  },
  {
    id: 'SBOM-002', detector: 'sbom', topic: 'License Compliance Analysis',
    keywords: ['GPL', 'MIT', 'Apache', 'LGPL', 'BSD', 'license compliance', 'copyleft', 'SPDX identifier'],
    conclusion: 'SBOM license analysis identifies licensing obligations for all dependencies. Copyleft licenses (GPL, AGPL) require source disclosure. Incompatible license combinations (e.g., GPL + proprietary) create legal risk. SPDX license identifiers provide standardized classification.',
    reasoning: 'Open source license compliance is a legal requirement. Failing to honor copyleft obligations can result in lawsuits (e.g., GPL enforcement by FSF/SFC). SBOM enables automated license auditing before release.',
    indicators: ['SPDX license identifiers in SBOM', 'License text files in dependency packages', 'Copyleft licenses in dependency tree', 'License incompatibility between components', 'Missing license information for components'],
    mitre_techniques: [], severity_default: 'medium',
    counter_measures: ['Automated license scanning (FOSSA, Black Duck, scancode-toolkit)', 'License allowlist/denylist policy', 'Legal review for copyleft dependencies', 'Replace copyleft deps with permissive alternatives'],
  },
  {
    id: 'SBOM-003', detector: 'sbom', topic: 'Supply Chain Integrity and Provenance',
    keywords: ['SLSA', 'provenance', 'supply chain', 'typosquatting', 'dependency confusion', 'reproducible build'],
    conclusion: 'SBOM provenance analysis verifies the integrity and authenticity of each dependency. SLSA (Supply-chain Levels for Software Artifacts) framework defines levels 1-4 of build provenance. Risks include typosquatting (similar package names), dependency confusion (private/public namespace), and compromised maintainer accounts.',
    reasoning: 'Supply chain attacks have grown exponentially (SolarWinds, CodeCov, ua-parser-js, event-stream). Provenance verification ensures packages were built from the expected source by the expected builder. SLSA L3+ requires hermetic, reproducible builds with signed provenance.',
    indicators: ['Sigstore/cosign signatures on packages', 'SLSA provenance attestations', 'Build reproducibility verification', 'Package name similarity analysis (typosquat detection)', 'Source-to-binary mapping verification'],
    mitre_techniques: ['T1195.001 - Supply Chain Compromise', 'T1195.002 - Compromise Software Supply Chain'], severity_default: 'critical',
    counter_measures: ['Require SLSA L2+ provenance for all dependencies', 'Use lock files with integrity hashes', 'Private registry with allow-listing', 'Reproducible builds with build provenance', 'Monitor for typosquatting on your package names'],
  },
  {
    id: 'SBOM-004', detector: 'sbom', topic: 'Outdated and Unmaintained Dependencies',
    keywords: ['outdated', 'unmaintained', 'abandoned', 'end of life', 'deprecated', 'last update'],
    conclusion: 'SBOM freshness analysis identifies dependencies that are outdated, unmaintained, or end-of-life. Packages with no updates in 2+ years, archived repositories, or explicit deprecation notices pose increasing security risk as new vulnerabilities will not be patched.',
    reasoning: 'Unmaintained dependencies accumulate unpatched vulnerabilities over time. They may also have compatibility issues with newer platforms. SBOM enables tracking of dependency freshness and maintainer activity.',
    indicators: ['Last published date > 24 months ago', 'GitHub repository archived flag', 'npm deprecation notice', 'No response to security issues', 'Declining download trends'],
    mitre_techniques: ['T1195 - Supply Chain Compromise'], severity_default: 'medium',
    counter_measures: ['Set maximum dependency age policy', 'Fork and maintain critical unmaintained deps', 'Replace with actively maintained alternatives', 'Regular dependency refresh cycles'],
  },
];

// ═══════════════════════════════════════════════════════════════
// DETECTOR IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════

const ALL_DETECTORS = [
  'anti_debugging', 'anti_tamper', 'obfuscation',
  'license_protection', 'drm', 'firmware_security', 'sbom',
];

function runAntiDebuggingDetection(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];
  const allText = buildSearchText(req);

  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'anti_debugging')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 0) {
      doctrines.push(d.id);
      for (const indicator of d.indicators) {
        const indicatorLower = indicator.toLowerCase();
        const indicatorKeywords = extractKeyTerms(indicatorLower);
        if (indicatorKeywords.some(ik => allText.toLowerCase().includes(ik))) {
          findings.push({
            id: `${d.id}-${findings.length}`,
            category: d.topic,
            description: indicator,
            evidence: `Matched keywords: ${matches.join(', ')}`,
            severity: d.severity_default,
            mitre_attack: d.mitre_techniques[0] || undefined,
          });
        }
      }
      if (findings.filter(f => f.category === d.topic).length === 0) {
        findings.push({
          id: `${d.id}-kw`,
          category: d.topic,
          description: d.conclusion,
          evidence: `Keyword matches: ${matches.join(', ')}`,
          severity: d.severity_default,
          mitre_attack: d.mitre_techniques[0] || undefined,
        });
      }
    }
  }

  // Pattern-based detection on disassembly/strings
  if (req.disassembly) {
    const asm = req.disassembly;
    if (/\brdtsc\b/i.test(asm)) {
      findings.push({ id: 'AD-RT-001', category: 'Timing Anti-Debug', description: 'RDTSC instruction detected — timing-based debugger detection', evidence: 'rdtsc in disassembly', severity: 'medium', mitre_attack: 'T1622' });
    }
    if (/\bint\s+2d\b/i.test(asm)) {
      findings.push({ id: 'AD-EX-001', category: 'Exception Anti-Debug', description: 'INT 2D instruction — exception-based anti-debugging', evidence: 'int 2d in disassembly', severity: 'medium', mitre_attack: 'T1622' });
    }
    if (/\bint\s+3\b/i.test(asm) || /\bcc\b.*breakpoint/i.test(asm)) {
      findings.push({ id: 'AD-EX-002', category: 'Exception Anti-Debug', description: 'INT 3 / software breakpoint instruction used for anti-debug', evidence: 'int 3 in disassembly', severity: 'low', mitre_attack: 'T1622' });
    }
  }

  if (req.imports) {
    const antiDbgApis = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
      'NtQuerySystemInformation', 'OutputDebugString', 'GetThreadContext', 'NtSetInformationThread'];
    for (const api of antiDbgApis) {
      if (req.imports.some(imp => imp.toLowerCase().includes(api.toLowerCase()))) {
        findings.push({ id: `AD-IMP-${api}`, category: 'Anti-Debug API Import', description: `Import of ${api} — known anti-debugging API`, evidence: `Found in import table`, severity: api.includes('Nt') ? 'high' : 'medium', mitre_attack: 'T1622' });
      }
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'anti_debugging',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.95, 0.3 + findings.length * 0.1),
    findings,
    summary: findings.length > 0
      ? `Detected ${findings.length} anti-debugging indicator(s). Techniques include: ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No anti-debugging techniques detected.',
    recommendations: findings.length > 0
      ? ['Use hardware breakpoints instead of software BPs', 'Employ ScyllaHide or TitanHide for transparent debugging', 'Hook timing APIs to return consistent values', 'Pass exceptions to application in debugger settings']
      : [],
    doctrines_applied: doctrines,
  };
}

function runAntiTamperDetection(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];
  const allText = buildSearchText(req);

  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'anti_tamper')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 0) {
      doctrines.push(d.id);
      findings.push({
        id: `${d.id}-match`,
        category: d.topic,
        description: d.conclusion,
        evidence: `Keywords: ${matches.join(', ')}`,
        severity: d.severity_default,
        mitre_attack: d.mitre_techniques[0] || undefined,
      });
    }
  }

  if (req.imports) {
    const tamperApis = ['WinVerifyTrust', 'CertGetCertificateChain', 'CryptVerifySignature', 'VirtualProtect'];
    for (const api of tamperApis) {
      if (req.imports.some(imp => imp.includes(api))) {
        findings.push({ id: `AT-IMP-${api}`, category: 'Anti-Tamper API', description: `Import of ${api} — used in code integrity or signing verification`, evidence: 'Import table', severity: 'high' });
      }
    }
  }

  if (req.sections) {
    for (const sec of req.sections) {
      if (sec.entropy > 7.5 && sec.name !== '.rsrc') {
        findings.push({ id: `AT-ENT-${sec.name}`, category: 'High Entropy Section', description: `Section ${sec.name} has entropy ${sec.entropy.toFixed(2)} — likely encrypted or compressed (packed/tamper-protected)`, evidence: `${sec.name}: entropy ${sec.entropy}`, severity: 'medium' });
      }
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'anti_tamper',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.95, 0.3 + findings.length * 0.12),
    findings,
    summary: findings.length > 0
      ? `Detected ${findings.length} anti-tamper indicator(s): ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No anti-tamper mechanisms detected.',
    recommendations: findings.length > 0
      ? ['Use hardware breakpoints to avoid code modification', 'Patch stored hash references if self-checking', 'Use syscall stubs to bypass IAT hooks', 'Verify signature chain before analysis']
      : [],
    doctrines_applied: doctrines,
  };
}

function runObfuscationAnalysis(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];
  const allText = buildSearchText(req);

  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'obfuscation')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 0) {
      doctrines.push(d.id);
      findings.push({
        id: `${d.id}-match`,
        category: d.topic,
        description: d.conclusion,
        evidence: `Keywords: ${matches.join(', ')}`,
        severity: d.severity_default,
        mitre_attack: d.mitre_techniques[0] || undefined,
      });
    }
  }

  // Section entropy analysis
  if (req.sections) {
    const codeSection = req.sections.find(s => s.name === '.text' || s.name === '.code' || s.name === 'CODE');
    if (codeSection && codeSection.entropy > 6.8) {
      findings.push({ id: 'OB-ENT-CODE', category: 'Code Section Entropy', description: `Code section ${codeSection.name} has high entropy (${codeSection.entropy.toFixed(2)}) — indicates packing, encryption, or heavy obfuscation`, evidence: `Entropy: ${codeSection.entropy}`, severity: codeSection.entropy > 7.5 ? 'critical' : 'high', mitre_attack: 'T1027.002' });
    }
    // Check for known packer sections
    const packerSections = ['.vmp', '.themida', '.upx', '.aspack', '.nsp', '.enigma'];
    for (const sec of req.sections) {
      if (packerSections.some(ps => sec.name.toLowerCase().startsWith(ps))) {
        findings.push({ id: `OB-PACK-${sec.name}`, category: 'Known Packer Section', description: `Section "${sec.name}" matches known packer/protector signature`, evidence: sec.name, severity: 'critical', mitre_attack: 'T1027.002' });
      }
    }
  }

  // String analysis for obfuscation indicators
  if (req.strings) {
    const readableCount = req.strings.filter(s => /^[\x20-\x7e]{4,}$/.test(s)).length;
    const ratio = readableCount / Math.max(1, req.strings.length);
    if (ratio < 0.3 && req.strings.length > 50) {
      findings.push({ id: 'OB-STR-LOW', category: 'String Encryption', description: `Only ${(ratio * 100).toFixed(1)}% of strings are readable — likely string encryption active`, evidence: `${readableCount}/${req.strings.length} readable`, severity: 'medium', mitre_attack: 'T1027.013' });
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'obfuscation',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.95, 0.3 + findings.length * 0.1),
    findings,
    summary: findings.length > 0
      ? `Detected ${findings.length} obfuscation indicator(s): ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No code obfuscation detected.',
    recommendations: findings.length > 0
      ? ['Use symbolic execution for CFF recovery', 'Apply FLOSS for encrypted string extraction', 'Use trace-based analysis for VM-protected code', 'Check for known packer unpacking tools']
      : [],
    doctrines_applied: doctrines,
  };
}

function runLicenseProtectionAnalysis(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];
  const allText = buildSearchText(req);

  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'license_protection')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 0) {
      doctrines.push(d.id);
      findings.push({
        id: `${d.id}-match`, category: d.topic, description: d.conclusion,
        evidence: `Keywords: ${matches.join(', ')}`, severity: d.severity_default,
        mitre_attack: d.mitre_techniques[0] || undefined,
      });
    }
  }

  if (req.strings) {
    const licStrings = req.strings.filter(s =>
      /licen[sc]e|serial|registr|activat|trial|evaluat|expire|subscription|hardware.?id/i.test(s)
    );
    if (licStrings.length > 3) {
      findings.push({ id: 'LP-STR-001', category: 'License Strings', description: `Found ${licStrings.length} license-related strings indicating protection scheme`, evidence: licStrings.slice(0, 5).join('; '), severity: 'medium' });
    }
  }

  if (req.imports) {
    const hwApis = ['GetVolumeInformation', 'GetAdaptersInfo', 'GetAdaptersAddresses', '__cpuid'];
    for (const api of hwApis) {
      if (req.imports.some(imp => imp.includes(api))) {
        findings.push({ id: `LP-HW-${api}`, category: 'Hardware Fingerprinting', description: `Import of ${api} — used for hardware ID generation in license binding`, evidence: 'Import table', severity: 'medium', mitre_attack: 'T1082' });
      }
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'license_protection',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.90, 0.25 + findings.length * 0.1),
    findings,
    summary: findings.length > 0
      ? `Detected ${findings.length} license protection indicator(s): ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No license protection mechanisms detected.',
    recommendations: findings.length > 0
      ? ['Analyze key validation algorithm for keygen potential', 'Check for online activation bypass via DNS redirect', 'Look for hardware fingerprint in license file/registry', 'Trace trial date storage location']
      : [],
    doctrines_applied: doctrines,
  };
}

function runDrmAnalysis(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];
  const allText = buildSearchText(req);

  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'drm')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 0) {
      doctrines.push(d.id);
      findings.push({
        id: `${d.id}-match`, category: d.topic, description: d.conclusion,
        evidence: `Keywords: ${matches.join(', ')}`, severity: d.severity_default,
        mitre_attack: d.mitre_techniques[0] || undefined,
      });
    }
  }

  // Check for known DRM libraries in imports/strings
  if (req.imports || req.strings) {
    const drmLibs = ['widevinecdm', 'libwidevine', 'FairPlayStreaming', 'PlayReadyCDM',
      'denuvo', 'EasyAntiCheat', 'BEClient', 'BEService', 'BEDaisy'];
    const searchIn = [...(req.imports || []), ...(req.strings || [])];
    for (const lib of drmLibs) {
      if (searchIn.some(s => s.toLowerCase().includes(lib.toLowerCase()))) {
        findings.push({ id: `DRM-LIB-${lib}`, category: 'DRM Library', description: `Known DRM/anti-cheat library detected: ${lib}`, evidence: `Found in binary`, severity: 'critical', mitre_attack: 'T1027.002' });
      }
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'drm',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.95, 0.3 + findings.length * 0.15),
    findings,
    summary: findings.length > 0
      ? `Detected ${findings.length} DRM indicator(s): ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No DRM mechanisms detected.',
    recommendations: findings.length > 0
      ? ['Identify DRM system and version', 'Check for L3 vs L1 CDM (L3 is software-only, weaker)', 'Look for key material in process memory during playback', 'Check for anti-cheat kernel driver bypass potential']
      : [],
    doctrines_applied: doctrines,
  };
}

function runFirmwareSecurityAnalysis(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];
  const allText = buildSearchText(req);

  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'firmware_security')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 0) {
      doctrines.push(d.id);
      findings.push({
        id: `${d.id}-match`, category: d.topic, description: d.conclusion,
        evidence: `Keywords: ${matches.join(', ')}`, severity: d.severity_default,
        mitre_attack: d.mitre_techniques[0] || undefined,
      });
    }
  }

  // Check for hardcoded credentials in strings
  if (req.strings) {
    const credPatterns = [
      /password\s*[:=]\s*\S+/i, /passwd\s*[:=]\s*\S+/i,
      /BEGIN\s+(RSA|EC|DSA|PRIVATE)\s+KEY/i,
      /api[_-]?key\s*[:=]\s*\S{10,}/i,
      /secret[_-]?key\s*[:=]\s*\S{10,}/i,
    ];
    for (const s of req.strings) {
      for (const pat of credPatterns) {
        if (pat.test(s)) {
          findings.push({
            id: `FW-CRED-${findings.length}`, category: 'Hardcoded Credential',
            description: 'Potential hardcoded credential found in firmware strings',
            evidence: s.substring(0, 80) + (s.length > 80 ? '...' : ''),
            severity: 'critical', cwe: 'CWE-798', mitre_attack: 'T1552.001',
          });
          break;
        }
      }
    }
  }

  // Check for common firmware binaries
  if (req.strings) {
    const fwIndicators = ['u-boot', 'busybox', 'dropbear', 'uClibc', 'OpenWrt', 'buildroot', 'yocto'];
    for (const fw of fwIndicators) {
      if (req.strings.some(s => s.toLowerCase().includes(fw.toLowerCase()))) {
        findings.push({ id: `FW-OS-${fw}`, category: 'Firmware Framework', description: `Firmware uses ${fw} — known embedded Linux framework`, evidence: fw, severity: 'info' });
      }
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'firmware_security',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.90, 0.25 + findings.length * 0.1),
    findings,
    summary: findings.length > 0
      ? `Detected ${findings.length} firmware security indicator(s): ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No firmware security issues detected.',
    recommendations: findings.length > 0
      ? ['Verify secure boot chain is complete (ROM → SPL → bootloader → kernel)', 'Check for exposed debug interfaces (JTAG/UART/SWD)', 'Ensure firmware updates are cryptographically signed', 'Remove all hardcoded credentials']
      : [],
    doctrines_applied: doctrines,
  };
}

function runSbomAnalysis(req: AnalysisRequest): DetectionResult {
  const findings: Finding[] = [];
  const doctrines: string[] = [];

  // Parse SBOM if provided
  if (req.sbom_json) {
    doctrines.push('SBOM-001', 'SBOM-002', 'SBOM-003', 'SBOM-004');
    const components = extractSbomComponents(req.sbom_json);
    let criticalCount = 0;
    let copyleftCount = 0;
    let outdatedCount = 0;

    for (const comp of components) {
      // CVE-like pattern detection (simulated — real implementation would query NVD API)
      if (comp.version && isKnownVulnerableVersion(comp.name, comp.version)) {
        criticalCount++;
        findings.push({
          id: `SBOM-CVE-${comp.name}`, category: 'Known Vulnerable Component',
          description: `${comp.name}@${comp.version} has known vulnerabilities`,
          evidence: `${comp.name} ${comp.version}`, severity: 'high',
          cwe: 'CWE-1395', mitre_attack: 'T1195.001',
        });
      }
      // License compliance
      if (comp.license && /GPL|AGPL|LGPL|SSPL/i.test(comp.license) && !/LGPL/i.test(comp.license)) {
        copyleftCount++;
        findings.push({
          id: `SBOM-LIC-${comp.name}`, category: 'Copyleft License',
          description: `${comp.name} uses ${comp.license} — copyleft obligations apply`,
          evidence: `License: ${comp.license}`, severity: 'medium',
        });
      }
    }

    findings.push({
      id: 'SBOM-SUMMARY', category: 'SBOM Summary',
      description: `Analyzed ${components.length} components: ${criticalCount} with known vulnerabilities, ${copyleftCount} with copyleft licenses`,
      evidence: `Total components: ${components.length}`, severity: criticalCount > 0 ? 'high' : 'info',
    });
  }

  // Parse package manifest if provided
  if (req.manifest && req.manifest_type) {
    doctrines.push('SBOM-001', 'SBOM-004');
    const deps = parseManifestDependencies(req.manifest, req.manifest_type);
    findings.push({
      id: 'SBOM-MANIFEST', category: 'Manifest Analysis',
      description: `Parsed ${deps.length} dependencies from ${req.manifest_type}`,
      evidence: deps.slice(0, 10).map(d => `${d.name}@${d.version}`).join(', '),
      severity: 'info',
    });

    for (const dep of deps) {
      if (isKnownVulnerableVersion(dep.name, dep.version)) {
        findings.push({
          id: `SBOM-DEP-${dep.name}`, category: 'Vulnerable Dependency',
          description: `${dep.name}@${dep.version} — known vulnerable version`,
          evidence: `${dep.name} ${dep.version}`, severity: 'high', mitre_attack: 'T1195.001',
        });
      }
    }
  }

  // Keyword-based detection from strings/text
  const allText = buildSearchText(req);
  for (const d of DOCTRINE_CACHE.filter(d => d.detector === 'sbom')) {
    const matches = d.keywords.filter(kw => allText.toLowerCase().includes(kw.toLowerCase()));
    if (matches.length > 1) {
      doctrines.push(d.id);
    }
  }

  const score = computeSeverityScore(findings);
  return {
    detector: 'sbom',
    severity: scoreToSeverity(score),
    confidence: Math.min(0.90, 0.2 + findings.length * 0.08),
    findings,
    summary: findings.length > 0
      ? `SBOM analysis found ${findings.length} item(s): ${[...new Set(findings.map(f => f.category))].join(', ')}.`
      : 'No SBOM data provided or no issues found. Submit sbom_json (CycloneDX/SPDX) or manifest for analysis.',
    recommendations: findings.length > 0
      ? ['Update vulnerable dependencies immediately', 'Review copyleft license obligations', 'Implement automated SBOM scanning in CI/CD', 'Verify dependency provenance and integrity']
      : ['Generate SBOM with syft, cyclonedx-cli, or spdx-sbom-generator', 'Scan with grype, trivy, or snyk'],
    doctrines_applied: [...new Set(doctrines)],
  };
}

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

function buildSearchText(req: AnalysisRequest): string {
  const parts: string[] = [];
  if (req.query) parts.push(req.query);
  if (req.disassembly) parts.push(req.disassembly);
  if (req.strings) parts.push(req.strings.join(' '));
  if (req.imports) parts.push(req.imports.join(' '));
  if (req.exports) parts.push(req.exports.join(' '));
  if (req.filename) parts.push(req.filename);
  if (req.file_type) parts.push(req.file_type);
  if (req.manifest) parts.push(req.manifest);
  return parts.join(' ');
}

function extractKeyTerms(text: string): string[] {
  return text.split(/[^a-z0-9_]+/).filter(t => t.length > 3);
}

function computeSeverityScore(findings: Finding[]): number {
  const weights: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 2, info: 0 };
  return findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0);
}

function scoreToSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (score >= 20) return 'critical';
  if (score >= 12) return 'high';
  if (score >= 6) return 'medium';
  if (score >= 2) return 'low';
  return 'info';
}

interface SbomComponent { name: string; version: string; license?: string; }

function extractSbomComponents(sbom: Record<string, unknown>): SbomComponent[] {
  const components: SbomComponent[] = [];
  // CycloneDX format
  if (Array.isArray((sbom as Record<string, unknown[]>).components)) {
    for (const c of (sbom as Record<string, { name: string; version: string; licenses?: { license?: { id?: string } }[] }[]>).components) {
      components.push({
        name: c.name || 'unknown',
        version: c.version || '*',
        license: c.licenses?.[0]?.license?.id,
      });
    }
  }
  // SPDX format
  if (Array.isArray((sbom as Record<string, unknown[]>).packages)) {
    for (const p of (sbom as Record<string, { name: string; versionInfo: string; licenseConcluded?: string }[]>).packages) {
      components.push({
        name: p.name || 'unknown',
        version: p.versionInfo || '*',
        license: p.licenseConcluded,
      });
    }
  }
  return components;
}

function parseManifestDependencies(manifest: string, type: string): { name: string; version: string }[] {
  const deps: { name: string; version: string }[] = [];
  try {
    if (type === 'package.json') {
      const pkg = JSON.parse(manifest);
      for (const [name, ver] of Object.entries(pkg.dependencies || {})) deps.push({ name, version: String(ver) });
      for (const [name, ver] of Object.entries(pkg.devDependencies || {})) deps.push({ name, version: String(ver) });
    } else if (type === 'requirements.txt') {
      for (const line of manifest.split('\n')) {
        const m = line.trim().match(/^([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*(.+)$/);
        if (m) deps.push({ name: m[1], version: m[2] });
      }
    } else if (type === 'Cargo.toml') {
      const depSection = manifest.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
      if (depSection) {
        for (const line of depSection[1].split('\n')) {
          const m = line.match(/^(\S+)\s*=\s*"([^"]+)"/);
          if (m) deps.push({ name: m[1], version: m[2] });
        }
      }
    }
  } catch { /* parse errors are non-fatal */ }
  return deps;
}

/** Known vulnerable versions — curated list of commonly exploited packages */
function isKnownVulnerableVersion(name: string, version: string): boolean {
  const vulnDb: Record<string, string[]> = {
    'log4j-core': ['2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9', '2.10', '2.11', '2.12', '2.13', '2.14', '2.15', '2.16'],
    'lodash': ['4.17.0', '4.17.1', '4.17.2', '4.17.3', '4.17.4', '4.17.5', '4.17.9', '4.17.10', '4.17.11', '4.17.15', '4.17.19', '4.17.20'],
    'minimist': ['0.0.1', '0.0.2', '0.0.3', '0.0.4', '0.0.5', '0.0.6', '0.0.7', '0.0.8', '0.0.9', '0.0.10', '0.1.0', '1.2.0', '1.2.1', '1.2.2', '1.2.3', '1.2.4', '1.2.5'],
    'express': ['4.17.0', '4.17.1', '3.0.0'],
    'ua-parser-js': ['0.7.29'],
    'event-stream': ['3.3.6'],
    'node-ipc': ['10.1.1', '10.1.2', '10.1.3'],
    'colors': ['1.4.1', '1.4.2'],
    'faker': ['6.6.6'],
    'requests': ['2.19.0', '2.19.1', '2.20.0'],
    'django': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '2.0', '2.1', '2.2'],
    'openssl': ['1.0.1', '1.0.1a', '1.0.1b', '1.0.1c', '1.0.1d', '1.0.1e', '1.0.1f'],
    'spring-core': ['5.3.0', '5.3.1', '5.3.2', '5.3.3', '5.3.4', '5.3.5', '5.3.6', '5.3.7', '5.3.8', '5.3.9', '5.3.10', '5.3.11', '5.3.12', '5.3.13', '5.3.14', '5.3.15', '5.3.16', '5.3.17'],
    'struts2-core': ['2.3.0', '2.3.1', '2.5.0', '2.5.1', '2.5.2', '2.5.10', '2.5.12'],
    'jackson-databind': ['2.9.0', '2.9.1', '2.9.2', '2.9.3', '2.9.4', '2.9.5', '2.9.6', '2.9.7', '2.9.8', '2.9.9', '2.9.10'],
  };
  const cleanVer = version.replace(/[^0-9.]/g, '');
  const entries = vulnDb[name.toLowerCase()];
  return entries ? entries.some(v => cleanVer.startsWith(v)) : false;
}

function generateAnalysisId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `RD-${ts}-${rand}`;
}

function computeOverallRisk(results: DetectionResult[]): { risk: string; score: number } {
  let totalScore = 0;
  const weights: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
  for (const r of results) {
    totalScore += weights[r.severity] || 0;
    totalScore += r.findings.length * 2;
  }
  let risk = 'minimal';
  if (totalScore >= 80) risk = 'critical';
  else if (totalScore >= 50) risk = 'high';
  else if (totalScore >= 25) risk = 'elevated';
  else if (totalScore >= 10) risk = 'moderate';
  else if (totalScore >= 3) risk = 'low';
  return { risk, score: Math.min(100, totalScore) };
}

// ═══════════════════════════════════════════════════════════════
// HONO APP — ROUTES
// ═══════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors({
  origin: ['https://echo-ept.com', 'https://echo-op.com', 'http://localhost:3000'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Echo-API-Key'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
}));

// Auth middleware for protected routes
function requireAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }): boolean {
  const key = c.req.header('X-Echo-API-Key');
  return key === c.env.ECHO_API_KEY;
}

// ─── Health ───
app.get("/", (c) => c.json({ service: 'echo-reveng-defense', status: 'operational' }));

app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    worker: 'echo-reveng-defense',
    version: c.env.WORKER_VERSION,
    timestamp: new Date().toISOString(),
    capabilities: ALL_DETECTORS,
    doctrine_count: DOCTRINE_CACHE.length,
    uptime: 'persistent',
  });
});

// ─── Stats ───
app.get('/stats', async (c) => {
  try {
    const total = await c.env.DB.prepare('SELECT COUNT(*) as count FROM analyses').first<{ count: number }>();
    const bySeverity = await c.env.DB.prepare(
      'SELECT overall_risk, COUNT(*) as count FROM analyses GROUP BY overall_risk'
    ).all();
    const recent = await c.env.DB.prepare(
      'SELECT analysis_id, filename, overall_risk, overall_score, created_at FROM analyses ORDER BY created_at DESC LIMIT 10'
    ).all();
    return c.json({
      ok: true,
      total_analyses: total?.count || 0,
      by_severity: bySeverity.results,
      recent: recent.results,
    });
  } catch (e) {
    return c.json({ ok: true, total_analyses: 0, by_severity: [], recent: [], note: 'DB may need initialization' });
  }
});

// ─── Doctrines ───
app.get('/doctrines', (c) => {
  const detector = new URL(c.req.url).searchParams.get('detector');
  const filtered = detector
    ? DOCTRINE_CACHE.filter(d => d.detector === detector)
    : DOCTRINE_CACHE;
  return c.json({
    ok: true,
    count: filtered.length,
    detectors: ALL_DETECTORS,
    doctrines: filtered.map(d => ({
      id: d.id, detector: d.detector, topic: d.topic,
      keywords: d.keywords, severity: d.severity_default,
      mitre: d.mitre_techniques,
    })),
  });
});

// ─── Main Analysis Endpoint ───
app.post('/analyze', async (c) => {
  if (!requireAuth(c)) {
    return c.json({ ok: false, error: 'Unauthorized. Provide X-Echo-API-Key header.' }, 401);
  }

  const startTime = Date.now();
  let body: AnalysisRequest;
  try {
    body = await c.req.json<AnalysisRequest>();
  } catch {
    return c.json({ ok: false, error: 'Invalid JSON body' }, 400);
  }

  const detectorsToRun = body.detectors && body.detectors.length > 0
    ? body.detectors.filter(d => ALL_DETECTORS.includes(d))
    : ALL_DETECTORS;

  if (detectorsToRun.length === 0) {
    return c.json({ ok: false, error: `Invalid detectors. Available: ${ALL_DETECTORS.join(', ')}` }, 400);
  }

  log('info', 'Analysis requested', {
    filename: body.filename || 'unknown',
    detectors: detectorsToRun,
    has_disassembly: !!body.disassembly,
    has_strings: !!(body.strings && body.strings.length),
    has_imports: !!(body.imports && body.imports.length),
    has_sbom: !!body.sbom_json,
    has_manifest: !!body.manifest,
  });

  const results: DetectionResult[] = [];
  const detectorFns: Record<string, (req: AnalysisRequest) => DetectionResult> = {
    anti_debugging: runAntiDebuggingDetection,
    anti_tamper: runAntiTamperDetection,
    obfuscation: runObfuscationAnalysis,
    license_protection: runLicenseProtectionAnalysis,
    drm: runDrmAnalysis,
    firmware_security: runFirmwareSecurityAnalysis,
    sbom: runSbomAnalysis,
  };

  for (const det of detectorsToRun) {
    const fn = detectorFns[det];
    if (fn) {
      try {
        results.push(fn(body));
      } catch (e) {
        log('error', `Detector ${det} failed`, { error: (e as Error).message });
        results.push({
          detector: det, severity: 'info', confidence: 0, findings: [],
          summary: `Detector error: ${(e as Error).message}`,
          recommendations: [], doctrines_applied: [],
        });
      }
    }
  }

  const { risk, score } = computeOverallRisk(results);
  const analysisId = generateAnalysisId();

  // AI-enhanced summary via Echo Chat
  let aiSummary: string | undefined;
  try {
    const totalFindings = results.reduce((s, r) => s + r.findings.length, 0);
    if (totalFindings > 0) {
      const summaryPrompt = `You are a reverse engineering security analyst. Summarize these findings concisely:\n\nFile: ${body.filename || 'unknown'}\nOverall Risk: ${risk} (${score}/100)\nDetectors: ${detectorsToRun.join(', ')}\n\nFindings:\n${results.filter(r => r.findings.length > 0).map(r => `[${r.detector}] ${r.summary}`).join('\n')}\n\nProvide a 2-3 sentence executive summary and the single most important recommendation.`;

      const chatResp = await c.env.ECHO_CHAT.fetch('https://chat/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY || '' },
        body: JSON.stringify({
          message: summaryPrompt,
          user_id: 'reveng-defense',
          site_id: 'reveng-defense',
          personality: 'prometheus',
          system_prompt: 'You are Prometheus, the security analysis AI. Be concise, technical, and actionable.',
        }),
      });
      const chatData = await chatResp.json() as Record<string, unknown>;
      if (chatData.response) aiSummary = chatData.response as string;
    }
  } catch (e) {
    log('warn', 'AI summary failed', { error: (e as Error).message });
  }

  const latencyMs = Date.now() - startTime;

  const response: AnalysisResponse = {
    analysis_id: analysisId,
    filename: body.filename || 'unknown',
    file_type: body.file_type || 'unknown',
    timestamp: new Date().toISOString(),
    detectors_run: detectorsToRun,
    results,
    overall_risk: risk,
    overall_score: score,
    ai_summary: aiSummary,
  };

  // Store in D1
  try {
    await c.env.DB.prepare(`
      INSERT INTO analyses (analysis_id, filename, file_type, detectors_run, overall_risk, overall_score, total_findings, ai_summary, latency_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      analysisId, body.filename || 'unknown', body.file_type || 'unknown',
      detectorsToRun.join(','), risk, score,
      results.reduce((s, r) => s + r.findings.length, 0),
      aiSummary || null, latencyMs, new Date().toISOString()
    ).run();

    // Store individual findings
    for (const r of results) {
      for (const f of r.findings) {
        await c.env.DB.prepare(`
          INSERT INTO findings (analysis_id, detector, finding_id, category, description, evidence, severity, mitre_attack, cwe, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(analysisId, r.detector, f.id, f.category, f.description, f.evidence, f.severity, f.mitre_attack || null, f.cwe || null, new Date().toISOString()).run();
      }
    }
  } catch (e) {
    log('error', 'D1 storage failed', { error: (e as Error).message });
  }

  // Cache result in KV
  try {
    await c.env.CACHE.put(`analysis:${analysisId}`, JSON.stringify(response), { expirationTtl: 86400 * 30 });
  } catch (e) {
    log('warn', 'KV cache failed', { error: (e as Error).message });
  }

  // Ingest to Shared Brain for cross-instance recall
  const totalFindings = results.reduce((s, r) => s + r.findings.length, 0);
  if (totalFindings > 0) {
    try {
      await c.env.SHARED_BRAIN.fetch('https://brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'echo-reveng-defense',
          role: 'assistant',
          content: `REVENG ANALYSIS: ${body.filename || 'unknown'} — Risk: ${risk} (${score}/100), ${totalFindings} findings across ${detectorsToRun.join(',')}. ${aiSummary || ''}`,
          importance: score >= 50 ? 8 : 5,
          tags: ['reveng', 'security', risk],
        }),
      });
    } catch (e) {
      log('warn', 'Shared Brain ingest failed', { error: (e as Error).message });
    }
  }

  log('info', 'Analysis complete', { analysis_id: analysisId, risk, score, findings: totalFindings, latency_ms: latencyMs });

  return c.json({ ok: true, ...response, latency_ms: latencyMs });
});

// ─── Get Analysis by ID ───
app.get('/analysis/:id', async (c) => {
  const id = c.req.param('id');

  // Check KV cache first
  const cached = await c.env.CACHE.get(`analysis:${id}`, 'json');
  if (cached) return c.json({ ok: true, source: 'cache', ...(cached as Record<string, unknown>) });

  // Fall back to D1
  try {
    const row = await c.env.DB.prepare('SELECT * FROM analyses WHERE analysis_id = ?').bind(id).first();
    if (!row) return c.json({ ok: false, error: 'Analysis not found' }, 404);

    const findings = await c.env.DB.prepare('SELECT * FROM findings WHERE analysis_id = ?').bind(id).all();
    return c.json({ ok: true, source: 'database', analysis: row, findings: findings.results });
  } catch {
    return c.json({ ok: false, error: 'Database error' }, 500);
  }
});

// ─── Natural Language Query ───
app.post('/query', async (c) => {
  if (!requireAuth(c)) return c.json({ ok: false, error: 'Unauthorized' }, 401);

  const { query } = await c.req.json<{ query: string }>();
  if (!query) return c.json({ ok: false, error: 'Missing query field' }, 400);

  // Search doctrines
  const queryLower = query.toLowerCase();
  const matchedDoctrines = DOCTRINE_CACHE.filter(d =>
    d.keywords.some(kw => queryLower.includes(kw.toLowerCase())) ||
    d.topic.toLowerCase().includes(queryLower) ||
    d.conclusion.toLowerCase().includes(queryLower.substring(0, 50))
  ).slice(0, 5);

  // AI-enhanced response
  let aiResponse = '';
  try {
    const context = matchedDoctrines.map(d =>
      `[${d.id}] ${d.topic}: ${d.conclusion}\nIndicators: ${d.indicators.join('; ')}\nCountermeasures: ${d.counter_measures.join('; ')}`
    ).join('\n\n');

    const chatResp = await c.env.ECHO_CHAT.fetch('https://chat/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY || '' },
      body: JSON.stringify({
        message: `Based on this reverse engineering knowledge, answer: ${query}\n\nContext:\n${context}`,
        user_id: 'reveng-defense',
        site_id: 'reveng-defense',
        personality: 'prometheus',
        system_prompt: 'You are an expert reverse engineer and security researcher. Answer technical questions about binary analysis, anti-debugging, anti-tamper, obfuscation, DRM, firmware security, and SBOM analysis. Be precise and cite specific techniques.',
      }),
    });
    const data = await chatResp.json() as Record<string, unknown>;
    aiResponse = (data.response as string) || '';
  } catch (e) {
    log('warn', 'AI query failed', { error: (e as Error).message });
  }

  return c.json({
    ok: true,
    query,
    matched_doctrines: matchedDoctrines.map(d => ({ id: d.id, topic: d.topic, detector: d.detector, conclusion: d.conclusion })),
    ai_response: aiResponse,
  });
});

// ─── Ingest Doctrines to Engine Runtime ───
app.post('/ingest-doctrines', async (c) => {
  if (!requireAuth(c)) return c.json({ ok: false, error: 'Unauthorized' }, 401);

  let ingested = 0;
  const errors: string[] = [];

  for (const d of DOCTRINE_CACHE) {
    try {
      await c.env.ENGINE_RUNTIME.fetch('https://engine/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': c.env.ECHO_API_KEY || '' },
        body: JSON.stringify({
          engine_id: 'DEF10',
          engine_name: 'Reverse Engineering Defense Detection Engine',
          category: 'REVENG',
          domain: 'security',
          topic: d.topic,
          keywords: d.keywords,
          conclusion: d.conclusion,
          reasoning: d.reasoning,
          confidence: 'DEFENSIBLE',
          authority_level: 10,
        }),
      });
      ingested++;
    } catch (e) {
      errors.push(`${d.id}: ${(e as Error).message}`);
    }
  }

  log('info', 'Doctrine ingestion complete', { ingested, errors: errors.length });
  return c.json({ ok: true, ingested, total: DOCTRINE_CACHE.length, errors: errors.length > 0 ? errors : undefined });
});

// ─── Cron: Periodic Stats Summary ───
app.get('/cron', async (c) => {
  try {
    const stats = await c.env.DB.prepare(
      'SELECT overall_risk, COUNT(*) as count FROM analyses WHERE created_at > datetime("now", "-12 hours") GROUP BY overall_risk'
    ).all();

    if (stats.results.length > 0) {
      const summary = stats.results.map((r: Record<string, unknown>) => `${r.overall_risk}: ${r.count}`).join(', ');
      await c.env.SHARED_BRAIN.fetch('https://brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'echo-reveng-defense',
          role: 'assistant',
          content: `REVENG DEFENSE 12h REPORT: ${summary}`,
          importance: 5,
          tags: ['reveng', 'report', 'cron'],
        }),
      });
    }
  } catch (e) {
    log('error', 'Cron failed', { error: (e as Error).message });
  }
  return c.json({ ok: true });
});

// ─── 404 Handler ───
app.notFound((c) => {
  return c.json({
    ok: false,
    error: 'Not Found',
    endpoints: [
      'GET  /health',
      'GET  /stats',
      'GET  /doctrines',
      'POST /analyze         (auth)',
      'GET  /analysis/:id',
      'POST /query           (auth)',
      'POST /ingest-doctrines (auth)',
    ],
  }, 404);
});

// ─── Error Handler ───
app.onError((err, c) => {
  log('error', 'Unhandled error', { error: err.message, stack: err.stack });
  return c.json({ ok: false, error: 'Internal server error' }, 500);
});

// ═══════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    log('info', 'Cron triggered', { cron: event.cron });
    ctx.waitUntil(
      app.fetch(new Request('https://worker/cron'), env as unknown as RequestInit)
        .catch(e => log('error', 'Cron fetch failed', { error: (e as Error).message }))
    );
  },
};
