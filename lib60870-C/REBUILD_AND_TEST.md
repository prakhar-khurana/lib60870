# Quick Rebuild and Test Guide

## Rebuild the Project

### Option 1: Using CMake (Recommended)
```powershell
cd c:\Users\z005653n\Desktop\lib60870\lib60870-C
cmake --build build --config Debug --clean-first
```

### Option 2: Using Visual Studio Solution
Open the solution file and rebuild:
```powershell
cd c:\Users\z005653n\Desktop\lib60870\lib60870-C
# Open lib60870-C.sln in Visual Studio and rebuild
```

### Option 3: Using MSBuild
```powershell
cd c:\Users\z005653n\Desktop\lib60870\lib60870-C
msbuild lib60870-C.sln /p:Configuration=Debug /t:Rebuild
```

## Run All Tests
```powershell
cd c:\Users\z005653n\Desktop\lib60870\lib60870-C
.\tests\Debug\tests.exe
```

## Run Specific A-Profile Test
```powershell
cd c:\Users\z005653n\Desktop\lib60870\lib60870-C
.\tests\Debug\tests.exe test_AProfile_KeyExchangeAndDataEncryption
```

## Expected Output

You should see detailed debug output showing the complete key exchange flow:

```
=== IEC 62351-5 A-Profile Security Test ===
Testing: Key Exchange, Encryption, Decryption, and Replay Protection

✓ Server started successfully
✓ Client configured with A-Profile security

--- Phase 1: ECDH Key Exchange ---
✓ TCP connection established
✓ STARTDT sent - initiating key exchange
Waiting for ECDH key exchange to complete...
APROFILE: Received security ASDU (S_RP_NA_1), elements=1
APROFILE: Element 0: spk=<address>, addr=65535
APROFILE: Extracted peer key: len=65
APROFILE: Key pair generated successfully
APROFILE: Server preparing to send public key response
APROFILE: Server sent public key response (result=1)
APROFILE: Now reading peer's public key (peer_key=<address>, peer_key_len=65)
APROFILE: Peer public key read successfully
APROFILE: Computing shared secret...
APROFILE: Shared secret computed successfully
APROFILE: Shared secret length: 32 bytes
APROFILE: Shared secret exported successfully
APROFILE: Deriving session key using HKDF...
APROFILE: Session key derived successfully
APROFILE: Setting up GCM encryption contexts...
APROFILE: Key exchange complete, security is active
✓ Key exchange phase completed
```

## Troubleshooting

### If build fails:
1. Check that all source files are present
2. Verify mbedtls library is available in dependencies/
3. Check CMakeLists.txt or project configuration

### If test hangs:
1. Look for the last debug message printed
2. Check if error message appears (with -0x#### error code)
3. Verify network ports are available (2404)

### If test fails with assertion:
1. Read the assertion message carefully
2. Check if key exchange completed successfully
3. Verify encrypted communication is working

## Summary of Changes

The fix adds comprehensive debug logging to `aprofile.c` to trace the complete key exchange process. Every critical step now has:
- Entry logging (what operation is about to happen)
- Error logging with fflush (if operation fails)
- Success logging (if operation succeeds)

This ensures complete visibility into the key exchange process and helps identify any failures immediately.
