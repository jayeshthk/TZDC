# TZDC API Documentation & Best Practices

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [API Reference](#api-reference)
3. [Best Practices](#best-practices)
4. [Security Guidelines](#security-guidelines)
5. [Performance Optimization](#performance-optimization)
6. [Troubleshooting](#troubleshooting)

---

## Core Concepts

### Temporal Encryption

**What**: Encryption keys that automatically expire after a configurable time window.

**Why**: Ensures stolen encrypted data becomes permanently inaccessible once keys expire, even if the attacker eventually gains system access.

**How**: Keys are derived deterministically using HKDF with time-slot identifiers. Once a time slot expires, the key cannot be regenerated.

```python
from tzdc import TZDCClient, TimeWindow

# Keys expire after 1 hour
client = TZDCClient(time_window=TimeWindow.HOUR_1)

# Encrypt data
ciphertext, nonce, key = client.encrypt_with_temporal_key(data)

# After 1 hour: decryption permanently fails
# Even with the master secret, expired keys cannot decrypt old data
```

### Cryptographic Sharding (Shamir's Secret Sharing)

**What**: Data is split into N shards where any K shards can reconstruct the original, but K-1 shards reveal nothing.

**Why**: Eliminates single point of failure. Attacker must compromise K different locations to access data.

**How**: Uses polynomial interpolation over finite fields. The secret is encoded as the constant term of a random polynomial.

```python
# Create 5 shards, any 3 can reconstruct
shards = client.encrypt_and_shard(
    data=sensitive_data,
    resource_id="resource_001",
    total_shards=5,
    threshold=3
)

# Store shards in different locations
# Attacker needs to compromise 3 locations (not just 1)
```

### Zero-Knowledge Proofs

**What**: Cryptographic methods to prove statements about data without revealing the data itself.

**Why**: Enables verification, auditing, and compliance without exposing sensitive information.

**How**: Uses hash commitments and mathematical proofs to verify properties.

```python
# Prove salary > $100,000 without revealing exact amount
commitment, proof = client.zk_prover.prove_range(
    value=125000,
    min_value=100000,
    max_value=1000000
)

# Verifier confirms salary is in range without learning exact value
is_valid = client.zk_prover.verify_range_proof(commitment, 125000, proof)
```

---

## API Reference

### TZDCClient

Main client interface for all TZDC operations.

#### Constructor

```python
TZDCClient(
    master_secret: Optional[bytes] = None,
    time_window: Union[TimeWindow, int] = TimeWindow.HOUR_1,
    storage_adapter: Optional[StorageAdapter] = None,
    cipher_type: CipherType = CipherType.AES_256_GCM,
    enable_audit_log: bool = True,
    audit_log_path: Optional[Path] = None
)
```

**Parameters**:

- `master_secret`: 32-byte master secret for key derivation (auto-generated if None)
- `time_window`: Key expiration window (TimeWindow enum or seconds as int)
- `storage_adapter`: Backend storage (defaults to local filesystem)
- `cipher_type`: Encryption algorithm (AES_256_GCM or CHACHA20_POLY1305)
- `enable_audit_log`: Whether to log operations
- `audit_log_path`: Path for audit log file

**Example**:

```python
from tzdc import TZDCClient, TimeWindow, CipherType

client = TZDCClient(
    time_window=TimeWindow.HOURS_24,
    cipher_type=CipherType.AES_256_GCM,
    enable_audit_log=True
)
```

#### encrypt_and_shard()

Primary method combining temporal encryption with cryptographic sharding.

```python
encrypt_and_shard(
    data: bytes,
    resource_id: str,
    total_shards: int = 5,
    threshold: int = 3,
    context: str = "default",
    custom_expiry: Optional[datetime] = None
) -> List[Shard]
```

**Parameters**:

- `data`: Raw data to encrypt and shard
- `resource_id`: Unique identifier for tracking
- `total_shards`: Number of shards to create
- `threshold`: Minimum shards needed for reconstruction
- `context`: Context string for key derivation (domain separation)
- `custom_expiry`: Override default expiration time

**Returns**: List of `Shard` objects

**Raises**:

- `ValueError`: Invalid parameters (threshold > total_shards, etc.)
- `EncryptionError`: Encryption failure

**Example**:

```python
shards = client.encrypt_and_shard(
    data=b"sensitive patient records",
    resource_id="patient_12345",
    total_shards=5,
    threshold=3,
    context="healthcare"
)

# Store shards separately
for i, shard in enumerate(shards):
    store_to_location(f"location_{i}", shard)
```

#### reconstruct_and_decrypt()

Reconstruct original data from shards and decrypt.

```python
reconstruct_and_decrypt(
    shards: List[Shard],
    context: str = "default"
) -> bytes
```

**Parameters**:

- `shards`: List of shard objects (must have at least threshold shards)
- `context`: Same context used during encryption

**Returns**: Original decrypted data as bytes

**Raises**:

- `KeyExpiredError`: Temporal key has expired
- `InsufficientShardsError`: Not enough shards provided
- `InvalidShardError`: Shard checksum validation failed
- `DecryptionError`: Decryption failed

**Example**:

```python
# Retrieve any 3 shards
retrieved_shards = [
    load_from_location("location_0"),
    load_from_location("location_2"),
    load_from_location("location_4")
]

try:
    original_data = client.reconstruct_and_decrypt(
        retrieved_shards,
        context="healthcare"
    )
except KeyExpiredError:
    print("Data has expired - security feature working!")
```

#### encrypt_with_temporal_key()

Simple encryption without sharding (for less sensitive scenarios).

```python
encrypt_with_temporal_key(
    data: bytes,
    context: str = "default",
    custom_expiry: Optional[datetime] = None
) -> Tuple[bytes, bytes, TemporalKey]
```

**Returns**: `(ciphertext, nonce, temporal_key)`

#### decrypt_with_temporal_key()

Decrypt data encrypted with temporal key (without shards).

```python
decrypt_with_temporal_key(
    ciphertext: bytes,
    nonce: bytes,
    context: str = "default"
) -> bytes
```

#### create_commitment()

Create zero-knowledge commitment for data.

```python
create_commitment(
    data: bytes,
    resource_id: str
) -> Tuple[Commitment, bytes]
```

**Returns**: `(commitment, salt)` - Store salt securely to verify later

#### verify_commitment()

Verify data matches a commitment.

```python
verify_commitment(
    commitment: Commitment,
    data: bytes,
    salt: bytes,
    resource_id: str
) -> bool
```

**Returns**: `True` if data matches commitment

#### store_shards()

Store shards using configured storage adapter.

```python
store_shards(
    shards: List[Shard],
    prefix: str = "shard"
) -> List[str]
```

**Returns**: List of storage keys

#### retrieve_shards()

Retrieve shards from storage.

```python
retrieve_shards(
    keys: List[str]
) -> List[Shard]
```

**Returns**: List of reconstructed Shard objects

#### Context Manager

Use as context manager for automatic cleanup:

```python
with client.session():
    shards = client.encrypt_and_shard(data, "resource_001")
    # Operations
    # Automatic cleanup on exit
```

---

## Best Practices

### 1. Choosing Time Windows

**General Guidelines**:

- **Shortest viable window**: Use the minimum time needed for legitimate access
- **Business requirements**: Match actual data lifecycle needs
- **Compliance**: Align with regulatory retention policies

**Industry Recommendations**:

| Industry   | Use Case                    | Recommended Window              |
| ---------- | --------------------------- | ------------------------------- |
| Healthcare | Temporary specialist access | 24-48 hours                     |
| Healthcare | Research study              | 30-90 days                      |
| Financial  | Transaction audit           | 7-90 days                       |
| Financial  | Temporary auditor access    | 7-14 days                       |
| ML/AI      | Training data               | Training duration + 24hr buffer |
| Enterprise | Contractor access           | Project duration                |
| Legal      | Document review             | Case duration + 30 days         |

**Example**:

```python
# ML training scenario
training_duration_hours = 6
buffer_hours = 2
total_hours = training_duration_hours + buffer_hours

client = TZDCClient(time_window=total_hours * 3600)
```

### 2. Shard Configuration

**Threshold Selection**:

| Total Shards | Recommended Threshold | Use Case                      |
| ------------ | --------------------- | ----------------------------- |
| 3            | 2                     | Small team, moderate security |
| 5            | 3                     | Standard enterprise use       |
| 7            | 4                     | High security environments    |
| 9            | 5                     | Critical infrastructure       |

**Rules of Thumb**:

- `threshold = ceil(total_shards * 0.6)` for balanced security/availability
- Never set threshold == total_shards (no fault tolerance)
- Higher thresholds = more security, less availability

**Example**:

```python
# High security: 5 of 7 required
shards = client.encrypt_and_shard(
    data=critical_data,
    resource_id="critical_001",
    total_shards=7,
    threshold=5
)
```

### 3. Shard Distribution Strategy

**Physical Distribution**:

```python
shard_locations = {
    "aws_us_east": shards[0],      # Different cloud provider
    "azure_europe": shards[1],      # Different region
    "gcp_asia": shards[2],          # Different continent
    "on_prem_primary": shards[3],   # On-premise backup
    "cold_storage": shards[4]       # Offline backup
}
```

**Never**:

- ❌ Store threshold shards in same physical location
- ❌ Store all shards with same cloud provider
- ❌ Store shards on same network segment

**Always**:

- ✅ Use geographic distribution
- ✅ Employ different storage technologies
- ✅ Maintain separate access controls per shard

### 4. Master Secret Management

**Generation**:

```python
from tzdc import generate_master_secret
import secrets

# Generate cryptographically secure master secret
master_secret = generate_master_secret()

# Store in Hardware Security Module (HSM) or Key Management Service (KMS)
store_in_hsm(master_secret)
```

**Storage Options** (in order of security):

1. **Hardware Security Module (HSM)** - Highest security, tamper-resistant
2. **Cloud KMS** (AWS KMS, Azure Key Vault, GCP KMS) - Managed encryption keys
3. **Environment Variables** - For development only
4. **Encrypted Configuration File** - Protected with separate encryption key

**Never**:

- ❌ Hardcode in source code
- ❌ Store in version control
- ❌ Store in plain text files
- ❌ Share across environments

**Example with Environment Variables**:

```python
import os
from tzdc import TZDCClient

# Retrieve from secure environment
master_secret = os.environ.get("TZDC_MASTER_SECRET")
if master_secret:
    master_secret = bytes.fromhex(master_secret)

client = TZDCClient(master_secret=master_secret)
```

### 5. Context Isolation

Use different contexts for different data domains:

```python
client = TZDCClient()

# Healthcare domain
healthcare_shards = client.encrypt_and_shard(
    patient_data,
    resource_id="patient_001",
    context="healthcare"
)

# Financial domain
financial_shards = client.encrypt_and_shard(
    transaction_data,
    resource_id="txn_001",
    context="financial"
)

# ML training domain
ml_shards = client.encrypt_and_shard(
    training_data,
    resource_id="batch_001",
    context="ml_training"
)
```

**Benefits**:

- Domain separation prevents cross-contamination
- Different keys for different data types
- Simplified access control management
- Better audit trail granularity

### 6. Audit Logging Best Practices

**Always Enable in Production**:

```python
from pathlib import Path

client = TZDCClient(
    enable_audit_log=True,
    audit_log_path=Path("/var/log/tzdc/audit.log")
)
```

**Regular Export and Archive**:

```python
from datetime import datetime, timedelta

# Export daily
date_str = datetime.now().strftime("%Y%m%d")
client.audit_logger.export_to_json(
    Path(f"/archive/tzdc_audit_{date_str}.json")
)

# Query recent operations
start_time = datetime.now(timezone.utc) - timedelta(hours=24)
recent_ops = client.audit_logger.get_logs(start_time=start_time)

# Monitor for suspicious activity
failed_ops = [log for log in recent_ops if not log['success']]
if len(failed_ops) > 10:
    alert_security_team()
```

### 7. Error Handling Patterns

**Comprehensive Error Handling**:

```python
from tzdc import (
    TZDCClient,
    KeyExpiredError,
    InsufficientShardsError,
    InvalidShardError,
    DecryptionError
)

client = TZDCClient()

try:
    shards = client.encrypt_and_shard(data, "resource_001")
    # Store shards

except ValueError as e:
    # Invalid parameters
    logger.error(f"Invalid configuration: {e}")

except Exception as e:
    # General encryption failure
    logger.error(f"Encryption failed: {e}")
    raise

# Later: Reconstruction
try:
    decrypted = client.reconstruct_and_decrypt(shards)

except KeyExpiredError:
    # Expected behavior - data expired
    logger.info("Data expired - temporal protection working")
    notify_user("Data no longer accessible")

except InsufficientShardsError:
    # Not enough shards available
    logger.error("Cannot reconstruct - insufficient shards")
    attempt_shard_recovery()

except InvalidShardError as e:
    # Shard corruption detected
    logger.error(f"Shard validation failed: {e}")
    request_alternative_shards()

except DecryptionError:
    # Authentication failure or key mismatch
    logger.error("Decryption failed - possible tampering")
    raise SecurityException("Data integrity compromised")
```

### 8. Performance Optimization

**Batch Processing**:

```python
import concurrent.futures

def encrypt_dataset(data_items):
    """Encrypt multiple items in parallel."""
    client = TZDCClient()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for data, resource_id in data_items:
            future = executor.submit(
                client.encrypt_and_shard,
                data,
                resource_id
            )
            futures.append(future)

        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    return results
```

**Memory-Efficient Streaming** (for large files):

```python
def encrypt_large_file(file_path, chunk_size=1024*1024):
    """Encrypt large file in chunks."""
    client = TZDCClient()

    with open(file_path, 'rb') as f:
        chunk_num = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            shards = client.encrypt_and_shard(
                chunk,
                resource_id=f"file_chunk_{chunk_num}",
                total_shards=3,
                threshold=2
            )

            # Store each chunk's shards
            store_shards(shards, chunk_num)
            chunk_num += 1
```

### 9. Testing Best Practices

**Unit Test Example**:

```python
import pytest
from tzdc import TZDCClient, KeyExpiredError
import time

def test_temporal_expiration():
    """Test that data becomes inaccessible after expiration."""
    # Use 1-second expiration for testing
    client = TZDCClient(time_window=1)

    data = b"test data"
    shards = client.encrypt_and_shard(
        data,
        resource_id="test_001",
        total_shards=3,
        threshold=2
    )

    # Should work immediately
    decrypted = client.reconstruct_and_decrypt(shards[:2])
    assert decrypted == data

    # Wait for expiration
    time.sleep(1.5)

    # Should fail after expiration
    with pytest.raises(KeyExpiredError):
        client.reconstruct_and_decrypt(shards[:2])
```

**Integration Test Example**:

```python
def test_distributed_storage_workflow():
    """Test complete workflow with distributed storage."""
    from tzdc import TZDCClient, LocalFileSystemAdapter
    import tempfile

    # Setup
    with tempfile.TemporaryDirectory() as tmpdir:
        client = TZDCClient(
            storage_adapter=LocalFileSystemAdapter(tmpdir)
        )

        # Encrypt
        data = b"sensitive data"
        shards = client.encrypt_and_shard(
            data,
            resource_id="integration_test",
            total_shards=5,
            threshold=3
        )

        # Store
        keys = client.store_shards(shards)
        assert len(keys) == 5

        # Retrieve
        retrieved = client.retrieve_shards(keys[:3])
        assert len(retrieved) == 3

        # Decrypt
        decrypted = client.reconstruct_and_decrypt(retrieved)
        assert decrypted == data
```

---

## Security Guidelines

### Threat Model

**TZDC Protects Against**:

1. **Data Breach with Delayed Discovery**

   - Scenario: Attacker steals encrypted data but discovery happens weeks later
   - Protection: Temporal keys expire, making stolen data useless
   - Example: Healthcare breach discovered 90 days after occurrence

2. **Insider Threats**

   - Scenario: Malicious employee with database access
   - Protection: Sharding prevents single-point access
   - Example: DBA cannot reconstruct data from single shard

3. **Cloud Provider Compromise**

   - Scenario: Single cloud provider breach
   - Protection: Shards distributed across providers
   - Example: AWS breach doesn't expose Azure/GCP shards

4. **Long-term Data Exposure**
   - Scenario: Old backups discovered years later
   - Protection: Keys expired long ago
   - Example: Tape backup from 2020 found in 2025

**TZDC Does NOT Protect Against**:

1. **Real-time Active Attacks**

   - Man-in-the-middle during encryption
   - Keylogger capturing master secret
   - Memory dumps during decryption

2. **Master Secret Compromise**

   - If master secret is stolen, future keys at risk
   - Past data with expired keys still protected
   - Mitigation: Rotate master secret regularly

3. **All Threshold Shards Compromised**

   - If attacker gets K-of-N shards before expiry
   - Mitigation: Distribute shards properly

4. **Side-Channel Attacks**
   - Timing attacks on cryptographic operations
   - Power analysis attacks
   - Mitigation: Use in trusted execution environments

### Defense in Depth

Layer TZDC with other security measures:

```python
# Layer 1: Network security (TLS/mTLS)
# Layer 2: Application authentication
# Layer 3: TZDC encryption and sharding
# Layer 4: Storage encryption at rest
# Layer 5: Physical security

class SecureDataPipeline:
    def __init__(self):
        self.tzdc_client = TZDCClient(
            time_window=TimeWindow.HOURS_24
        )

    def process_sensitive_data(self, data, user_credentials):
        # Layer 1: Verify user authentication
        if not self.authenticate_user(user_credentials):
            raise AuthenticationError()

        # Layer 2: Check authorization
        if not self.authorize_access(user_credentials, data):
            raise AuthorizationError()

        # Layer 3: TZDC encryption and sharding
        shards = self.tzdc_client.encrypt_and_shard(
            data,
            resource_id=generate_resource_id(),
            total_shards=5,
            threshold=3
        )

        # Layer 4: Distribute with redundancy
        self.distribute_shards_securely(shards)

        # Layer 5: Audit logging
        self.log_access(user_credentials, data)

        return shards
```

### Compliance Mappings

**GDPR Compliance**:

```python
# Right to be forgotten - automatic
client = TZDCClient(time_window=TimeWindow.DAYS_30)

# After 30 days, data automatically deleted
# No manual intervention needed

# Explicit deletion if needed earlier
def handle_gdpr_deletion_request(user_id):
    # Delete all shards for user
    shard_keys = find_user_shards(user_id)
    for key in shard_keys:
        client.storage.delete(key)

    # Log deletion
    log_gdpr_compliance(user_id, "data_deleted")
```

**HIPAA Compliance**:

```python
# Minimum necessary standard
# Only create shards needed for specific purpose

def share_patient_data_with_specialist(patient_id, specialist_id):
    client = TZDCClient(
        time_window=TimeWindow.HOURS_48,  # 48-hour consultation
        enable_audit_log=True
    )

    patient_data = get_patient_record(patient_id)

    # Encrypt with automatic expiration
    shards = client.encrypt_and_shard(
        patient_data,
        resource_id=f"patient_{patient_id}",
        total_shards=3,
        threshold=2
    )

    # Distribute: Hospital + Specialist + Backup
    distribute_for_consultation(shards, specialist_id)

    # Audit trail automatically maintained
    return shards
```

**PCI-DSS Compliance**:

```python
# Card data retention limits

def process_payment(card_data, transaction_id):
    client = TZDCClient(
        time_window=TimeWindow.DAYS_90,  # PCI requirement
        enable_audit_log=True
    )

    # Encrypt card data
    shards = client.encrypt_and_shard(
        card_data,
        resource_id=transaction_id,
        total_shards=5,
        threshold=3,
        context="payment_processing"
    )

    # Store in compliance-ready manner
    store_with_audit_trail(shards)

    # After 90 days: automatic deletion
```

---

## Performance Optimization

### Benchmark Results

**Hardware**: Intel i7-10700K, 32GB RAM, NVMe SSD

| Operation                 | Data Size | Time    | Throughput |
| ------------------------- | --------- | ------- | ---------- |
| Encryption (AES-256-GCM)  | 1 MB      | 7.2 ms  | 139 MB/s   |
| Encryption (ChaCha20)     | 1 MB      | 5.8 ms  | 172 MB/s   |
| Decryption (AES-256-GCM)  | 1 MB      | 8.1 ms  | 123 MB/s   |
| Shard Creation (5 shards) | 1 MB      | 12.3 ms | 81 MB/s    |
| Shard Reconstruction      | 3 shards  | 9.7 ms  | 103 MB/s   |
| Key Generation            | -         | 1.8 ms  | -          |
| ZK Commitment             | 1 KB      | 0.9 ms  | -          |

### Optimization Strategies

**1. Cipher Selection**:

```python
# For maximum throughput
client_fast = TZDCClient(cipher_type=CipherType.CHACHA20_POLY1305)

# For maximum compatibility
client_standard = TZDCClient(cipher_type=CipherType.AES_256_GCM)
```

**2. Shard Configuration Trade-offs**:

```python
# High security, slower
high_security = client.encrypt_and_shard(
    data, "resource_001",
    total_shards=9, threshold=6  # More shards = more overhead
)

# Balanced
balanced = client.encrypt_and_shard(
    data, "resource_001",
    total_shards=5, threshold=3  # Recommended
)

# Fast, lower security
fast = client.encrypt_and_shard(
    data, "resource_001",
    total_shards=3, threshold=2  # Minimal overhead
)
```

**3. Key Caching**:

```python
# Keys are automatically cached within same time slot
# Reuse client instance for better performance

client = TZDCClient()

for i in range(100):
    # Same time slot = cached key = faster
    shards = client.encrypt_and_shard(
        data_items[i],
        f"resource_{i}",
        context="batch_processing"
    )
```

**4. Parallel Processing**:

```python
from concurrent.futures import ThreadPoolExecutor

def parallel_encryption(data_list, max_workers=4):
    client = TZDCClient()

    def encrypt_item(item):
        data, resource_id = item
        return client.encrypt_and_shard(data, resource_id)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(encrypt_item, data_list))

    return results

# 4x speedup on quad-core system
results = parallel_encryption(dataset, max_workers=4)
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. KeyExpiredError

**Problem**: Data cannot be decrypted because temporal key expired.

**Cause**: Time window elapsed since encryption.

**Solution**:

```python
# This is EXPECTED behavior - feature, not bug!
# Data should become inaccessible after expiration

try:
    decrypted = client.reconstruct_and_decrypt(shards)
except KeyExpiredError as e:
    print(f"Data expired: {e}")
    # Inform user data is no longer accessible
    # This is the security feature working as designed
```

**Prevention**:

- Set appropriate time windows for your use case
- Use `custom_expiry` for critical data
- Check `shard.expires_at` before attempting decryption

#### 2. InsufficientShardsError

**Problem**: Not enough shards available for reconstruction.

**Cause**: Missing shards or storage failure.

**Solution**:

```python
try:
    decrypted = client.reconstruct_and_decrypt(shards)
except InsufficientShardsError as e:
    print(f"Need more shards: {e}")

    # Try to retrieve additional shards
    additional_shards = retrieve_backup_shards()
    all_shards = shards + additional_shards

    decrypted = client.reconstruct_and_decrypt(all_shards)
```

**Prevention**:

- Store more shards than threshold
- Implement shard redundancy
- Regular backup verification

#### 3. InvalidShardError

**Problem**: Shard checksum validation fails.

**Cause**: Data corruption or tampering.

**Solution**:

```python
try:
    decrypted = client.reconstruct_and_decrypt(shards)
except InvalidShardError as e:
    print(f"Shard corrupted: {e}")

    # Use different shards
    alternative_shards = get_alternative_shards()
    decrypted = client.reconstruct_and_decrypt(alternative_shards)

    # Alert security team
    alert_security("Possible tampering detected")
```

**Prevention**:

- Use reliable storage systems
- Implement storage-level checksums
- Regular integrity checks

#### 4. DecryptionError

**Problem**: Decryption fails even with valid shards.

**Possible Causes**:

- Wrong context used
- Master secret mismatch
- Data tampering

**Solution**:

```python
# Ensure correct context
decrypted = client.reconstruct_and_decrypt(
    shards,
    context="healthcare"  # Must match encryption context
)

# Verify master secret
if master_secret != original_master_secret:
    raise ValueError("Master secret mismatch")

# Check audit logs for tampering
logs = client.get_audit_logs(resource_id="resource_001")
if any(not log['success'] for log in logs):
    investigate_security_incident()
```

#### 5. Performance Issues

**Problem**: Encryption/decryption too slow.

**Solutions**:

```python
# 1. Use faster cipher
client = TZDCClient(cipher_type=CipherType.CHACHA20_POLY1305)

# 2. Reduce shard count
shards = client.encrypt_and_shard(
    data, "resource_001",
    total_shards=3,  # Fewer shards = faster
    threshold=2
)

# 3. Disable PBKDF2 for non-critical data
from tzdc import TemporalKeyManager

key_manager = TemporalKeyManager(
    master_secret=secret,
    use_pbkdf2=False  # Faster but less secure
)

# 4. Batch operations
results = parallel_encryption(data_items, max_workers=8)
```

### Debug Mode

**Enable Verbose Logging**:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('tzdc')
logger.setLevel(logging.DEBUG)

client = TZDCClient(enable_audit_log=True)

# Now all operations are logged in detail
```

### Health Checks

**Verify System Health**:

```python
def health_check():
    """Verify TZDC system is functioning correctly."""
    client = TZDCClient()

    # Test encryption/decryption
    test_data = b"health check"
    try:
        shards = client.encrypt_and_shard(
            test_data,
            "health_check",
            total_shards=3,
            threshold=2
        )

        decrypted = client.reconstruct_and_decrypt(shards[:2])

        assert decrypted == test_data
        print("✓ TZDC system healthy")
        return True

    except Exception as e:
        print(f"✗ TZDC system unhealthy: {e}")
        return False

# Run periodically
if __name__ == "__main__":
    health_check()
```

---

## Frequently Asked Questions

### Q: Can I change the time window after encryption?

**A**: No. The time window is baked into the temporal key at encryption time. You must decrypt and re-encrypt with a new time window.

### Q: What happens if my system clock is wrong?

**A**: Temporal keys are based on Unix timestamps. Clock skew can cause issues. Ensure NTP synchronization across all systems.

### Q: Can I use TZDC with databases?

**A**: Yes. Encrypt data before storing in database, store shards in separate columns/tables.

```python
# Example with PostgreSQL
def store_encrypted_record(conn, record_id, data):
    client = TZDCClient()
    shards = client.encrypt_and_shard(data, record_id)

    for i, shard in enumerate(shards):
        conn.execute(
            "INSERT INTO shards VALUES (%s, %s, %s)",
            (record_id, i, serialize_shard(shard))
        )
```

### Q: Is TZDC quantum-resistant?

**A**: No. Current version uses classical cryptography (AES, SHA-256). Post-quantum support planned for v2.0.

### Q: Can shards be compressed?

**A**: Yes, compress before encryption for better efficiency.

```python
import gzip

compressed = gzip.compress(large_data)
shards = client.encrypt_and_shard(compressed, "resource_001")

# Later: decompress after decryption
decrypted_compressed = client.reconstruct_and_decrypt(shards)
original = gzip.decompress(decrypted_compressed)
```

---

## Additional Resources

- **GitHub**: https://github.com/jayeshthk/TZDC.git
- **Examples**: https://github.com/jayeshthk/TZDC.git/tree/main/examples
- **Security Advisories**: https://github.com/jayeshthk/TZDC.git/security/advisories

---
