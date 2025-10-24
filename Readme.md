# TZDC: Temporal Zero-Trust Data Compartmentalization

## 🚀 What is TZDC?

TZDC prevents catastrophic data breaches by ensuring stolen data **automatically becomes useless** through:

1. **Temporal Encryption**: Time-bound keys that automatically expire, making data permanently inaccessible after configurable windows
2. **Cryptographic Sharding**: Data fragmentation using Shamir's Secret Sharing where individual shards are meaningless in isolation
3. **Zero-Knowledge Proofs**: Verify data properties without revealing the underlying data

### Why TZDC?

Traditional encryption has a critical weakness: if an attacker steals encrypted data and eventually obtains the key, all historical data becomes compromised. TZDC solves this by:

- ✅ **Automatic Breach Mitigation**: Data self-destructs after expiration—no manual intervention needed
- ✅ **Zero Single Point of Failure**: Sharding eliminates centralized vulnerability
- ✅ **Privacy-Preserving AI**: Train ML models on sensitive data with automatic post-training deletion
- ✅ **Compliance-Ready**: Built for GDPR, HIPAA, PCI-DSS requirements

## 📦 Installation

```bash
git clone https://github.com/jayeshthk/TZDC.git
cd TZDC

#create a virtual env
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

```

**Requirements**: Python 3.10+

## 🎯 Quick Start

### Basic Usage: Encrypt with Auto-Expiration

```python
from tzdc import TZDCClient, TimeWindow

# Initialize client with 1-hour expiration
client = TZDCClient(time_window=TimeWindow.HOUR_1)

# Encrypt sensitive data
sensitive_data = b"Patient medical records: diabetes diagnosis"

shards = client.encrypt_and_shard(
    data=sensitive_data,
    resource_id="patient_12345",
    total_shards=5,
    threshold=3  # Any 3 shards can reconstruct
)

# Store shards separately (e.g., different servers/regions)
for i, shard in enumerate(shards):
    client.storage.store(f"shard_{i}", serialize_shard(shard))

# Later: Reconstruct with any 3 shards
retrieved_shards = [deserialize_shard(client.storage.retrieve(f"shard_{i}"))
                    for i in range(3)]
original_data = client.reconstruct_and_decrypt(retrieved_shards)

# After 1 hour: Data becomes permanently inaccessible!
```

### ML Training Data Protection

```python
from tzdc import TZDCClient, TimeWindow
from datetime import datetime, timedelta

client = TZDCClient(time_window=TimeWindow.HOURS_24)

# Protect training data with 24-hour expiration
training_data = load_sensitive_dataset()

shards = client.encrypt_and_shard(
    data=training_data,
    resource_id="ml_batch_001",
    total_shards=3,
    threshold=2,
    custom_expiry=datetime.utcnow() + timedelta(hours=24)
)

# Distribute shards to training nodes
for i, shard in enumerate(shards):
    send_to_training_node(node_id=i, shard=shard)

# After training completes, data is permanently deleted
# No manual cleanup needed—built-in temporal expiration
```

### Healthcare Data Sharing

```python
from tzdc import TZDCClient, TimeWindow

client = TZDCClient(time_window=TimeWindow.HOURS_24)

# Temporary specialist access to patient records
patient_data = b"Patient: John Doe, Diagnosis: Diabetes Type 2"

# Create zero-knowledge commitment for audit trail
commitment, salt = client.create_commitment(
    patient_data,
    resource_id="patient_12345"
)

# Encrypt with automatic expiration
shards = client.encrypt_and_shard(
    patient_data,
    resource_id="patient_12345",
    total_shards=5,
    threshold=3
)

# Specialist accesses data (requires 3 of 5 shards)
# After 24 hours, access automatically revokes
```

### Financial Audit Trail

```python
from tzdc import TZDCClient, TimeWindow

client = TZDCClient(
    time_window=TimeWindow.DAYS_7,
    enable_audit_log=True,
    audit_log_path="financial_audit.log"
)

# Process transaction with 7-day retention
transaction = b"Transaction: $10,000 from Account A to Account B"

shards = client.encrypt_and_shard(
    transaction,
    resource_id="txn_001",
    total_shards=5,
    threshold=3
)

# Store in distributed ledger
keys = client.store_shards(shards, prefix="txn")

# Auditor can access within 7 days
# After 7 days: automatic deletion per compliance policy

# View immutable audit trail
logs = client.get_audit_logs(resource_id="txn_001")
```

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                       TZDCClient                            │
│  High-level API for encryption, sharding, and ZK proofs     │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼──────────┐  ┌──────▼─────────┐  ┌───────▼──────────┐
│ TemporalKey      │  │ ShardManager   │  │ ZeroKnowledge    │
│ Manager          │  │                │  │ Prover           │
│                  │  │ Shamir's       │  │                  │
│ HKDF-SHA256      │  │ Secret         │  │ Commitments &    │
│ PBKDF2           │  │ Sharing        │  │ Range Proofs     │
│ Auto-expiration  │  │ (K-of-N)       │  │                  │
└──────────────────┘  └────────────────┘  └──────────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │ EncryptionEngine  │
                    │ AES-256-GCM       │
                    │ ChaCha20-Poly1305 │
                    └───────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │ StorageAdapter    │
                    │ Filesystem / S3   │
                    │ Redis / PostgreSQL│
                    └───────────────────┘
```

### Data Flow

1. **Encryption Phase**:

   ```
   Raw Data → Temporal Key Generation → AES-256-GCM Encryption →
   Shamir's Secret Sharing → N Shards → Distributed Storage
   ```

2. **Decryption Phase**:

   ```
   Retrieve K Shards → Lagrange Interpolation → Reconstruct Encrypted Data →
   Temporal Key Validation → AES-256-GCM Decryption → Original Data
   ```

3. **Expiration**:
   ```
   Time Window Expires → Temporal Key Becomes Invalid →
   Decryption Permanently Fails → Data Protection Guaranteed
   ```

## 🔐 Security Features

### Temporal Key Management

- **HKDF-SHA256**: Cryptographically secure key derivation
- **PBKDF2**: Key stretching with 100,000 iterations
- **Time-slotted keys**: Automatic rotation and invalidation
- **No key storage**: Keys regenerated deterministically from master secret

### Cryptographic Sharding

- **Shamir's Secret Sharing**: Information-theoretic security
- **Threshold scheme**: K-of-N reconstruction (e.g., 3-of-5)
- **Individual shard encryption**: Each shard encrypted with unique temporal key
- **Checksum validation**: SHA-256 checksums prevent corruption

### Authenticated Encryption

- **AES-256-GCM**: Industry-standard authenticated encryption
- **ChaCha20-Poly1305**: Alternative high-performance cipher
- **Automatic nonce generation**: 96-bit cryptographically secure nonces
- **Tampering detection**: Authentication tags prevent modification

### Zero-Knowledge Proofs

- **Hash commitments**: SHA-256 based commitments
- **Range proofs**: Prove value within range without revealing value
- **Membership proofs**: Prove element in set without revealing element
- **Audit trails**: Verify operations without exposing data

## 📖 API Reference

### TZDCClient

Main high-level interface for all TZDC operations.

```python
class TZDCClient:
    def __init__(
        self,
        master_secret: Optional[bytes] = None,
        time_window: Union[TimeWindow, int] = TimeWindow.HOUR_1,
        storage_adapter: Optional[StorageAdapter] = None,
        cipher_type: CipherType = CipherType.AES_256_GCM,
        enable_audit_log: bool = True,
        audit_log_path: Optional[Path] = None
    )
```

#### Methods

**encrypt_and_shard(data, resource_id, total_shards=5, threshold=3, context="default", custom_expiry=None)**

Encrypt data with temporal key and split into cryptographic shards.

- **Returns**: `List[Shard]`
- **Raises**: `EncryptionError`, `ValueError`

**reconstruct_and_decrypt(shards, context="default")**

Reconstruct data from shards and decrypt using temporal key.

- **Returns**: `bytes` (original data)
- **Raises**: `KeyExpiredError`, `InsufficientShardsError`, `DecryptionError`

**encrypt_with_temporal_key(data, context="default", custom_expiry=None)**

Simple encryption without sharding.

- **Returns**: `Tuple[bytes, bytes, TemporalKey]` (ciphertext, nonce, key)

**create_commitment(data, resource_id)**

Create zero-knowledge commitment.

- **Returns**: `Tuple[Commitment, bytes]` (commitment, salt)

**verify_commitment(commitment, data, salt, resource_id)**

Verify data against commitment.

- **Returns**: `bool`

### TimeWindow Enum

Predefined time windows for key expiration:

```python
TimeWindow.SECONDS_30   # 30 seconds
TimeWindow.MINUTES_5    # 5 minutes
TimeWindow.MINUTES_15   # 15 minutes
TimeWindow.HOUR_1       # 1 hour
TimeWindow.HOURS_24     # 24 hours
TimeWindow.DAYS_7       # 7 days
TimeWindow.DAYS_30      # 30 days
```

### Storage Adapters

#### LocalFileSystemAdapter

```python
from tzdc import LocalFileSystemAdapter

adapter = LocalFileSystemAdapter(base_path="./tzdc_storage")
```

#### Custom Storage Adapter

```python
from tzdc import StorageAdapter

class MyStorageAdapter(StorageAdapter):
    def store(self, key: str, data: bytes) -> bool:
        # Implementation
        pass

    def retrieve(self, key: str) -> Optional[bytes]:
        # Implementation
        pass

    def delete(self, key: str) -> bool:
        # Implementation
        pass

    def list_keys(self, prefix: str = "") -> List[str]:
        # Implementation
        pass
```

## 🎓 Advanced Usage

### Custom Time Windows

```python
from tzdc import TZDCClient

# Custom time window (2 hours = 7200 seconds)
client = TZDCClient(time_window=7200)

# Or use timedelta for custom expiry
from datetime import datetime, timedelta

custom_expiry = datetime.utcnow() + timedelta(days=3, hours=6)
shards = client.encrypt_and_shard(
    data=data,
    resource_id="resource_001",
    custom_expiry=custom_expiry
)
```

### Context Manager Pattern

```python
from tzdc import TZDCClient

with TZDCClient(time_window=3600) as client:
    shards = client.encrypt_and_shard(data, "resource_001")
    # Automatic cleanup on exit
```

### Async Operations (Future Feature)

```python
# Coming in v1.1.0
import asyncio
from tzdc import AsyncTZDCClient

async def process_data():
    client = AsyncTZDCClient()
    shards = await client.encrypt_and_shard_async(data, "resource_001")
    return shards
```

### Distributed Storage

```python
from tzdc import TZDCClient

# S3 Storage
from tzdc.storage import S3StorageAdapter
s3_adapter = S3StorageAdapter(bucket="my-tzdc-bucket")

client = TZDCClient(storage_adapter=s3_adapter)

# Redis Storage
from tzdc.storage import RedisStorageAdapter
redis_adapter = RedisStorageAdapter(host="localhost", port=6379)

client = TZDCClient(storage_adapter=redis_adapter)
```

### Batch Operations

```python
from tzdc import TZDCClient

client = TZDCClient()

# Encrypt multiple items
datasets = [
    (b"data1", "resource_001"),
    (b"data2", "resource_002"),
    (b"data3", "resource_003"),
]

all_shards = []
for data, resource_id in datasets:
    shards = client.encrypt_and_shard(data, resource_id)
    all_shards.append((resource_id, shards))
```

### Audit Log Analysis

```python
from tzdc import TZDCClient
from datetime import datetime, timedelta

client = TZDCClient(enable_audit_log=True)

# Get all encryption operations
encrypt_logs = client.get_audit_logs(operation="encrypt_and_shard")

# Get logs for specific resource
resource_logs = client.get_audit_logs(resource_id="patient_12345")

# Export audit logs
client.audit_logger.export_to_json("audit_export.json")

# Time-based filtering
start_time = datetime.utcnow() - timedelta(hours=24)
recent_logs = client.audit_logger.get_logs(start_time=start_time)
```

## 🧪 Testing

```bash

python test_tzdc.py

```

## 📊 Performance

Benchmarks on standard hardware (Apple M3 chip with an 8-core CPU and up to a 10-core GPU):

| Operation                   | Data Size | Time   | Throughput |
| --------------------------- | --------- | ------ | ---------- |
| Encryption (AES-256-GCM)    | 1 MB      | ~8 ms  | 125 MB/s   |
| Decryption (AES-256-GCM)    | 1 MB      | ~10 ms | 100 MB/s   |
| Shard Generation (5 shards) | 1 MB      | ~15 ms | -          |
| Shard Reconstruction        | 3 shards  | ~12 ms | -          |
| Key Generation              | -         | ~2 ms  | -          |
| ZK Commitment               | 1 KB      | ~1 ms  | -          |

Memory overhead: ~1.8x original data size during operations.

## 🛡️ Security Considerations

### Best Practices

1. **Master Secret Management**

   ```python
   # Generate and securely store master secret
   from tzdc import generate_master_secret

   master_secret = generate_master_secret()
   # Store in secure key management system (HSM, KMS, etc.)
   ```

2. **Time Window Selection**

   - Use shortest feasible window for your use case
   - Healthcare: 24 hours - 7 days
   - Financial: 7 days - 30 days
   - ML Training: Match training duration + buffer

3. **Shard Distribution**

   - Store shards in geographically separate locations
   - Use different cloud providers for redundancy
   - Never store threshold number of shards together

4. **Audit Logging**
   - Always enable audit logging in production
   - Regularly export and archive audit logs
   - Monitor for unauthorized access attempts

### Known Limitations

- **No Post-Quantum Cryptography**: Current version uses classical cryptography
- **Clock Synchronization**: Requires accurate system clocks for temporal keys
- **Key Derivation**: Master secret compromise compromises all derived keys
- **Timing Attacks**: Not protected against advanced timing side-channel attacks

### Threat Model

TZDC protects against:

- ✅ Data breaches (stolen encrypted data becomes useless after expiration)
- ✅ Insider threats (sharding prevents single-point compromise)
- ✅ Long-term data exposure (automatic expiration)
- ✅ Unauthorized reconstruction (requires threshold shards)

TZDC does NOT protect against:

- ❌ Master secret compromise (protects future data, not past)
- ❌ Real-time man-in-the-middle attacks
- ❌ Physical hardware attacks
- ❌ Social engineering

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/jayeshthk/TZDC.git
cd tzdc-python
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Run tests
python test_tzdc.py

```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Shamir's Secret Sharing**: Adi Shamir (1979)
- **Cryptography Library**: Python Cryptographic Authority
- **Inspired by**: Time-lock puzzles, zero-knowledge proof systems

## 📚 References

1. Shamir, A. (1979). "How to share a secret". Communications of the ACM.
2. Boneh, D., & Naor, M. (2000). "Timed commitments". CRYPTO 2000.
3. Goldwasser, S., Micali, S., & Rackoff, C. (1989). "The knowledge complexity of interactive proof systems".

## 📞 Support

- **Documentation**: [Docs.md](Docs.md)
- **Issues**: https://github.com/jayeshthk/TZDC.git/issues
- **Discussions**: https://github.com/jayeshthk/TZDC.git/discussions
- **Email**: jayesh@arkvien.com
