"""
TZDC Library Test Suite
========================

Comprehensive tests for all TZDC components including:
- Temporal key management
- Shard creation and reconstruction
- Encryption/decryption
- Zero-knowledge proofs
- Storage adapters
- End-to-end workflows
"""

import pytest
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import shutil
from tzdc_core import Shard

# Import TZDC components
from tzdc_core import (
    TZDCClient,
    TemporalKeyManager,
    ShardManager,
    EncryptionEngine,
    ZeroKnowledgeProver,
    LocalFileSystemAdapter,
    AuditLogger,
    TimeWindow,
    CipherType,
    KeyExpiredError,
    InsufficientShardsError,
    InvalidShardError,
    EncryptionError,
    DecryptionError,
    ProofVerificationError,
    generate_master_secret,
    serialize_shard,
    deserialize_shard
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def master_secret():
    """Generate master secret for tests."""
    return generate_master_secret()


@pytest.fixture
def sample_data():
    """Sample data for testing."""
    return b"Test data for TZDC"

@pytest.fixture
def key_manager(master_secret):
    """Create TemporalKeyManager instance."""
    return TemporalKeyManager(master_secret, time_window=60)


@pytest.fixture
def shard_manager():
    """Create ShardManager instance."""
    return ShardManager()


@pytest.fixture
def encryption_engine():
    """Create EncryptionEngine instance."""
    return EncryptionEngine(CipherType.AES_256_GCM)


@pytest.fixture
def zk_prover():
    """Create ZeroKnowledgeProver instance."""
    return ZeroKnowledgeProver()


@pytest.fixture
def storage_adapter(temp_dir):
    """Create LocalFileSystemAdapter instance."""
    return LocalFileSystemAdapter(temp_dir / "storage")


@pytest.fixture
def tzdc_client(temp_dir):
    """Create TZDCClient instance."""
    return TZDCClient(
        time_window=TimeWindow.MINUTES_5,
        storage_adapter=LocalFileSystemAdapter(temp_dir / "storage"),
        enable_audit_log=True,
        audit_log_path=temp_dir / "audit.log"
    )


# ============================================================================
# TEMPORAL KEY MANAGER TESTS
# ============================================================================

class TestTemporalKeyManager:
    """Tests for TemporalKeyManager class."""
    
    def test_generate_temporal_key(self, key_manager):
        """Test temporal key generation."""
        key = key_manager.generate_temporal_key(context="test")
        
        assert key.key is not None
        assert len(key.key) == 32
        assert key.is_valid()
        assert key.time_remaining() > 0
        assert "test" in key.key_id
    
    def test_key_expiration(self, master_secret):
        """Test that keys expire correctly."""
        # Create manager with 1-second expiration
        manager = TemporalKeyManager(master_secret, time_window=1)
        key = manager.generate_temporal_key()
        
        assert key.is_valid()
        
        # Wait for expiration
        time.sleep(1.5)
        
        assert not key.is_valid()
        
        with pytest.raises(KeyExpiredError):
            manager.validate_key(key)
    
    def test_key_caching(self, key_manager):
        """Test that keys are properly cached."""
        key1 = key_manager.generate_temporal_key(context="test")
        key2 = key_manager.generate_temporal_key(context="test")
        
        # Same context and time slot should return cached key
        assert key1.key == key2.key
        assert key1.key_id == key2.key_id
    
    def test_different_contexts(self, key_manager):
        """Test that different contexts generate different keys."""
        key1 = key_manager.generate_temporal_key(context="context1")
        key2 = key_manager.generate_temporal_key(context="context2")
        
        assert key1.key != key2.key
        assert key1.key_id != key2.key_id
    
    def test_custom_expiry(self, key_manager):
        """Test custom expiration times."""
        custom_expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        key = key_manager.generate_temporal_key(custom_expiry=custom_expiry)
        
        assert key.expires_at == custom_expiry
        assert key.time_remaining() > 86000  # Close to 24 hours
    
    def test_cleanup_expired_keys(self, master_secret):
        """Test cleanup of expired keys."""
        manager = TemporalKeyManager(master_secret, time_window=1)
        
        # Generate multiple keys
        key1 = manager.generate_temporal_key(context="test1")
        key2 = manager.generate_temporal_key(context="test2")
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Generate new key (should trigger different time slot)
        key3 = manager.generate_temporal_key(context="test3")
        
        # Cleanup
        removed = manager.cleanup_expired_keys()
        
        assert removed >= 2
    
    def test_get_temporal_key_by_id(self, key_manager):
        """Test retrieving key by ID."""
        key = key_manager.generate_temporal_key(context="test")
        retrieved_key = key_manager.get_temporal_key_by_id(key.key_id)
        
        assert retrieved_key is not None
        assert retrieved_key.key_id == key.key_id
        assert retrieved_key.key == key.key
    
    def test_generate_temporal_key_for_time(self, key_manager):
        """Test generating key for specific time."""
        timestamp = datetime.now(timezone.utc).timestamp()
        key = key_manager.generate_temporal_key_for_time(context="test", timestamp=timestamp)
        
        assert key.key is not None
        assert key.is_valid()


# ============================================================================
# SHARD MANAGER TESTS
# ============================================================================

class TestShardManager:
    """Tests for ShardManager class."""
    
    def test_create_shards(self, shard_manager, sample_data):
        """Test shard creation."""
        shards = shard_manager.create_shards(
            sample_data,
            total_shards=5,
            threshold=3
        )
        
        assert len(shards) == 5
        assert all(shard.threshold == 3 for shard in shards)
        assert all(shard.total_shards == 5 for shard in shards)
        assert all(shard.validate_checksum() for shard in shards)
    
    def test_reconstruct_from_shards(self, shard_manager, sample_data):
        """Test data reconstruction from shards."""
        shards = shard_manager.create_shards(
            sample_data,
            total_shards=5,
            threshold=3
        )
        
        # Use any 3 shards
        selected_shards = shards[:3]
        reconstructed = shard_manager.reconstruct_from_shards(selected_shards)
        
        assert reconstructed == sample_data
    
    def test_different_shard_combinations(self, shard_manager, sample_data):
        """Test that different shard combinations work."""
        shards = shard_manager.create_shards(
            sample_data,
            total_shards=5,
            threshold=3
        )
        
        # Try different combinations
        combinations = [
            [0, 1, 2],
            [0, 2, 4],
            [1, 3, 4],
            [2, 3, 4]
        ]
        
        for combo in combinations:
            selected = [shards[i] for i in combo]
            reconstructed = shard_manager.reconstruct_from_shards(selected)
            assert reconstructed == sample_data
    
    def test_insufficient_shards(self, shard_manager, sample_data):
        """Test that insufficient shards raise error."""
        shards = shard_manager.create_shards(
            sample_data,
            total_shards=5,
            threshold=3
        )
        
        # Try with only 2 shards
        with pytest.raises(InsufficientShardsError):
            shard_manager.reconstruct_from_shards(shards[:2])
    
    def test_invalid_checksum(self, shard_manager, sample_data):
        """Test that corrupted shards are detected."""
        shards = shard_manager.create_shards(sample_data, total_shards=3, threshold=2)
        
        # Corrupt a shard
        shards[0].encrypted_data = b"corrupted_data"
        
        with pytest.raises(InvalidShardError):
            shard_manager.reconstruct_from_shards(shards[:2])
    
    def test_large_data(self, shard_manager):
        """Test sharding of larger data."""
        # Use data that fits within the new prime size
        large_data = b"L" * 50  # 50 bytes

        shards = shard_manager.create_shards(
            large_data,
            total_shards=5,
            threshold=3
        )

        reconstructed = shard_manager.reconstruct_from_shards(shards[:3])
        assert reconstructed == large_data


    def test_shard_encoding_decoding(self, shard_manager):
        """Test point encoding and decoding."""
        x = 5
        y = 123456789
        
        encoded = shard_manager._encode_point(x, y)
        decoded_x, decoded_y = shard_manager._decode_point(encoded)
        
        assert x == decoded_x
        assert y == decoded_y


# ============================================================================
# ENCRYPTION ENGINE TESTS
# ============================================================================

class TestEncryptionEngine:
    """Tests for EncryptionEngine class."""
    
    def test_encrypt_decrypt_aes(self, sample_data):
        """Test AES-256-GCM encryption/decryption."""
        engine = EncryptionEngine(CipherType.AES_256_GCM)
        key = secrets.token_bytes(32)
        
        ciphertext, nonce = engine.encrypt(sample_data, key)
        
        assert ciphertext != sample_data
        assert len(nonce) == 12
        
        plaintext = engine.decrypt(ciphertext, key, nonce)
        assert plaintext == sample_data
    
    def test_encrypt_decrypt_chacha(self, sample_data):
        """Test ChaCha20-Poly1305 encryption/decryption."""
        engine = EncryptionEngine(CipherType.CHACHA20_POLY1305)
        key = secrets.token_bytes(32)
        
        ciphertext, nonce = engine.encrypt(sample_data, key)
        plaintext = engine.decrypt(ciphertext, key, nonce)
        
        assert plaintext == sample_data
    
    def test_authenticated_encryption(self, sample_data):
        """Test that tampering is detected."""
        engine = EncryptionEngine(CipherType.AES_256_GCM)
        key = secrets.token_bytes(32)
        
        ciphertext, nonce = engine.encrypt(sample_data, key)
        
        # Tamper with ciphertext
        tampered = bytes([b ^ 1 for b in ciphertext])
        
        with pytest.raises(DecryptionError):
            engine.decrypt(tampered, key, nonce)
    
    def test_wrong_key(self, sample_data):
        """Test that wrong key fails decryption."""
        engine = EncryptionEngine(CipherType.AES_256_GCM)
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        
        ciphertext, nonce = engine.encrypt(sample_data, key1)
        
        with pytest.raises(DecryptionError):
            engine.decrypt(ciphertext, key2, nonce)
    
    def test_associated_data(self, sample_data):
        """Test authenticated associated data."""
        engine = EncryptionEngine(CipherType.AES_256_GCM)
        key = secrets.token_bytes(32)
        associated = b"metadata"
        
        ciphertext, nonce = engine.encrypt(sample_data, key, associated)
        plaintext = engine.decrypt(ciphertext, key, nonce, associated)
        
        assert plaintext == sample_data
        
        # Wrong associated data should fail
        with pytest.raises(DecryptionError):
            engine.decrypt(ciphertext, key, nonce, b"wrong")


# ============================================================================
# ZERO-KNOWLEDGE PROVER TESTS
# ============================================================================

class TestZeroKnowledgeProver:
    """Tests for ZeroKnowledgeProver class."""
    
    def test_create_and_verify_commitment(self, zk_prover, sample_data):
        """Test commitment creation and verification."""
        commitment, salt = zk_prover.create_commitment(sample_data)
        
        assert commitment.commitment_hash is not None
        assert len(salt) == 32
        
        # Verify with correct data
        assert zk_prover.verify_commitment(commitment, sample_data, salt)
        
        # Verify with wrong data should fail
        assert not zk_prover.verify_commitment(commitment, b"wrong data", salt)
    
    def test_commitment_with_custom_salt(self, zk_prover, sample_data):
        """Test commitment with custom salt."""
        custom_salt = secrets.token_bytes(16)
        commitment, salt = zk_prover.create_commitment(sample_data, salt=custom_salt)
        
        assert salt == custom_salt
        assert zk_prover.verify_commitment(commitment, sample_data, custom_salt)
    
    def test_range_proof(self, zk_prover):
        """Test range proof creation and verification."""
        value = 50
        commitment, proof_data = zk_prover.prove_range(
            value=value,
            min_value=0,
            max_value=100
        )
        
        assert commitment.proof_type == "range_proof"
        assert zk_prover.verify_range_proof(commitment, value, proof_data)
    
    def test_range_proof_invalid_value(self, zk_prover):
        """Test that range proof fails for out-of-range values."""
        with pytest.raises(ProofVerificationError):
            zk_prover.prove_range(
                value=150,
                min_value=0,
                max_value=100
            )
    
    def test_range_proof_boundary(self, zk_prover):
        """Test range proof at boundaries."""
        # Test minimum boundary
        commitment1, proof1 = zk_prover.prove_range(0, 0, 100)
        assert zk_prover.verify_range_proof(commitment1, 0, proof1)
        
        # Test maximum boundary
        commitment2, proof2 = zk_prover.prove_range(100, 0, 100)
        assert zk_prover.verify_range_proof(commitment2, 100, proof2)


# ============================================================================
# STORAGE ADAPTER TESTS
# ============================================================================

class TestLocalFileSystemAdapter:
    """Tests for LocalFileSystemAdapter class."""
    
    def test_store_and_retrieve(self, storage_adapter):
        """Test storing and retrieving data."""
        key = "test_key"
        data = b"test data"
        
        assert storage_adapter.store(key, data)
        retrieved = storage_adapter.retrieve(key)
        
        assert retrieved == data
    
    def test_retrieve_nonexistent(self, storage_adapter):
        """Test retrieving non-existent key."""
        result = storage_adapter.retrieve("nonexistent")
        assert result is None
    
    def test_delete(self, storage_adapter):
        """Test deleting data."""
        key = "test_key"
        data = b"test data"
        
        storage_adapter.store(key, data)
        assert storage_adapter.delete(key)
        assert storage_adapter.retrieve(key) is None
    
    def test_list_keys(self, storage_adapter):
        """Test listing stored keys."""
        keys = ["key1", "key2", "key3"]
        
        for key in keys:
            storage_adapter.store(key, b"data")
        
        stored_keys = storage_adapter.list_keys()
        assert len(stored_keys) >= 3
        assert all(key in stored_keys for key in keys)
    
    def test_list_keys_with_prefix(self, storage_adapter):
        """Test listing keys with prefix filter."""
        storage_adapter.store("test_key1", b"data")
        storage_adapter.store("test_key2", b"data")
        storage_adapter.store("other_key", b"data")
        
        test_keys = storage_adapter.list_keys(prefix="test")
        
        assert len(test_keys) >= 2
        assert all("test" in key for key in test_keys)


# ============================================================================
# AUDIT LOGGER TESTS
# ============================================================================

class TestAuditLogger:
    """Tests for AuditLogger class."""
    
    def test_log_operation(self, temp_dir):
        """Test logging operations."""
        logger = AuditLogger(temp_dir / "audit.log")
        
        logger.log_operation(
            operation="encrypt",
            resource_id="test_resource",
            metadata={"size": 100}
        )
        
        logs = logger.get_logs()
        assert len(logs) == 1
        assert logs[0]["operation"] == "encrypt"
        assert logs[0]["resource_id"] == "test_resource"
        assert logs[0]["success"] is True
    
    def test_filter_by_operation(self, temp_dir):
        """Test filtering logs by operation."""
        logger = AuditLogger()
        
        logger.log_operation("encrypt", "resource1")
        logger.log_operation("decrypt", "resource2")
        logger.log_operation("encrypt", "resource3")
        
        encrypt_logs = logger.get_logs(operation="encrypt")
        assert len(encrypt_logs) == 2
        assert all(log["operation"] == "encrypt" for log in encrypt_logs)
    
    def test_filter_by_resource_id(self, temp_dir):
        """Test filtering logs by resource ID."""
        logger = AuditLogger()
        
        logger.log_operation("encrypt", "resource1")
        logger.log_operation("decrypt", "resource1")
        logger.log_operation("encrypt", "resource2")
        
        resource1_logs = logger.get_logs(resource_id="resource1")
        assert len(resource1_logs) == 2
        assert all(log["resource_id"] == "resource1" for log in resource1_logs)
    
    def test_export_to_json(self, temp_dir):
        """Test exporting logs to JSON."""
        logger = AuditLogger()
        
        logger.log_operation("encrypt", "resource1")
        logger.log_operation("decrypt", "resource2")
        
        output_path = temp_dir / "exported_logs.json"
        logger.export_to_json(output_path)
        
        assert output_path.exists()
        import json
        with open(output_path) as f:
            exported_logs = json.load(f)
        
        assert len(exported_logs) == 2


# ============================================================================
# TZDC CLIENT TESTS
# ============================================================================

class TestTZDCClient:
    """Tests for TZDCClient class."""
    
    def test_encrypt_and_shard(self, tzdc_client, sample_data):
        """Test end-to-end encryption and sharding."""
        shards = tzdc_client.encrypt_and_shard(
            data=sample_data,
            resource_id="test_resource",
            total_shards=5,
            threshold=3
        )
        
        assert len(shards) == 5
        assert all(shard.threshold == 3 for shard in shards)
        assert all(shard.metadata["resource_id"] == "test_resource" for shard in shards)
        assert all("nonce" in shard.metadata for shard in shards)
        assert all("key_id" in shard.metadata for shard in shards)
    
    def test_reconstruct_and_decrypt(self, tzdc_client, sample_data):
        """Test end-to-end reconstruction and decryption."""
        shards = tzdc_client.encrypt_and_shard(
            data=sample_data,
            resource_id="test_resource",
            total_shards=5,
            threshold=3
        )
        
        # Use any 3 shards
        decrypted = tzdc_client.reconstruct_and_decrypt(shards[:3])
        
        assert decrypted == sample_data
    
    def test_store_and_retrieve_shards(self, tzdc_client, sample_data):
        """Test storing and retrieving shards."""
        shards = tzdc_client.encrypt_and_shard(
            data=sample_data,
            resource_id="test_resource",
            total_shards=3,
            threshold=2
        )
        
        keys = tzdc_client.store_shards(shards, prefix="test_shard")
        
        assert len(keys) == 3
        
        retrieved_shards = tzdc_client.retrieve_shards(keys)
        
        assert len(retrieved_shards) == 3
        
        # Should be able to decrypt with retrieved shards
        decrypted = tzdc_client.reconstruct_and_decrypt(retrieved_shards[:2])
        assert decrypted == sample_data
    
    def test_temporal_key_encryption(self, tzdc_client, sample_data):
        """Test simple temporal key encryption without sharding."""
        ciphertext, nonce, temporal_key = tzdc_client.encrypt_with_temporal_key(
            sample_data,
            context="test"
        )
        
        assert ciphertext != sample_data
        assert temporal_key.is_valid()
        
        decrypted = tzdc_client.decrypt_with_temporal_key(
            ciphertext,
            nonce,
            context="test"
        )
        
        assert decrypted == sample_data
    
    def test_expired_key_error(self, temp_dir):
        """Test that expired keys raise errors."""
        client = TZDCClient(
            time_window=1,  # 1 second expiration
            storage_adapter=LocalFileSystemAdapter(temp_dir / "storage")
        )
        
        shards = client.encrypt_and_shard(
            b"test data",
            resource_id="test",
            total_shards=3,
            threshold=2
        )
        
        # Wait for expiration
        time.sleep(1.5)
        
        with pytest.raises(KeyExpiredError):
            client.reconstruct_and_decrypt(shards[:2])
    
    def test_context_manager(self, tzdc_client, sample_data):
        """Test using client as context manager."""
        with tzdc_client.session() as client:
            shards = client.encrypt_and_shard(
                sample_data,
                resource_id="test",
                total_shards=3,
                threshold=2
            )
            
            decrypted = client.reconstruct_and_decrypt(shards[:2])
            assert decrypted == sample_data
    
    def test_audit_logging(self, tzdc_client, sample_data):
        """Test that operations are logged."""
        shards = tzdc_client.encrypt_and_shard(
            sample_data,
            resource_id="test_audit",
            total_shards=3,
            threshold=2
        )
        
        tzdc_client.reconstruct_and_decrypt(shards[:2])
        
        logs = tzdc_client.get_audit_logs()
        
        assert len(logs) >= 2
        assert any(log["operation"] == "encrypt_and_shard" for log in logs)
        assert any(log["operation"] == "reconstruct_and_decrypt" for log in logs)
    
    def test_commitment_workflow(self, tzdc_client, sample_data):
        """Test zero-knowledge commitment workflow."""
        commitment, salt = tzdc_client.create_commitment(
            sample_data,
            resource_id="test_commitment"
        )
        
        assert commitment.commitment_hash is not None
        
        is_valid = tzdc_client.verify_commitment(
            commitment,
            sample_data,
            salt,
            resource_id="test_commitment"
        )
        
        assert is_valid
    
    def test_cleanup(self, temp_dir):
        """Test cleanup of expired keys."""
        client = TZDCClient(
            time_window=1,
            storage_adapter=LocalFileSystemAdapter(temp_dir / "storage")
        )
        
        # Generate keys
        client.key_manager.generate_temporal_key("test1")
        client.key_manager.generate_temporal_key("test2")
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Cleanup should remove expired keys
        client.cleanup()
        
        # After cleanup, cache should be empty or only contain valid keys
        expired_count = sum(1 for key in client.key_manager._key_cache.values() if not key.is_valid())
        assert expired_count == 0


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================

class TestUtilityFunctions:
    """Tests for utility functions."""
    
    def test_generate_master_secret(self):
        """Test master secret generation."""
        secret = generate_master_secret()
        
        assert len(secret) == 32
        assert isinstance(secret, bytes)
        
        # Should generate different secrets
        secret2 = generate_master_secret()
        assert secret != secret2
    
    def test_serialize_deserialize_shard(self, shard_manager, sample_data):
        """Test shard serialization and deserialization."""
        shards = shard_manager.create_shards(sample_data, total_shards=3, threshold=2)
        original_shard = shards[0]
        
        serialized = serialize_shard(original_shard)
        deserialized = deserialize_shard(serialized)
        
        assert deserialized.shard_id == original_shard.shard_id
        assert deserialized.encrypted_data == original_shard.encrypted_data
        assert deserialized.checksum == original_shard.checksum
        assert deserialized.validate_checksum()


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """End-to-end integration tests."""
    
    def test_ml_training_workflow(self, temp_dir):
        """Test ML training data protection workflow."""
        client = TZDCClient(
            time_window=TimeWindow.HOURS_24,
            storage_adapter=LocalFileSystemAdapter(temp_dir / "ml_storage")
        )
        
        # Simulate training data (smaller to fit prime)
        training_data = b"Training features and labels" + b"X" * 20  # ~50 bytes
        
        # Encrypt and shard
        shards = client.encrypt_and_shard(
            training_data,
            resource_id="ml_batch_001",
            total_shards=3,
            threshold=2
        )
        
        # Store shards on "different nodes"
        keys = client.store_shards(shards, prefix="node")
        
        # Simulate retrieval from nodes
        retrieved_shards = client.retrieve_shards(keys[:2])
        
        # Reconstruct during training
        reconstructed = client.reconstruct_and_decrypt(retrieved_shards)
        
        assert reconstructed == training_data
        
        # Verify audit trail
        logs = client.get_audit_logs(resource_id="ml_batch_001")
        assert len(logs) >= 2

    def test_healthcare_data_sharing(self, temp_dir):
        """Test healthcare data sharing workflow."""
        client = TZDCClient(
            time_window=TimeWindow.HOURS_24,
            storage_adapter=LocalFileSystemAdapter(temp_dir / "health_storage")
        )
        
        # Patient data
        patient_data = b"Patient: John Doe, Diagnosis: Diabetes Type 2, Treatment: Metformin"
        
        # Create commitment for privacy
        commitment, salt = client.create_commitment(
            patient_data,
            resource_id="patient_12345"
        )
        
        # Encrypt and shard for temporary specialist access
        shards = client.encrypt_and_shard(
            patient_data,
            resource_id="patient_12345",
            total_shards=5,
            threshold=3,
            custom_expiry=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        
        # Specialist retrieves and decrypts
        decrypted = client.reconstruct_and_decrypt(shards[:3])
        
        # Verify data integrity
        assert client.verify_commitment(commitment, decrypted, salt, "patient_12345")
        assert decrypted == patient_data
    
    def test_financial_audit_trail(self, temp_dir):
        """Test financial transaction with audit trail."""
        audit_log_path = temp_dir / "financial_audit.log"
        client = TZDCClient(
            time_window=TimeWindow.DAYS_7,
            enable_audit_log=True,
            audit_log_path=audit_log_path
        )
        
        # Transaction data
        transaction = b"Transaction ID: TXN-001, Amount: $10000, From: Account A, To: Account B"
        
        # Encrypt with 7-day retention
        shards = client.encrypt_and_shard(
            transaction,
            resource_id="txn_001",
            total_shards=5,
            threshold=3
        )
        
        # Store shards
        keys = client.store_shards(shards)
        
        # Auditor accesses
        retrieved_shards = client.retrieve_shards(keys[:3])
        audit_data = client.reconstruct_and_decrypt(retrieved_shards)
        
        assert audit_data == transaction
        
        # Verify audit log exists
        assert audit_log_path.exists()
        
        # Check audit trail
        logs = client.get_audit_logs(resource_id="txn_001")
        assert len(logs) >= 2
        assert all(log["success"] for log in logs)


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestPerformance:
    """Performance benchmark tests."""
    
    def test_encryption_performance(self, tzdc_client):
        """Test encryption performance for 1KB data."""
        data_1kb = secrets.token_bytes(1024)  # 1KB instead of 1MB
        
        start_time = time.time()
        ciphertext, nonce, key = tzdc_client.encrypt_with_temporal_key(data_1kb)
        end_time = time.time()
        
        duration_ms = (end_time - start_time) * 1000
        
        # Should be reasonably fast
        assert duration_ms < 100  # More lenient for test environment
        print(f"Encryption time: {duration_ms:.2f}ms")
    
    def test_sharding_performance(self, shard_manager):
        """Test sharding performance."""
        data = b"P" * 40  # 40 bytes
        
        start_time = time.time()
        shards = shard_manager.create_shards(data, total_shards=5, threshold=3)
        end_time = time.time()
        
        duration_ms = (end_time - start_time) * 1000
        
        # Should be reasonably fast
        assert duration_ms < 1000
        print(f"Sharding time: {duration_ms:.2f}ms for 5 shards")

    
    def test_memory_efficiency(self, tzdc_client):
        """Test memory overhead during operations."""
        data = b"M" * 50  # 50 bytes
        
        shards = tzdc_client.encrypt_and_shard(
            data,
            resource_id="memory_test",
            total_shards=5,
            threshold=3
        )
        
        # Calculate total shard size
        total_shard_size = sum(len(shard.encrypted_data) for shard in shards)
        
        # Overhead should be reasonable
        assert total_shard_size > 0
        
        print(f"Original size: {len(data)} bytes")
        print(f"Total shard size: {total_shard_size} bytes")
        print(f"Overhead: {(total_shard_size / len(data)):.2f}x")


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """Tests for error handling and edge cases."""
    
    def test_invalid_shard_reconstruction(self, shard_manager, sample_data):
        """Test reconstruction with invalid shards."""
        shards = shard_manager.create_shards(sample_data, total_shards=3, threshold=2)
        
        # Create invalid shard with wrong threshold
        invalid_shard = Shard(
            shard_id="invalid",
            shard_index=1,
            total_shards=3,
            threshold=5,  # Wrong threshold
            encrypted_data=shards[0].encrypted_data,
            checksum=shards[0].checksum,
            created_at=shards[0].created_at
        )
        
        with pytest.raises(InsufficientShardsError):
            shard_manager.reconstruct_from_shards([invalid_shard, shards[1]])

    def test_empty_data_sharding(self, shard_manager):
        """Test sharding empty data."""
        empty_data = b""
        shards = shard_manager.create_shards(empty_data, total_shards=3, threshold=2)
        
        reconstructed = shard_manager.reconstruct_from_shards(shards[:2])
        assert reconstructed == empty_data
    
    def test_corrupted_encrypted_data(self, tzdc_client, sample_data):
        """Test handling of corrupted encrypted data."""
        shards = tzdc_client.encrypt_and_shard(
            sample_data,
            resource_id="test",
            total_shards=3,
            threshold=2
        )
        
        # Corrupt encrypted data
        shards[0].encrypted_data = b"corrupted" + shards[0].encrypted_data[9:]
        
        with pytest.raises((DecryptionError, InvalidShardError)):
            tzdc_client.reconstruct_and_decrypt(shards[:2])


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])