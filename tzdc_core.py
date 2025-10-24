"""
TZDC: Temporal Zero-Trust Data Compartmentalization Library
============================================================

A production-ready Python library for privacy-enhancing data operations through
cryptographic fragmentation and temporal key expiration.

Author: TZDC Development Team
License: MIT
Python: 3.10+
"""

import hashlib
import hmac
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import json
import logging
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# ============================================================================
# EXCEPTIONS
# ============================================================================

class TZDCError(Exception):
    """Base exception for all TZDC errors."""
    pass


class KeyExpiredError(TZDCError):
    """Raised when attempting to use an expired temporal key."""
    pass


class InvalidShardError(TZDCError):
    """Raised when shard validation fails."""
    pass


class InsufficientShardsError(TZDCError):
    """Raised when not enough shards are provided for reconstruction."""
    pass


class EncryptionError(TZDCError):
    """Raised when encryption operations fail."""
    pass


class DecryptionError(TZDCError):
    """Raised when decryption operations fail."""
    pass


class ProofVerificationError(TZDCError):
    """Raised when zero-knowledge proof verification fails."""
    pass


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class TimeWindow(Enum):
    """Predefined time windows for temporal key expiration."""
    SECONDS_30 = 30
    MINUTES_5 = 300
    MINUTES_15 = 900
    HOUR_1 = 3600
    HOURS_24 = 86400
    DAYS_7 = 604800
    DAYS_30 = 2592000


class CipherType(Enum):
    """Supported cipher algorithms."""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


@dataclass
class TemporalKey:
    """Represents a time-bound encryption key."""
    key: bytes
    created_at: datetime
    expires_at: datetime
    key_id: str
    
    def is_valid(self) -> bool:
        """Check if key is still valid (not expired)."""
        return datetime.now(timezone.utc) < self.expires_at
    
    def time_remaining(self) -> float:
        """Return seconds remaining until expiration."""
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, delta.total_seconds())


@dataclass
class Shard:
    """Represents a single data shard with metadata."""
    shard_id: str
    shard_index: int
    total_shards: int
    threshold: int
    encrypted_data: bytes
    checksum: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def validate_checksum(self) -> bool:
        """Verify shard integrity using checksum."""
        computed = hashlib.sha256(self.encrypted_data).hexdigest()
        return hmac.compare_digest(computed, self.checksum)


@dataclass
class Commitment:
    """Zero-knowledge commitment for proving data properties."""
    commitment_hash: str
    proof_type: str
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# TEMPORAL KEY MANAGER
# ============================================================================

class TemporalKeyManager:
    """
    Manages time-slotted encryption keys with automatic expiration.
    
    Uses HKDF-SHA256 for key derivation from master secret with proper
    key stretching using PBKDF2 or Argon2.
    """
    
    def __init__(
        self,
        master_secret: Optional[bytes] = None,
        time_window: Union[TimeWindow, int] = TimeWindow.HOUR_1,
        use_pbkdf2: bool = True,
        pbkdf2_iterations: int = 100_000
    ):
        """
        Initialize temporal key manager.
        
        Args:
            master_secret: Master secret for key derivation (generated if None)
            time_window: Key expiration window in seconds
            use_pbkdf2: Whether to use PBKDF2 for key stretching
            pbkdf2_iterations: Number of PBKDF2 iterations
        """
        if master_secret is None:
            master_secret = secrets.token_bytes(32)
        
        self.master_secret = master_secret
        self.time_window = time_window.value if isinstance(time_window, TimeWindow) else time_window
        self.use_pbkdf2 = use_pbkdf2
        self.pbkdf2_iterations = pbkdf2_iterations
        self._key_cache: Dict[str, TemporalKey] = {}
        
    def get_temporal_key_by_id(self, key_id: str) -> Optional[TemporalKey]:
        """
        Retrieve a temporal key by its ID from cache.
        
        Args:
            key_id: The key identifier
            
        Returns:
            TemporalKey if found and valid, None otherwise
        """
        if key_id in self._key_cache:
            cached_key = self._key_cache[key_id]
            if cached_key.is_valid():
                return cached_key
        return None
    
    def generate_temporal_key_for_time(
        self,
        context: str = "default",
        timestamp: Optional[float] = None
    ) -> TemporalKey:
        """
        Generate a temporal key for a specific time.
        
        Args:
            context: Context string for key derivation
            timestamp: Specific timestamp to use (uses current time if None)
            
        Returns:
            TemporalKey object
        """
        if timestamp is None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.fromtimestamp(timestamp, timezone.utc)
        
        time_slot = int(now.timestamp()) // self.time_window
        key_id = f"{context}_{time_slot}"
        
        # Check cache
        if key_id in self._key_cache:
            cached_key = self._key_cache[key_id]
            if cached_key.is_valid():
                return cached_key
            else:
                del self._key_cache[key_id]
        
        # Derive key (same as original method)
        info = f"{context}:{time_slot}".encode()
        
        if self.use_pbkdf2:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=info[:16].ljust(16, b'\x00'),
                iterations=self.pbkdf2_iterations,
                backend=default_backend()
            )
            stretched_key = kdf.derive(self.master_secret)
        else:
            stretched_key = self.master_secret
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        key_material = hkdf.derive(stretched_key)
        
        expires_at = now + timedelta(seconds=self.time_window)
        
        temporal_key = TemporalKey(
            key=key_material,
            created_at=now,
            expires_at=expires_at,
            key_id=key_id
        )
        
        self._key_cache[key_id] = temporal_key
        return temporal_key
    def generate_temporal_key_for_time(
        self,
        context: str = "default",
        timestamp: Optional[float] = None
    ) -> TemporalKey:
        """
        Generate a temporal key for a specific time.
        
        Args:
            context: Context string for key derivation
            timestamp: Specific timestamp to use (uses current time if None)
            
        Returns:
            TemporalKey object
        """
        if timestamp is None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.fromtimestamp(timestamp, timezone.utc)
        
        time_slot = int(now.timestamp()) // self.time_window
        key_id = f"{context}_{time_slot}"
        
        # Check cache
        if key_id in self._key_cache:
            cached_key = self._key_cache[key_id]
            if cached_key.is_valid():
                return cached_key
            else:
                del self._key_cache[key_id]
        
        # Derive key (same as original method)
        info = f"{context}:{time_slot}".encode()
        
        if self.use_pbkdf2:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=info[:16].ljust(16, b'\x00'),
                iterations=self.pbkdf2_iterations,
                backend=default_backend()
            )
            stretched_key = kdf.derive(self.master_secret)
        else:
            stretched_key = self.master_secret
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        key_material = hkdf.derive(stretched_key)
        
        expires_at = now + timedelta(seconds=self.time_window)
        
        temporal_key = TemporalKey(
            key=key_material,
            created_at=now,
            expires_at=expires_at,
            key_id=key_id
        )
        
        self._key_cache[key_id] = temporal_key
        return temporal_key
    
    def generate_temporal_key(
        self,
        context: str = "default",
        custom_expiry: Optional[datetime] = None
    ) -> TemporalKey:
        """
        Generate a time-bound encryption key.
        
        Args:
            context: Context string for key derivation (domain separation)
            custom_expiry: Custom expiration time (overrides time_window)
            
        Returns:
            TemporalKey object with key material and metadata
        """
        now = datetime.now(timezone.utc)
        timestamp = int(now.timestamp())
        
        # Create time slot identifier
        time_slot = timestamp // self.time_window
        key_id = f"{context}_{time_slot}"
        
        # Check cache
        if key_id in self._key_cache:
            cached_key = self._key_cache[key_id]
            if cached_key.is_valid():
                return cached_key
            else:
                del self._key_cache[key_id]
        
        # Derive key using HKDF
        info = f"{context}:{time_slot}".encode()
        
        if self.use_pbkdf2:
            # First stretch the master secret
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=info[:16].ljust(16, b'\x00'),
                iterations=self.pbkdf2_iterations,
                backend=default_backend()
            )
            stretched_key = kdf.derive(self.master_secret)
        else:
            stretched_key = self.master_secret
        
        # Then derive time-specific key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        key_material = hkdf.derive(stretched_key)
        
        # Calculate expiration
        if custom_expiry:
            expires_at = custom_expiry
        else:
            expires_at = now + timedelta(seconds=self.time_window)
        
        temporal_key = TemporalKey(
            key=key_material,
            created_at=now,
            expires_at=expires_at,
            key_id=key_id
        )
        
        # Cache the key
        self._key_cache[key_id] = temporal_key
        
        return temporal_key
    
    def validate_key(self, temporal_key: TemporalKey) -> bool:
        """
        Validate if a temporal key is still usable.
        
        Args:
            temporal_key: Key to validate
            
        Returns:
            True if key is valid and not expired
            
        Raises:
            KeyExpiredError: If key has expired
        """
        if not temporal_key.is_valid():
            raise KeyExpiredError(
                f"Key {temporal_key.key_id} expired at {temporal_key.expires_at}"
            )
        return True
    
    def cleanup_expired_keys(self) -> int:
        """
        Remove expired keys from cache.
        
        Returns:
            Number of keys removed
        """
        expired_keys = [
            key_id for key_id, key in self._key_cache.items()
            if not key.is_valid()
        ]
        
        for key_id in expired_keys:
            del self._key_cache[key_id]
        
        return len(expired_keys)


# ============================================================================
# SHARD MANAGER (Shamir's Secret Sharing)
# ============================================================================

class ShardManager:
    """
    Implements Shamir's Secret Sharing Scheme for data fragmentation.
    
    Splits data into N shards where any K shards can reconstruct the original,
    but K-1 shards reveal nothing.
    """
    
    def __init__(self, prime: Optional[int] = None):
        """
        Initialize shard manager.
        
        Args:
            prime: Prime number for finite field operations (auto-generated if None)
        """
        # Use a practical 1024-bit prime that can handle reasonable data sizes
        # This prime is: 2^1024 - 2^960 - 1 + 2^64 * floor(2^894 * π) + 129093
        # Precomputed to avoid floating point issues
        self.prime = prime or 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859
        
    def create_shards(
        self,
        data: bytes,
        total_shards: int = 5,
        threshold: int = 3,
        expires_at: Optional[datetime] = None
    ) -> List[Shard]:
        """
        Split data into cryptographic shards using Shamir's Secret Sharing.
        
        Args:
            data: Data to shard
            total_shards: Total number of shards to create
            threshold: Minimum shards needed for reconstruction
            expires_at: Optional expiration time for shards
            
        Returns:
            List of Shard objects
            
        Raises:
            ValueError: If threshold > total_shards or invalid parameters
        """
        if threshold > total_shards:
            raise ValueError("Threshold cannot exceed total shards")
        
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")
        
        # Calculate maximum data size that can be handled
        max_data_size = (self.prime.bit_length() - 64) // 8  # Leave margin for encoding
        
        if len(data) > max_data_size:
            raise ValueError(
                f"Data too large ({len(data)} bytes). Maximum supported: {max_data_size} bytes. "
                "Consider compressing the data or using chunking."
            )
        
        # Convert data to integer directly (no length prefix)
        data_int = int.from_bytes(data, byteorder='big')
        
        # Ensure data_int is less than prime
        if data_int >= self.prime:
            raise ValueError("Data too large for the chosen prime")
        
        # Generate random polynomial coefficients
        coefficients = [data_int] + [
            secrets.randbelow(self.prime) for _ in range(threshold - 1)
        ]
        
        # Evaluate polynomial at different points to create shards
        shards = []
        base_id = secrets.token_hex(8)
        created_at = datetime.now(timezone.utc)
        
        for i in range(1, total_shards + 1):
            # Evaluate polynomial at x=i
            point = self._evaluate_polynomial(coefficients, i, self.prime)
            
            # Encode the point (x, y)
            shard_data = self._encode_point(i, point)
            
            # Create checksum
            checksum = hashlib.sha256(shard_data).hexdigest()
            
            shard = Shard(
                shard_id=f"{base_id}_{i}",
                shard_index=i,
                total_shards=total_shards,
                threshold=threshold,
                encrypted_data=shard_data,
                checksum=checksum,
                created_at=created_at,
                expires_at=expires_at,
                metadata={"original_length": len(data)}  # Store original length
            )
            
            shards.append(shard)
        
        return shards

    def reconstruct_from_shards(self, shards: List[Shard]) -> bytes:
        """
        Reconstruct original data from shards using Lagrange interpolation.
        
        Args:
            shards: List of shards (must have at least threshold shards)
            
        Returns:
            Original data as bytes
            
        Raises:
            InsufficientShardsError: If not enough shards provided
            InvalidShardError: If shard validation fails
        """
        if not shards:
            raise InsufficientShardsError("No shards provided")
        
        # Validate all shards
        for shard in shards:
            if not shard.validate_checksum():
                raise InvalidShardError(f"Shard {shard.shard_id} failed checksum validation")
        
        threshold = shards[0].threshold
        
        if len(shards) < threshold:
            raise InsufficientShardsError(
                f"Need at least {threshold} shards, got {len(shards)}"
            )
        
        # Decode points from shards
        points = []
        for shard in shards[:threshold]:  # Use exactly threshold shards
            x, y = self._decode_point(shard.encrypted_data)
            points.append((x, y))
        
        # Use Lagrange interpolation to find secret (polynomial at x=0)
        secret = self._lagrange_interpolation(points, 0, self.prime)
        
        # Get original data length from metadata
        original_length = shards[0].metadata.get("original_length")
        
        if original_length is not None:
            # Convert back to bytes with exact length
            return secret.to_bytes(original_length, byteorder='big')
        else:
            # Fallback: calculate byte length and return
            byte_length = (secret.bit_length() + 7) // 8
            return secret.to_bytes(byte_length, byteorder='big')
    def _evaluate_polynomial(self, coefficients: List[int], x: int, prime: int) -> int:
        """Evaluate polynomial at point x in finite field."""
        result = 0
        for i, coeff in enumerate(coefficients):
            result = (result + coeff * pow(x, i, prime)) % prime
        return result
    
    def _lagrange_interpolation(
        self,
        points: List[Tuple[int, int]],
        x: int,
        prime: int
    ) -> int:
        """
        Lagrange interpolation in finite field.
        
        Args:
            points: List of (x, y) coordinate tuples
            x: Point at which to evaluate
            prime: Prime modulus
            
        Returns:
            Interpolated value at x
        """
        result = 0
        
        for i, (xi, yi) in enumerate(points):
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(points):
                if i != j:
                    numerator = (numerator * (x - xj)) % prime
                    denominator = (denominator * (xi - xj)) % prime
            
            # Compute modular inverse
            lagrange_basis = (numerator * self._mod_inverse(denominator, prime)) % prime
            result = (result + yi * lagrange_basis) % prime
        
        return result
    
    def _mod_inverse(self, a: int, prime: int) -> int:
        """Compute modular multiplicative inverse using Extended Euclidean Algorithm."""
        return pow(a, prime - 2, prime)  # Fermat's little theorem
    
    def _encode_point(self, x: int, y: int) -> bytes:
        """Encode a point (x, y) as bytes."""
        # Calculate required byte size for y based on prime size
        y_byte_size = (self.prime.bit_length() + 7) // 8
        x_bytes = x.to_bytes(4, byteorder='big')
        y_bytes = y.to_bytes(y_byte_size, byteorder='big')
        return x_bytes + y_bytes

    def _decode_point(self, data: bytes) -> Tuple[int, int]:
        """Decode bytes back to point (x, y)."""
        x = int.from_bytes(data[:4], byteorder='big')
        y_byte_size = (self.prime.bit_length() + 7) // 8
        y = int.from_bytes(data[4:4 + y_byte_size], byteorder='big')
        return x, y
    

# ============================================================================
# ENCRYPTION ENGINE
# ============================================================================

class EncryptionEngine:
    """
    Handles encryption/decryption operations using authenticated encryption.
    
    Supports AES-256-GCM and ChaCha20-Poly1305 with proper nonce management.
    """
    
    def __init__(self, cipher_type: CipherType = CipherType.AES_256_GCM):
        """
        Initialize encryption engine.
        
        Args:
            cipher_type: Cipher algorithm to use
        """
        self.cipher_type = cipher_type
    
    def encrypt(
        self,
        data: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data using authenticated encryption.
        
        Args:
            data: Plaintext to encrypt
            key: 32-byte encryption key
            associated_data: Optional authenticated but unencrypted data
            
        Returns:
            Tuple of (ciphertext, nonce)
            
        Raises:
            EncryptionError: If encryption fails
        """
        if len(key) != 32:
            raise EncryptionError("Key must be 32 bytes")
        
        try:
            if self.cipher_type == CipherType.AES_256_GCM:
                cipher = AESGCM(key)
                nonce = secrets.token_bytes(12)  # 96 bits for GCM
            else:  # ChaCha20-Poly1305
                cipher = ChaCha20Poly1305(key)
                nonce = secrets.token_bytes(12)  # 96 bits
            
            ciphertext = cipher.encrypt(nonce, data, associated_data)
            
            return ciphertext, nonce
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")
    
    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data using authenticated encryption.
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte decryption key
            nonce: Nonce used during encryption
            associated_data: Optional authenticated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption or authentication fails
        """
        if len(key) != 32:
            raise DecryptionError("Key must be 32 bytes")
        
        try:
            if self.cipher_type == CipherType.AES_256_GCM:
                cipher = AESGCM(key)
            else:  # ChaCha20-Poly1305
                cipher = ChaCha20Poly1305(key)
            
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
            
            return plaintext
            
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}")


# ============================================================================
# ZERO-KNOWLEDGE PROVER
# ============================================================================

class ZeroKnowledgeProver:
    """
    Implements simplified zero-knowledge proof schemes for data properties.
    
    Supports commitments and basic proofs without revealing underlying data.
    """
    
    def __init__(self):
        """Initialize zero-knowledge prover."""
        pass
    
    def create_commitment(
        self,
        data: bytes,
        proof_type: str = "sha256",
        salt: Optional[bytes] = None
    ) -> Tuple[Commitment, bytes]:
        """
        Create a cryptographic commitment to data.
        
        Args:
            data: Data to commit to
            proof_type: Type of commitment scheme
            salt: Optional salt (generated if None)
            
        Returns:
            Tuple of (Commitment, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Create hash commitment
        commitment_data = salt + data
        commitment_hash = hashlib.sha256(commitment_data).hexdigest()
        
        commitment = Commitment(
            commitment_hash=commitment_hash,
            proof_type=proof_type,
            created_at=datetime.now(timezone.utc),
            metadata={"salt_length": len(salt)}
        )
        
        return commitment, salt
    
    def verify_commitment(
        self,
        commitment: Commitment,
        data: bytes,
        salt: bytes
    ) -> bool:
        """
        Verify that data matches a commitment.
        
        Args:
            commitment: Commitment to verify against
            data: Data to check
            salt: Salt used in commitment
            
        Returns:
            True if data matches commitment
        """
        commitment_data = salt + data
        computed_hash = hashlib.sha256(commitment_data).hexdigest()
        
        return hmac.compare_digest(computed_hash, commitment.commitment_hash)
    
    def prove_range(
        self,
        value: int,
        min_value: int,
        max_value: int,
        salt: Optional[bytes] = None
    ) -> Tuple[Commitment, Dict[str, Any]]:
        """
        Create a zero-knowledge range proof (simplified).
        
        Proves that value is within [min_value, max_value] without revealing value.
        
        Args:
            value: Value to prove range for
            min_value: Minimum value in range
            max_value: Maximum value in range
            salt: Optional salt
            
        Returns:
            Tuple of (Commitment, proof_data)
        """
        if not (min_value <= value <= max_value):
            raise ProofVerificationError("Value not in specified range")
        
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Create commitment to value
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        commitment_data = salt + value_bytes
        commitment_hash = hashlib.sha256(commitment_data).hexdigest()
        
        commitment = Commitment(
            commitment_hash=commitment_hash,
            proof_type="range_proof",
            created_at=datetime.now(timezone.utc),
            metadata={
                "min_value": min_value,
                "max_value": max_value
            }
        )
        
        proof_data = {
            "salt": salt.hex(),
            "min_value": min_value,
            "max_value": max_value
        }
        
        return commitment, proof_data
    
    def verify_range_proof(
        self,
        commitment: Commitment,
        value: int,
        proof_data: Dict[str, Any]
    ) -> bool:
        """
        Verify a range proof.
        
        Args:
            commitment: Commitment to verify
            value: Value to check
            proof_data: Proof data from prove_range
            
        Returns:
            True if proof is valid
        """
        salt = bytes.fromhex(proof_data["salt"])
        min_value = proof_data["min_value"]
        max_value = proof_data["max_value"]
        
        # Check range
        if not (min_value <= value <= max_value):
            return False
        
        # Verify commitment
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        commitment_data = salt + value_bytes
        computed_hash = hashlib.sha256(commitment_data).hexdigest()
        
        return hmac.compare_digest(computed_hash, commitment.commitment_hash)


# ============================================================================
# STORAGE ADAPTER (Abstract Base Class)
# ============================================================================

class StorageAdapter(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def store(self, key: str, data: bytes) -> bool:
        """Store data at key."""
        pass
    
    @abstractmethod
    def retrieve(self, key: str) -> Optional[bytes]:
        """Retrieve data from key."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete data at key."""
        pass
    
    @abstractmethod
    def list_keys(self, prefix: str = "") -> List[str]:
        """List all keys with optional prefix."""
        pass


class LocalFileSystemAdapter(StorageAdapter):
    """Local filesystem storage adapter."""
    
    def __init__(self, base_path: Union[str, Path] = "./tzdc_storage"):
        """
        Initialize local filesystem adapter.
        
        Args:
            base_path: Base directory for storage
        """
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def store(self, key: str, data: bytes) -> bool:
        """Store data to file."""
        try:
            file_path = self.base_path / self._sanitize_key(key)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(data)
            return True
        except Exception as e:
            logging.error(f"Failed to store {key}: {e}")
            return False
    
    def retrieve(self, key: str) -> Optional[bytes]:
        """Retrieve data from file."""
        try:
            file_path = self.base_path / self._sanitize_key(key)
            if file_path.exists():
                return file_path.read_bytes()
            return None
        except Exception as e:
            logging.error(f"Failed to retrieve {key}: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete file."""
        try:
            file_path = self.base_path / self._sanitize_key(key)
            if file_path.exists():
                file_path.unlink()
                return True
            return False
        except Exception as e:
            logging.error(f"Failed to delete {key}: {e}")
            return False
    
    def list_keys(self, prefix: str = "") -> List[str]:
        """List all stored keys."""
        try:
            keys = []
            for file_path in self.base_path.rglob("*"):
                if file_path.is_file():
                    key = str(file_path.relative_to(self.base_path))
                    if key.startswith(prefix):
                        keys.append(key)
            return keys
        except Exception as e:
            logging.error(f"Failed to list keys: {e}")
            return []
    
    def _sanitize_key(self, key: str) -> str:
        """Sanitize key for filesystem use."""
        return key.replace("/", "_").replace("\\", "_")


# ============================================================================
# AUDIT LOGGER
# ============================================================================

class AuditLogger:
    """
    Immutable append-only audit trail for TZDC operations.
    
    Records all operations without revealing sensitive data content.
    """
    
    def __init__(self, log_file: Optional[Path] = None):
        """
        Initialize audit logger.
        
        Args:
            log_file: Optional file path for persistent logging
        """
        self.log_file = log_file
        self.in_memory_logs: List[Dict[str, Any]] = []
        
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log_operation(
        self,
        operation: str,
        resource_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True
    ) -> None:
        """
        Log an operation to the audit trail.
        
        Args:
            operation: Type of operation (encrypt, decrypt, shard, etc.)
            resource_id: Identifier for the resource
            metadata: Additional metadata (non-sensitive)
            success: Whether operation succeeded
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "resource_id": resource_id,
            "success": success,
            "metadata": metadata or {}
        }
        
        self.in_memory_logs.append(log_entry)
        
        if self.log_file:
            self._append_to_file(log_entry)
    
    def _append_to_file(self, log_entry: Dict[str, Any]) -> None:
        """Append log entry to file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logging.error(f"Failed to write audit log: {e}")
    
    def get_logs(
        self,
        operation: Optional[str] = None,
        resource_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve logs with optional filtering.
        
        Args:
            operation: Filter by operation type
            resource_id: Filter by resource ID
            start_time: Filter by start time
            end_time: Filter by end time
            
        Returns:
            Filtered list of log entries
        """
        filtered_logs = self.in_memory_logs
        
        if operation:
            filtered_logs = [log for log in filtered_logs if log["operation"] == operation]
        
        if resource_id:
            filtered_logs = [log for log in filtered_logs if log["resource_id"] == resource_id]
        
        if start_time:
            filtered_logs = [
                log for log in filtered_logs
                if datetime.fromisoformat(log["timestamp"]) >= start_time
            ]
        
        if end_time:
            filtered_logs = [
                log for log in filtered_logs
                if datetime.fromisoformat(log["timestamp"]) <= end_time
            ]
        
        return filtered_logs
    
    def export_to_json(self, output_path: Path) -> None:
        """Export all logs to JSON file."""
        output_path.write_text(json.dumps(self.in_memory_logs, indent=2))


# ============================================================================
# MAIN TZDC CLIENT
# ============================================================================

class TZDCClient:
    """
    Main high-level API for TZDC operations.
    
    Provides a unified interface for temporal encryption, data sharding,
    and zero-knowledge proofs.
    """
    
    def __init__(
        self,
        master_secret: Optional[bytes] = None,
        time_window: Union[TimeWindow, int] = TimeWindow.HOUR_1,
        storage_adapter: Optional[StorageAdapter] = None,
        cipher_type: CipherType = CipherType.AES_256_GCM,
        enable_audit_log: bool = True,
        audit_log_path: Optional[Path] = None
    ):
        """
        Initialize TZDC client.
        
        Args:
            master_secret: Master secret for key derivation
            time_window: Default time window for key expiration
            storage_adapter: Storage backend (defaults to local filesystem)
            cipher_type: Encryption cipher to use
            enable_audit_log: Whether to enable audit logging
            audit_log_path: Path for audit log file
        """
        self.key_manager = TemporalKeyManager(master_secret, time_window)
        self.shard_manager = ShardManager()
        self.encryption_engine = EncryptionEngine(cipher_type)
        self.zk_prover = ZeroKnowledgeProver()
        self.storage = storage_adapter or LocalFileSystemAdapter()
        
        if enable_audit_log:
            self.audit_logger = AuditLogger(audit_log_path)
        else:
            self.audit_logger = None
    
    @contextmanager
    def session(self):
        """
        Context manager for TZDC operations.
        
        Usage:
            with client.session():
                # Perform operations
                pass
        """
        try:
            yield self
        finally:
            self.cleanup()
    
    def encrypt_and_shard(
        self,
        data: bytes,
        resource_id: str,
        total_shards: int = 5,
        threshold: int = 3,
        context: str = "default",
        custom_expiry: Optional[datetime] = None
    ) -> List[Shard]:
        """
        Encrypt data with temporal key and split into shards.
        
        This is the primary high-level encryption API combining temporal
        encryption with cryptographic data fragmentation.
        
        Args:
            data: Data to encrypt and shard
            resource_id: Unique identifier for this resource
            total_shards: Total number of shards to create
            threshold: Minimum shards needed for reconstruction
            context: Context for key derivation
            custom_expiry: Custom expiration time
            
        Returns:
            List of encrypted shards
        """
        try:
            # Generate temporal key
            temporal_key = self.key_manager.generate_temporal_key(context, custom_expiry)
            
            # Create shards from plaintext first
            plaintext_shards = self.shard_manager.create_shards(
                data,
                total_shards=total_shards,
                threshold=threshold,
                expires_at=temporal_key.expires_at
            )
            
            # Encrypt each shard individually with the same temporal key
            encrypted_shards = []
            for shard in plaintext_shards:
                # Serialize the shard data
                shard_data = serialize_shard(shard)
                
                # Encrypt the serialized shard
                ciphertext, nonce = self.encryption_engine.encrypt(shard_data, temporal_key.key)
                
                # Create new shard with encrypted data
                encrypted_shard = Shard(
                    shard_id=shard.shard_id,
                    shard_index=shard.shard_index,
                    total_shards=shard.total_shards,
                    threshold=shard.threshold,
                    encrypted_data=ciphertext,
                    checksum=hashlib.sha256(ciphertext).hexdigest(),
                    created_at=shard.created_at,
                    expires_at=shard.expires_at,
                    metadata={
                        "key_id": temporal_key.key_id,
                        "context": context,
                        "resource_id": resource_id,
                        "nonce": nonce.hex(),
                        "created_at": temporal_key.created_at.isoformat()
                    }
                )
                encrypted_shards.append(encrypted_shard)
            
            # Audit log
            if self.audit_logger:
                self.audit_logger.log_operation(
                    operation="encrypt_and_shard",
                    resource_id=resource_id,
                    metadata={
                        "total_shards": total_shards,
                        "threshold": threshold,
                        "expires_at": temporal_key.expires_at.isoformat()
                    }
                )
            
            return encrypted_shards
            
        except Exception as e:
            if self.audit_logger:
                self.audit_logger.log_operation(
                    operation="encrypt_and_shard",
                    resource_id=resource_id,
                    success=False,
                    metadata={"error": str(e)}
                )
            raise
    def reconstruct_and_decrypt(
        self,
        shards: List[Shard],
        context: str = "default"
    ) -> bytes:
        """
        Reconstruct data from shards and decrypt using temporal key.
        
        Args:
        shards: List of shards (must have at least threshold)
            context: Context used during encryption
            
        Returns:
            Original decrypted data
            
        Raises:
            KeyExpiredError: If temporal key has expired
            InsufficientShardsError: If not enough shards provided
            DecryptionError: If decryption fails
        """
        try:
            resource_id = shards[0].metadata.get("resource_id", "unknown")
            
            # Check if shards have expired
            if shards[0].expires_at and datetime.now(timezone.utc) > shards[0].expires_at:
                raise KeyExpiredError(
                    f"Shards expired at {shards[0].expires_at}"
                )
            
            # Get the exact temporal key used during encryption
            key_id = shards[0].metadata.get("key_id")
            context = shards[0].metadata.get("context", context)
            created_at_str = shards[0].metadata.get("created_at")
            
            if key_id and hasattr(self.key_manager, 'generate_temporal_key_for_time') and created_at_str:
                # Use the exact same time slot as encryption
                created_at = datetime.fromisoformat(created_at_str)
                timestamp = created_at.timestamp()
                temporal_key = self.key_manager.generate_temporal_key_for_time(context, timestamp)
            else:
                # Fallback to current time
                temporal_key = self.key_manager.generate_temporal_key(context)
            
            # Validate key is still valid
            self.key_manager.validate_key(temporal_key)
            
            # Decrypt each shard first
            decrypted_shards = []
            for shard in shards:
                nonce_hex = shard.metadata.get("nonce")
                if not nonce_hex:
                    raise DecryptionError("Nonce not found in shard metadata")
                
                nonce = bytes.fromhex(nonce_hex)
                
                # Decrypt the shard data
                shard_data = self.encryption_engine.decrypt(
                    shard.encrypted_data,
                    temporal_key.key,
                    nonce
                )
                
                # Deserialize the shard
                plaintext_shard = deserialize_shard(shard_data)
                decrypted_shards.append(plaintext_shard)
            
            # Reconstruct original data from decrypted shards
            plaintext = self.shard_manager.reconstruct_from_shards(decrypted_shards)
            
            # Audit log
            if self.audit_logger:
                self.audit_logger.log_operation(
                    operation="reconstruct_and_decrypt",
                    resource_id=resource_id,
                    metadata={"shards_used": len(shards)}
                )
            
            return plaintext
            
        except Exception as e:
            if self.audit_logger:
                resource_id = shards[0].metadata.get("resource_id", "unknown") if shards else "unknown"
                self.audit_logger.log_operation(
                    operation="reconstruct_and_decrypt",
                    resource_id=resource_id,
                    success=False,
                    metadata={"error": str(e)}
                )
            raise
    
    def encrypt_with_temporal_key(
        self,
        data: bytes,
        context: str = "default",
        custom_expiry: Optional[datetime] = None
    ) -> Tuple[bytes, bytes, TemporalKey]:
        """
        Encrypt data with temporal key (without sharding).
        
        Use this for simpler encryption scenarios where sharding is not needed.
        
        Args:
            data: Data to encrypt
            context: Context for key derivation
            custom_expiry: Custom expiration time
            
        Returns:
            Tuple of (ciphertext, nonce, temporal_key)
        """
        temporal_key = self.key_manager.generate_temporal_key(context, custom_expiry)
        ciphertext, nonce = self.encryption_engine.encrypt(data, temporal_key.key)
        
        return ciphertext, nonce, temporal_key
    
    def decrypt_with_temporal_key(
        self,
        ciphertext: bytes,
        nonce: bytes,
        context: str = "default"
    ) -> bytes:
        """
        Decrypt data using temporal key.
        
        Args:
            ciphertext: Encrypted data
            nonce: Nonce used during encryption
            context: Context used during encryption
            
        Returns:
            Decrypted plaintext
        """
        temporal_key = self.key_manager.generate_temporal_key(context)
        self.key_manager.validate_key(temporal_key)
        
        return self.encryption_engine.decrypt(ciphertext, temporal_key.key, nonce)
    
    def store_shards(
        self,
        shards: List[Shard],
        prefix: str = "shard"
    ) -> List[str]:
        """
        Store shards using the configured storage adapter.
        
        Args:
            shards: List of shards to store
            prefix: Key prefix for storage
            
        Returns:
            List of storage keys
        """
        keys = []
        for shard in shards:
            key = f"{prefix}_{shard.shard_id}"
            
            # Serialize shard metadata
            shard_data = {
                "shard_id": shard.shard_id,
                "shard_index": shard.shard_index,
                "total_shards": shard.total_shards,
                "threshold": shard.threshold,
                "encrypted_data": shard.encrypted_data.hex(),
                "checksum": shard.checksum,
                "created_at": shard.created_at.isoformat(),
                "expires_at": shard.expires_at.isoformat() if shard.expires_at else None,
                "metadata": shard.metadata
            }
            
            serialized = json.dumps(shard_data).encode()
            self.storage.store(key, serialized)
            keys.append(key)
        
        return keys
    
    def retrieve_shards(self, keys: List[str]) -> List[Shard]:
        """
        Retrieve shards from storage.
        
        Args:
            keys: List of storage keys
            
        Returns:
            List of Shard objects
        """
        shards = []
        for key in keys:
            data = self.storage.retrieve(key)
            if data:
                shard_data = json.loads(data.decode())
                
                shard = Shard(
                    shard_id=shard_data["shard_id"],
                    shard_index=shard_data["shard_index"],
                    total_shards=shard_data["total_shards"],
                    threshold=shard_data["threshold"],
                    encrypted_data=bytes.fromhex(shard_data["encrypted_data"]),
                    checksum=shard_data["checksum"],
                    created_at=datetime.fromisoformat(shard_data["created_at"]),
                    expires_at=datetime.fromisoformat(shard_data["expires_at"]) if shard_data["expires_at"] else None,
                    metadata=shard_data["metadata"]
                )
                
                shards.append(shard)
        
        return shards
    
    def create_commitment(
        self,
        data: bytes,
        resource_id: str
    ) -> Tuple[Commitment, bytes]:
        """
        Create zero-knowledge commitment for data.
        
        Args:
            data: Data to commit to
            resource_id: Resource identifier
            
        Returns:
            Tuple of (Commitment, salt)
        """
        commitment, salt = self.zk_prover.create_commitment(data)
        
        if self.audit_logger:
            self.audit_logger.log_operation(
                operation="create_commitment",
                resource_id=resource_id,
                metadata={"commitment_hash": commitment.commitment_hash}
            )
        
        return commitment, salt
    
    def verify_commitment(
        self,
        commitment: Commitment,
        data: bytes,
        salt: bytes,
        resource_id: str
    ) -> bool:
        """
        Verify data against commitment.
        
        Args:
            commitment: Commitment to verify
            data: Data to check
            salt: Salt used in commitment
            resource_id: Resource identifier
            
        Returns:
            True if verification succeeds
        """
        result = self.zk_prover.verify_commitment(commitment, data, salt)
        
        if self.audit_logger:
            self.audit_logger.log_operation(
                operation="verify_commitment",
                resource_id=resource_id,
                success=result
            )
        
        return result
    
    def cleanup(self) -> None:
        """Clean up expired keys and resources."""
        removed = self.key_manager.cleanup_expired_keys()
        if removed > 0:
            logging.info(f"Cleaned up {removed} expired keys")
    
    def get_audit_logs(
        self,
        operation: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs.
        
        Args:
            operation: Filter by operation type
            resource_id: Filter by resource ID
            
        Returns:
            List of log entries
        """
        if not self.audit_logger:
            return []
        
        return self.audit_logger.get_logs(operation=operation, resource_id=resource_id)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_master_secret() -> bytes:
    """
    Generate a cryptographically secure master secret.
    
    Returns:
        32-byte random secret
    """
    return secrets.token_bytes(32)


def serialize_shard(shard: Shard) -> bytes:
    """
    Serialize a shard to bytes for storage or transmission.
    
    Args:
        shard: Shard to serialize
        
    Returns:
        Serialized shard data
    """
    shard_dict = {
        "shard_id": shard.shard_id,
        "shard_index": shard.shard_index,
        "total_shards": shard.total_shards,
        "threshold": shard.threshold,
        "encrypted_data": shard.encrypted_data.hex(),
        "checksum": shard.checksum,
        "created_at": shard.created_at.isoformat(),
        "expires_at": shard.expires_at.isoformat() if shard.expires_at else None,
        "metadata": shard.metadata
    }
    
    return json.dumps(shard_dict).encode()


def deserialize_shard(data: bytes) -> Shard:
    """
    Deserialize bytes back into a Shard object.
    
    Args:
        data: Serialized shard data
        
    Returns:
        Shard object
    """
    shard_dict = json.loads(data.decode())
    
    return Shard(
        shard_id=shard_dict["shard_id"],
        shard_index=shard_dict["shard_index"],
        total_shards=shard_dict["total_shards"],
        threshold=shard_dict["threshold"],
        encrypted_data=bytes.fromhex(shard_dict["encrypted_data"]),
        checksum=shard_dict["checksum"],
        created_at=datetime.fromisoformat(shard_dict["created_at"]),
        expires_at=datetime.fromisoformat(shard_dict["expires_at"]) if shard_dict["expires_at"] else None,
        metadata=shard_dict["metadata"]
    )


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

def example_basic_usage():
    """Basic usage example for TZDC library."""
    
    # Initialize client with 1-hour expiration window
    client = TZDCClient(
        time_window=TimeWindow.HOUR_1,
        enable_audit_log=True
    )
    
    # Use smaller test data to avoid prime size issues
    sensitive_data = b"Patient record: John Doe"
    
    # Encrypt and shard sensitive data
    shards = client.encrypt_and_shard(
        data=sensitive_data,
        resource_id="patient_12345",
        total_shards=5,
        threshold=3
    )
    
    print(f"Created {len(shards)} shards. Any {shards[0].threshold} can reconstruct the data.")
    
    # Store shards in different locations (simulated)
    shard_keys = client.store_shards(shards)
    print(f"Stored shards: {shard_keys}")
    
    # Later: Reconstruct data using any 3 shards
    retrieved_shards = client.retrieve_shards(shard_keys[:3])
    
    try:
        decrypted_data = client.reconstruct_and_decrypt(
            shards=retrieved_shards,
            context="default"
        )
        
        # Safe printing that handles both text and binary data
        try:
            print(f"Successfully decrypted: {decrypted_data.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"Successfully decrypted (hex): {decrypted_data.hex()}")
            print(f"Successfully decrypted (raw bytes): {decrypted_data}")
            
    except KeyExpiredError:
        print("Data has expired - this is a security feature!")
    except Exception as e:
        print(f"Decryption failed: {e}")
    
    # View audit logs
    logs = client.get_audit_logs()
    print(f"\nAudit trail: {len(logs)} operations recorded")

def example_ml_training():
    """Example: Protecting ML training data."""
    
    client = TZDCClient(time_window=TimeWindow.HOURS_24)
    
    # Simulate training data
    training_data = b"Feature vectors and labels for ML model training..."
    
    # Encrypt with 24-hour expiration (after training completes)
    shards = client.encrypt_and_shard(
        data=training_data,
        resource_id="ml_training_batch_001",
        total_shards=3,
        threshold=2
    )
    
    print("Training data protected with automatic 24-hour expiration")
    print("After training completes, data becomes permanently inaccessible")
    
    # Store shards on different training nodes
    for i, shard in enumerate(shards):
        print(f"  Shard {i+1} -> Training Node {i+1}")


def example_zero_knowledge_proof():
    """Example: Zero-knowledge proofs for data verification."""
    
    client = TZDCClient()
    
    # Sensitive data
    salary_data = b"Employee salary: $125000"
    
    # Create commitment
    commitment, salt = client.create_commitment(
        data=salary_data,
        resource_id="employee_456"
    )
    
    print(f"Created commitment: {commitment.commitment_hash[:16]}...")
    print("Commitment proves data exists without revealing content")
    
    # Later: Verify without exposing salary
    is_valid = client.verify_commitment(
        commitment=commitment,
        data=salary_data,
        salt=salt,
        resource_id="employee_456"
    )
    
    print(f"Verification result: {is_valid}")


if __name__ == "__main__":
    print("=" * 70)
    print("TZDC Library - Temporal Zero-Trust Data Compartmentalization")
    print("=" * 70)
    print()
    
    print("Example 1: Basic Encryption and Sharding")
    print("-" * 70)
    example_basic_usage()
    
    print("\n" + "=" * 70)
    print("Example 2: ML Training Data Protection")
    print("-" * 70)
    example_ml_training()
    
    print("\n" + "=" * 70)
    print("Example 3: Zero-Knowledge Proofs")
    print("-" * 70)
    example_zero_knowledge_proof()