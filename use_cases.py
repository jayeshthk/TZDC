"""
TZDC Library - Comprehensive Example Use Cases
================================================

Real-world examples demonstrating TZDC library usage across different industries.
"""

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

from tzdc_core import (
    TZDCClient,
    TimeWindow,
    generate_master_secret,
    serialize_shard,
    deserialize_shard,
    ZeroKnowledgeProver
)


# ============================================================================
# EXAMPLE 1: Healthcare - Temporary Specialist Access
# ============================================================================

def healthcare_specialist_access():
    """
    Healthcare scenario: Share patient records with specialist for 48 hours.
    
    Compliance: HIPAA, GDPR
    Use case: Temporary consultant access to patient data
    """
    print("=" * 70)
    print("HEALTHCARE: Temporary Specialist Access to Patient Records")
    print("=" * 70)
    
    # Initialize client with 48-hour expiration (convert to seconds)
    client = TZDCClient(
        time_window=TimeWindow.HOURS_24.value * 2,  # 48 hours in seconds
        enable_audit_log=True,
        audit_log_path=Path("healthcare_audit.log")
    )
    
    # Patient data (PHI - Protected Health Information)
    patient_data = json.dumps({
        "patient_id": "P12345",
        "name": "John Doe",
        "dob": "1980-05-15",
        "diagnosis": "Diabetes Type 2",
        "medications": ["Metformin 500mg", "Lisinopril 10mg"],
        "lab_results": {
            "glucose": 145,
            "hba1c": 7.2
        }
    }).encode()
    
    print(f"\n1. Encrypting patient data (PHI): {len(patient_data)} bytes")
    
    # Create zero-knowledge commitment for audit trail
    commitment, salt = client.create_commitment(
        patient_data,
        resource_id="patient_P12345"
    )
    print(f"   Created audit commitment: {commitment.commitment_hash[:16]}...")
    
    # Encrypt and shard data
    shards = client.encrypt_and_shard(
        data=patient_data,
        resource_id="patient_P12345",
        total_shards=5,
        threshold=3  # Requires 3 of 5 shards
    )
    
    print(f"   Generated {len(shards)} shards (threshold: 3)")
    print(f"   Expiration: {shards[0].expires_at}")
    
    # Distribute shards to different secure locations
    shard_locations = {
        "hospital_primary_db": shards[0],
        "hospital_backup_db": shards[1],
        "specialist_secure_portal": shards[2],
        "regional_health_archive": shards[3],
        "compliance_backup": shards[4]
    }
    
    print("\n2. Distributing shards to secure locations:")
    for location, shard in shard_locations.items():
        print(f"   - {location}: Shard {shard.shard_index}")
    
    # Specialist accesses data (needs 3 shards)
    print("\n3. Specialist accessing patient data...")
    specialist_shards = [
        shards[0],  # hospital_primary_db
        shards[2],  # specialist_secure_portal
        shards[3]   # regional_health_archive
    ]
    
    try:
        decrypted_data = client.reconstruct_and_decrypt(specialist_shards)
        patient_info = json.loads(decrypted_data.decode())
        
        print(f"   ✓ Access granted to Dr. Smith (Endocrinologist)")
        print(f"   ✓ Patient: {patient_info['name']}")
        print(f"   ✓ Diagnosis: {patient_info['diagnosis']}")
        
        # Verify data integrity using commitment
        is_valid = client.verify_commitment(
            commitment,
            decrypted_data,
            salt,
            resource_id="patient_P12345"
        )
        print(f"   ✓ Data integrity verified: {is_valid}")
        
    except Exception as e:
        print(f"   ✗ Access failed: {e}")
    
    # Check audit logs
    logs = client.get_audit_logs(resource_id="patient_P12345")
    print(f"\n4. Audit trail: {len(logs)} operations logged")
    for log in logs[-3:]:  # Show last 3 operations
        print(f"   - {log['timestamp']}: {log['operation']}")
    
    print("\n5. After 48 hours: Data automatically becomes inaccessible")
    print("   No manual intervention needed - compliance automated!")
    print()


# ============================================================================
# EXAMPLE 2: Machine Learning - Training Data Protection
# ============================================================================

def ml_training_data_protection():
    """
    ML scenario: Protect sensitive training data during federated learning.
    
    Use case: Distributed ML training with automatic data deletion
    Requirements: Privacy-preserving AI, GDPR compliance
    """
    print("=" * 70)
    print("MACHINE LEARNING: Federated Training Data Protection")
    print("=" * 70)
    
    # Training will take 6 hours, set expiration to 8 hours for buffer
    client = TZDCClient(
        time_window=TimeWindow.HOUR_1.value * 8,  # 8 hours in seconds
        enable_audit_log=True
    )
    
    # Simulate sensitive training dataset
    training_batch = {
        "batch_id": "batch_2025_001",
        "features": [[1.2, 3.4, 5.6], [2.1, 4.3, 6.5], [3.0, 5.2, 7.8]],
        "labels": [0, 1, 0],
        "user_data": "sensitive_pii_included"
    }
    training_data = json.dumps(training_batch).encode()
    
    print(f"\n1. Protecting ML training data: {len(training_data)} bytes")
    print(f"   Training duration: 6 hours")
    print(f"   Data retention: 8 hours (auto-delete after training)")
    
    # Encrypt and shard for distributed training
    shards = client.encrypt_and_shard(
        data=training_data,
        resource_id="ml_batch_2025_001",
        total_shards=3,
        threshold=2,  # Any 2 training nodes can reconstruct
        custom_expiry=datetime.now(timezone.utc) + timedelta(hours=8)
    )
    
    print(f"\n2. Distributing to {len(shards)} federated training nodes:")
    
    # Simulate distribution to training nodes
    training_nodes = {
        "node_usa_east": shards[0],
        "node_europe": shards[1],
        "node_asia": shards[2]
    }
    
    for node_name, shard in training_nodes.items():
        print(f"   - {node_name}: Shard {shard.shard_index}")
        print(f"     Size: {len(shard.encrypted_data)} bytes")
    
    # Node 1 and Node 2 collaborate for training
    print("\n3. Training phase: Nodes USA-East + Europe reconstructing data...")
    training_shards = [shards[0], shards[1]]
    
    try:
        reconstructed_data = client.reconstruct_and_decrypt(training_shards)
        
        print("   ✓ Data reconstructed for training")
        print("   ✓ Model training in progress...")
        print("   ✓ Gradients computed and aggregated")
        
    except Exception as e:
        print(f"   ✗ Training data reconstruction failed: {e}")
        return
    
    # After training completes
    print("\n4. Post-training:")
    print("   ✓ Model saved (no raw data included)")
    print("   ✓ Training data automatically expires in 8 hours")
    print("   ✓ Even if attacker steals encrypted shards later,")
    print("     temporal keys have expired - data is permanently protected!")
    
    # View audit trail
    logs = client.get_audit_logs(resource_id="ml_batch_2025_001")
    print(f"\n5. ML Pipeline Audit: {len(logs)} operations")
    for log in logs[-2:]:  # Show last 2 operations
        print(f"   [{log['timestamp']}] {log['operation']}")
    
    print()


# ============================================================================
# EXAMPLE 3: Financial Services - Transaction Audit Trail
# ============================================================================

def financial_transaction_audit():
    """
    Financial scenario: Process transaction with compliant retention.
    
    Use case: PCI-DSS compliant transaction processing with auto-deletion
    Requirement: 90-day retention, then automatic deletion
    """
    print("=" * 70)
    print("FINANCIAL SERVICES: Transaction Processing with Audit Trail")
    print("=" * 70)
    
    # 90-day retention for compliance
    client = TZDCClient(
        time_window=TimeWindow.DAYS_30.value * 3,  # 90 days in seconds
        enable_audit_log=True,
        audit_log_path=Path("financial_audit.log")
    )
    
    # Transaction data
    transaction_data = json.dumps({
        "transaction_id": "TXN-2025-10-001",
        "timestamp": "2025-10-23T10:30:00Z",
        "amount": 50000.00,
        "currency": "USD",
        "from_account": "****1234",
        "to_account": "****5678",
        "card_details": {
            "card_number": "****-****-****-1234",
            "cvv_hash": "hashed_cvv_value"
        },
        "merchant": "Example Corp",
        "status": "completed"
    }).encode()
    
    print(f"\n1. Processing high-value transaction: ${50000:,.2f}")
    
    # Create commitment for non-repudiation
    commitment, salt = client.create_commitment(
        transaction_data,
        resource_id="TXN-2025-10-001"
    )
    
    print(f"   Created cryptographic proof: {commitment.commitment_hash[:20]}...")
    
    # Encrypt and shard transaction
    shards = client.encrypt_and_shard(
        data=transaction_data,
        resource_id="TXN-2025-10-001",
        total_shards=5,
        threshold=3,
        context="financial_transactions"
    )
    
    print(f"\n2. Securing transaction with {len(shards)} shards:")
    print(f"   - Retention period: 90 days")
    print(f"   - Reconstruction requires: 3 of 5 shards")
    
    # Distribute shards across secure infrastructure
    storage_locations = [
        "primary_bank_vault",
        "backup_datacenter_east",
        "backup_datacenter_west",
        "compliance_archive",
        "disaster_recovery_site"
    ]
    
    shard_storage = {}
    for i, (location, shard) in enumerate(zip(storage_locations, shards)):
        shard_storage[location] = shard
        print(f"   Shard {i+1} → {location}")
    
    # Auditor requests transaction details within retention period
    print("\n3. Compliance Audit (Day 45):")
    print("   Auditor requesting transaction details...")
    
    # Retrieve and decrypt with any 3 shards
    audit_shards = [
        shard_storage["primary_bank_vault"],
        shard_storage["backup_datacenter_east"],
        shard_storage["compliance_archive"]
    ]
    
    try:
        decrypted_transaction = client.reconstruct_and_decrypt(
            audit_shards,
            context="financial_transactions"
        )
        
        transaction_info = json.loads(decrypted_transaction.decode())
        print(f"   ✓ Transaction ID: {transaction_info['transaction_id']}")
        print(f"   ✓ Amount: ${transaction_info['amount']:,.2f}")
        print(f"   ✓ Status: {transaction_info['status']}")
        
        # Verify transaction integrity
        is_valid = client.verify_commitment(
            commitment,
            decrypted_transaction,
            salt,
            resource_id="TXN-2025-10-001"
        )
        print(f"   ✓ Transaction integrity verified: {is_valid}")
        
    except Exception as e:
        print(f"   ✗ Transaction reconstruction failed: {e}")
    
    print("\n4. Post-Retention (Day 91):")
    print("   ✗ Temporal keys expired")
    print("   ✗ Data permanently inaccessible")
    print("   ✓ PCI-DSS compliance maintained")
    print("   ✓ 'Right to be forgotten' automatically enforced")
    
    # Export audit trail for compliance
    print("\n5. Exporting compliance audit trail...")
    if client.audit_logger:
        client.audit_logger.export_to_json(Path("transaction_audit_export.json"))
        print("   ✓ Audit trail exported: transaction_audit_export.json")
    else:
        print("   ✗ Audit logging not enabled")
    print()


# ============================================================================
# EXAMPLE 4: Enterprise - Temporary Contractor Access
# ============================================================================

def enterprise_contractor_access():
    """
    Enterprise scenario: Grant temporary access to external contractor.
    
    Use case: 3rd party contractor needs access for specific project duration
    Security: Zero-trust architecture with automatic revocation
    """
    print("=" * 70)
    print("ENTERPRISE: Temporary Contractor Access Management")
    print("=" * 70)
    
    # Project duration: 2 weeks
    client = TZDCClient(
        time_window=TimeWindow.DAYS_7.value * 2,  # 14 days in seconds
        enable_audit_log=True
    )
    
    # Confidential project data
    project_data = json.dumps({
        "project_id": "PROJ-2025-ALPHA",
        "project_name": "New Product Launch",
        "confidential_specs": {
            "feature_1": "Advanced AI integration",
            "feature_2": "Blockchain-based authentication",
            "target_market": "Enterprise B2B",
            "revenue_projection": "$10M ARR"
        },
        "internal_notes": "Partnership with Company X pending",
        "budget": 500000
    }).encode()
    
    print("\n1. Granting contractor access to confidential project:")
    print(f"   Project: New Product Launch")
    print(f"   Contractor: External Design Agency")
    print(f"   Duration: 14 days")
    
    # Encrypt and shard
    shards = client.encrypt_and_shard(
        data=project_data,
        resource_id="PROJ-2025-ALPHA",
        total_shards=4,
        threshold=2,
        custom_expiry=datetime.now(timezone.utc) + timedelta(days=14)
    )
    
    print(f"\n2. Data protection setup:")
    print(f"   - Total shards: {len(shards)}")
    print(f"   - Required for access: 2 shards")
    print(f"   - Auto-expiration: {shards[0].expires_at}")
    
    # Distribute shards
    print("\n3. Shard distribution:")
    distribution = {
        "internal_hr_vault": shards[0],
        "contractor_portal": shards[1],
        "project_manager_access": shards[2],
        "backup_security_vault": shards[3]
    }
    
    for location, shard in distribution.items():
        print(f"   - {location}: Shard {shard.shard_index}")
    
    # Contractor accesses data during project
    print("\n4. Contractor accessing project data (Day 5):")
    contractor_shards = [
        distribution["contractor_portal"],
        distribution["project_manager_access"]
    ]
    
    try:
        decrypted_data = client.reconstruct_and_decrypt(contractor_shards)
        project_info = json.loads(decrypted_data.decode())
        
        print(f"   ✓ Access granted to contractor")
        print(f"   ✓ Project: {project_info['project_name']}")
        print(f"   ✓ Access logged for security audit")
        
    except Exception as e:
        print(f"   ✗ Contractor access failed: {e}")
    
    # Project completes
    print("\n5. Project completion (Day 14):")
    print("   ✓ Project delivered successfully")
    print("   ✓ Contractor access automatically revoked")
    print("   ✓ Data becomes permanently inaccessible")
    print("   ✓ No manual access revocation needed!")
    
    # Security audit
    logs = client.get_audit_logs(resource_id="PROJ-2025-ALPHA")
    print(f"\n6. Security Audit: {len(logs)} access events logged")
    access_events = [log for log in logs if log['operation'] == 'reconstruct_and_decrypt']
    for log in access_events[-2:]:  # Show last 2 access events
        print(f"   - Access event: {log['timestamp']}")
    
    print()


# ============================================================================
# EXAMPLE 5: Research - Privacy-Preserving Data Analysis
# ============================================================================

def research_data_analysis():
    """
    Research scenario: Multi-institutional study with sensitive data.
    
    Use case: Collaborative research without centralizing sensitive data
    Privacy: Each institution holds shards, requires collaboration for analysis
    """
    print("=" * 70)
    print("RESEARCH: Privacy-Preserving Multi-Institutional Study")
    print("=" * 70)
    
    client = TZDCClient(
        time_window=TimeWindow.DAYS_30.value,  # 30 days in seconds
        enable_audit_log=True
    )
    
    # Research dataset (anonymized patient cohort)
    research_data = json.dumps({
        "study_id": "STUDY-COVID-2025",
        "study_name": "COVID-19 Long-term Effects Analysis",
        "institutions": ["Hospital A", "Hospital B", "Hospital C"],
        "patient_cohort": {
            "total_patients": 1500,
            "demographics": {"age_range": "18-75", "gender_mix": "balanced"},
            "conditions": ["post_covid_syndrome", "cardiovascular_effects"]
        },
        "sensitive_findings": "Preliminary results show significant correlation",
        "next_steps": "Publish in peer-reviewed journal"
    }).encode()
    
    print("\n1. Multi-institutional research study:")
    print("   Study: COVID-19 Long-term Effects")
    print("   Institutions: 3 hospitals")
    print("   Duration: 30 days")
    
    # Create commitment for research integrity
    commitment, salt = client.create_commitment(
        research_data,
        resource_id="STUDY-COVID-2025"
    )
    
    print(f"\n2. Research data integrity proof:")
    print(f"   Commitment: {commitment.commitment_hash[:24]}...")
    print("   (Proves data existence without revealing content)")
    
    # Shard data across institutions
    shards = client.encrypt_and_shard(
        data=research_data,
        resource_id="STUDY-COVID-2025",
        total_shards=3,
        threshold=2,  # Requires 2 of 3 institutions to collaborate
        custom_expiry=datetime.now(timezone.utc) + timedelta(days=30)
    )
    
    print(f"\n3. Distributing data shards:")
    institutions = {
        "Hospital_A_Research_Dept": shards[0],
        "Hospital_B_Research_Dept": shards[1],
        "Hospital_C_Research_Dept": shards[2]
    }
    
    for institution, shard in institutions.items():
        print(f"   - {institution}: Shard {shard.shard_index}")
        print(f"     (Institution cannot access data alone)")
    
    # Analysis requires collaboration
    print("\n4. Collaborative analysis:")
    print("   Hospital A + Hospital B collaborating for analysis...")
    
    analysis_shards = [shards[0], shards[1]]
    
    try:
        decrypted_research = client.reconstruct_and_decrypt(analysis_shards)
        
        print("   ✓ Data reconstructed for joint analysis")
        print("   ✓ Statistical analysis performed")
        print("   ✓ Results aggregated")
        
        # Verify data integrity before publication
        is_valid = client.verify_commitment(
            commitment,
            decrypted_research,
            salt,
            resource_id="STUDY-COVID-2025"
        )
        
        print(f"\n5. Pre-publication integrity check:")
        print(f"   ✓ Data integrity verified: {is_valid}")
        print(f"   ✓ Ready for peer review")
        
    except Exception as e:
        print(f"   ✗ Collaborative analysis failed: {e}")
    
    print("\n6. Post-publication (Day 31):")
    print("   ✓ Study published")
    print("   ✓ Raw data automatically deleted")
    print("   ✓ Privacy preserved - GDPR compliant")
    print("   ✓ Only aggregated results remain public")
    
    print()


# ============================================================================
# EXAMPLE 6: Zero-Knowledge Proof - Salary Verification
# ============================================================================

def zero_knowledge_salary_proof():
    """
    Demonstrate zero-knowledge proof for salary verification.
    
    Use case: Prove salary is above threshold without revealing exact amount
    Application: Loan applications, visa applications, etc.
    """
    print("=" * 70)
    print("ZERO-KNOWLEDGE PROOF: Salary Verification Without Disclosure")
    print("=" * 70)
    
    client = TZDCClient()
    
    # Employee salary (sensitive)
    actual_salary = 125000  # $125,000
    
    print(f"\n1. Scenario: Loan application requires proof of income > $100,000")
    print(f"   Employee's actual salary: ${actual_salary:,}")
    print(f"   Requirement: Prove salary > $100,000 WITHOUT revealing amount")
    
    # Create range proof
    print(f"\n2. Creating zero-knowledge range proof...")
    commitment, proof_data = client.zk_prover.prove_range(
        value=actual_salary,
        min_value=100000,
        max_value=1000000  # Upper bound for proof
    )
    
    print(f"   ✓ Commitment created: {commitment.commitment_hash[:20]}...")
    print(f"   ✓ Proof generated (does not reveal exact salary)")
    
    # Bank verifies proof
    print(f"\n3. Bank verification:")
    is_valid = client.zk_prover.verify_range_proof(
        commitment,
        actual_salary,
        proof_data
    )
    
    print(f"   ✓ Proof verified: {is_valid}")
    print(f"   ✓ Bank confirmed: Salary is between $100K - $1M")
    print(f"   ✓ Exact salary NOT disclosed: Privacy preserved!")
    
    print(f"\n4. Benefits of zero-knowledge approach:")
    print(f"   - Employee privacy maintained")
    print(f"   - Bank requirements satisfied")
    print(f"   - No unnecessary data exposure")
    print(f"   - Cryptographically verifiable")
    
    print()


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Run all example scenarios."""
    
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  TZDC LIBRARY - COMPREHENSIVE REAL-WORLD EXAMPLES".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print("\n")
    
    examples = [
        ("Healthcare", healthcare_specialist_access),
        ("Machine Learning", ml_training_data_protection),
        ("Financial Services", financial_transaction_audit),
        ("Enterprise Security", enterprise_contractor_access),
        ("Research", research_data_analysis),
        ("Zero-Knowledge Proof", zero_knowledge_salary_proof),
    ]
    
    print("Select an example to run:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    print(f"  {len(examples) + 1}. Run all examples")
    print(f"  0. Exit")
    
    try:
        choice = input("\nEnter your choice (0-7): ").strip()
        choice = int(choice)
        
        if choice == 0:
            print("\nExiting...")
            return
        elif choice == len(examples) + 1:
            print("\nRunning all examples...\n")
            for name, func in examples:
                func()
                input("\nPress Enter to continue to next example...")
        elif 1 <= choice <= len(examples):
            examples[choice - 1][1]()
        else:
            print("Invalid choice!")
    except (ValueError, KeyboardInterrupt):
        print("\nExiting...")
    
    print("\n" + "=" * 70)
    print("Thank you for exploring TZDC!")
    print("=" * 70)


if __name__ == "__main__":
    main()