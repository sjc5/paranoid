use super::*;

#[path = "support/credential_materialization.rs"]
mod credential_materialization;
#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/in_memory_commit_store.rs"]
mod support_in_memory_commit_store;

use credential_materialization::*;
use fixtures::*;
use support_in_memory_commit_store::*;

mod active_proof_commit_guards;
mod active_proof_configured_secret_fast_fail;
mod active_proof_guards;
mod active_proof_revocation_guards;
mod commit_adapters;
mod commit_guard_matrix;
mod config_validation;
mod credential_lifecycle;
mod credential_metadata;
mod credential_recovery_authority;
mod csrf_cycle_guards;
mod execution_boundary;
mod in_memory_commit_store;
mod in_memory_commit_store_atomicity;
mod in_memory_commit_store_revocation_and_time;
mod input_validation;
mod load_contract;
mod loaded_state_and_guards;
mod method_adapter_contract;
mod mounted_admin_support;
mod mounted_credential_lifecycle;
mod mounted_runtime;
mod mounted_subject_lifecycle;
mod out_of_band_active_proof;
mod pending_lifecycle_actions;
mod postgres_runtime;
mod postgres_store;
mod proof_policy;
mod request_revocation_resolution;
mod revocation;
mod safe_read_and_request_resolution;
mod session_and_device_lifecycle;
mod session_secret_resolution;
mod source_guards;
mod step_up_request_resolution;
mod storage_contract;
mod weak_active_proof_failure_guards;
mod weak_proof_gate;
mod web_runtime;
mod web_transport;
