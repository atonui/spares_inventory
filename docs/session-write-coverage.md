# Authenticated write coverage

Each protected row must revalidate the original session inside its owning transaction. All 50 protected operations have valid-session and revoked-after-auth HTTP evidence. The registration inventory test rejects unclassified mutation routes.

| Method | Path | Classification | Owner / evidence |
|---|---|---|---|
| PUT | `/api/profile` | protected record write | `main.py:update_profile`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/profile/change-password` | protected record write | `main.py:change_password`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/auth/revoke-other-sessions` | protected record write | `main.py:revoke_other_sessions`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/forgot-password` | public capability | Public capability; unchanged; `test_archived_user_cannot_receive_or_verify_reset_credentials` |
| POST | `/api/reset-password` | public capability | Public reset capability; unchanged; `test_session_revocation[reset]` |
| POST | `/api/auth/login` | public capability | Public password authentication; unchanged; `test_public_authentication_remains_compatible` |
| DELETE | `/api/auth/sessions/{session_id}` | protected record write | `main.py:revoke_session`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/auth/sessions/revoke-all` | protected record write | `main.py:revoke_all_sessions`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/auth/logout` | protected record write | `main.py:logout`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/inventory/consume` | protected record write | `main.py:consume_stock`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/inventory/import-balances` | protected record write | `main.py:import_stock_balances`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/inventory/add` | protected record write | `main.py:add_stock`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| PUT | `/api/inventory/update` | protected record write | `main.py:update_stock`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/inventory/transfer` | protected record write | `main.py:transfer_stock`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/inventory/transfers/{transfer_id}/receive` | protected record write | `main.py:receive_transfer`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/inventory/transfers/{transfer_id}/return` | protected record write | `main.py:return_transfer`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/parts/{part_id}/restore` | protected record write | `main.py:restore_parts`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/stores/{store_id}/restore` | protected record write | `main.py:restore_stores`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/users/{target_user_id}/restore` | protected record write | `main.py:restore_users`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/users` | protected record write | `main.py:create_user`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| PUT | `/api/users/{target_user_id}` | protected record write | `main.py:update_user`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| DELETE | `/api/users/{target_user_id}` | protected record write | `main.py:delete_user`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/stores` | protected record write | `main.py:create_store`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| POST | `/api/stores/bulk-import` | protected record write | `main.py:bulk_import_stores`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| PUT | `/api/stores/{store_id}` | protected record write | `main.py:update_store`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| DELETE | `/api/stores/{store_id}` | protected record write | `main.py:delete_store`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| POST | `/api/store-types` | protected record write | `main.py:create_store_type`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| PUT | `/api/store-types/{type_id}` | protected record write | `main.py:update_store_type`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| DELETE | `/api/store-types/{type_id}` | protected record write | `main.py:delete_store_type`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| POST | `/api/parts` | protected record write | `main.py:create_part`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| POST | `/api/parts/bulk-import` | protected record write | `main.py:bulk_import_parts`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| PUT | `/api/parts/{part_id}` | protected record write | `main.py:update_part`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| DELETE | `/api/parts/{part_id}` | protected record write | `main.py:delete_part`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| DELETE | `/api/logs/activity/cleanup` | protected record write | `main.py:cleanup_old_logs`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/equipment` | protected record write | `main.py:create_equipment`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| PUT | `/api/equipment/{equipment_id}` | protected record write | `main.py:update_equipment`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| POST | `/api/equipment/{equipment_id}/transfer` | protected record write | `main.py:transfer_equipment`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| POST | `/api/equipment/{equipment_id}/calibrate` | protected record write | `main.py:update_calibration`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| DELETE | `/api/equipment/{equipment_id}` | protected record write | `main.py:delete_equipment`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| PUT | `/api/settings/calibration-reminder-days` | protected record write | `main.py:update_calibration_reminder_days`; guarded owner; `test_catalog_and_equipment_write_routes` valid/revoked pairs; atomic success activity |
| POST | `/api/superadmin/users/{target_id}/reset-password` | protected record write | `main.py:superadmin_reset_password`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/superadmin/unlock-account` | protected record write | `main.py:unlock_account`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/superadmin/unlock-accounts/bulk` | protected record write | `main.py:bulk_unlock_accounts`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/superadmin/sessions/force-logout` | protected record write | `main.py:force_logout_user`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/superadmin/sessions/force-logout-all` | protected record write | `main.py:force_logout_all`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| PUT | `/api/superadmin/security-config/{key}` | protected record write | `main.py:update_security_config`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| PUT | `/api/superadmin/users/{target_id}/role` | protected record write | `main.py:update_user_role`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/superadmin/database/query` | read/maintenance; guard audit | `main.py:run_readonly_query`; guarded standalone audit; `test_maintenance_audit_uses_current_session` |
| POST | `/api/superadmin/database/restore` | protected record write | Existing live restore owner + mandatory session/role callback; `test_restore_rechecks_original_session_under_lock`, real-ordering tests |
| POST | `/api/superadmin/database/vacuum` | read/maintenance; guard audit | `main.py:vacuum_database`; guarded standalone audit; `test_maintenance_audit_uses_current_session` |
| DELETE | `/api/superadmin/database/logs/purge` | protected record write | `main.py:purge_all_logs`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/superadmin/announcement` | protected record write | `main.py:set_announcement`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| DELETE | `/api/superadmin/announcement` | protected record write | `main.py:clear_announcement`; guarded owner; `test_profile_session_and_admin_write_routes` valid/revoked pairs; atomic existing activity |
| POST | `/api/inventory/count-preview` | read/maintenance; guard audit | Read-only snapshot and signed preview; `test_stock_counts.py`; no mutation audit |
| POST | `/api/inventory/count-confirm` | protected record write | `stock_counts.py:count_confirm`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |
| PUT | `/api/inventory/minimum` | protected record write | `replenishment.py:minimum`; `test_stock_write_routes` valid/revoked pairs; borrowed current permissions |

Authenticated GET activity audits use the same guarded standalone adapter. Their responses remain reads; an invalidated session cannot emit a database activity row. `test_read_audit_after_restore_does_not_write` exercises the actual decorator and `test_maintenance_audit_uses_current_session` exercises backup/query/VACUUM.

| GET path | Existing activity owner |
|---|---|
| `/api/parts` | Read decorator → guarded standalone activity |
| `/api/users` | Read decorator → guarded standalone activity |
| `/api/equipment/statistics` | Read decorator → guarded standalone activity |
| `/api/equipment` | Read decorator → guarded standalone activity |
| `/api/equipment/{equipment_id}/history` | Read decorator → guarded standalone activity |
| `/api/settings/calibration-reminder-days` | Read decorator → guarded standalone activity |
| `/api/superadmin/database/backup` | Explicit guarded standalone activity |

Initial authentication last-activity has its own short owning transaction, verified by `test_initial_auth_holds_lock_through_activity_update`. All other read/report/export routes emit no application-record mutation beyond initial authentication. `VACUUM`, file creation/download and public authentication remain the spec-defined exclusions. Schema/deployment are unchanged.
