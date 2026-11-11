-- Staged admission after a provider loss (Switch spec 12.6 step 2; Switch wire 7.4.14): set at
-- the `recovery` transition when the recovery document lists an app, cleared for good at
-- `POST /recovery/admission` or at the first qualifying upload. It counts only while the
-- account serves the generation the recovery began (`recovery_from`).
ALTER TABLE accounts ADD COLUMN admission_staged BOOLEAN NOT NULL DEFAULT false;
