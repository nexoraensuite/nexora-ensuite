-- 011_finance_rules.sql
-- Nexora Finance — RULES & RLS (GOVERNANCE)
-- Idempotent guarded policy creation and role setup.

SET search_path = finance, finance_ai, finance_audit, public;

-- 1) Create domain roles if missing (guarded)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='finance_approver') THEN
    CREATE ROLE finance_approver;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='treasury_manager') THEN
    CREATE ROLE treasury_manager;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='auditor') THEN
    CREATE ROLE auditor;
  END IF;
END$$;

-- 2) Revoke public usage on finance schemas
REVOKE ALL ON SCHEMA finance FROM public;
REVOKE ALL ON SCHEMA finance_ai FROM public;
REVOKE ALL ON SCHEMA finance_audit FROM public;

GRANT USAGE ON SCHEMA finance TO authenticated;
GRANT USAGE ON SCHEMA finance_ai TO authenticated;
GRANT USAGE ON SCHEMA finance_audit TO authenticated;

-- 3) Enable RLS on sensitive tables (guarded)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='journal_entries') THEN
    EXECUTE 'ALTER TABLE finance.journal_entries ENABLE ROW LEVEL SECURITY';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='journal_batches') THEN
    EXECUTE 'ALTER TABLE finance.journal_batches ENABLE ROW LEVEL SECURITY';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='invoices') THEN
    EXECUTE 'ALTER TABLE finance.invoices ENABLE ROW LEVEL SECURITY';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='supplier_invoices') THEN
    EXECUTE 'ALTER TABLE finance.supplier_invoices ENABLE ROW LEVEL SECURITY';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='payment_requests') THEN
    EXECUTE 'ALTER TABLE finance.payment_requests ENABLE ROW LEVEL SECURITY';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='tax_event_outbox') THEN
    EXECUTE 'ALTER TABLE finance.tax_event_outbox ENABLE ROW LEVEL SECURITY';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='finance' AND table_name='audit_snapshots') THEN
    EXECUTE 'ALTER TABLE finance.audit_snapshots ENABLE ROW LEVEL SECURITY';
  END IF;
END$$;

-- 4) Policies (guarded creation). Policy names prefixed with finance_policy_

-- journal_entries: select by org or finance admin
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='journal_entries' AND policyname='finance_policy_journal_entries_select'
  ) THEN
    CREATE POLICY finance_policy_journal_entries_select ON finance.journal_entries
      FOR SELECT
      USING (org_id = finance.current_org_id() OR finance.is_finance_admin());
  END IF;
END$$;

-- journal_entries: write via functions only (deny direct inserts unless service_role or approver)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='journal_entries' AND policyname='finance_policy_journal_entries_write'
  ) THEN
    CREATE POLICY finance_policy_journal_entries_write ON finance.journal_entries
      FOR ALL
      USING (finance.user_has_role('service_role') OR finance.is_finance_approver() OR finance.is_finance_admin())
      WITH CHECK (finance.user_has_role('service_role') OR finance.is_finance_approver() OR finance.is_finance_admin());
  END IF;
END$$;

-- journal_batches: only approver/admin can post/modify
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='journal_batches' AND policyname='finance_policy_journal_batches_manage'
  ) THEN
    CREATE POLICY finance_policy_journal_batches_manage ON finance.journal_batches
      FOR ALL
      USING (finance.is_finance_approver() OR finance.is_finance_admin())
      WITH CHECK (finance.is_finance_approver() OR finance.is_finance_admin());
  END IF;
END$$;

-- invoices: org members can select; posting restricted to finance approver or service_role
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='invoices' AND policyname='finance_policy_invoices_select_org'
  ) THEN
    CREATE POLICY finance_policy_invoices_select_org ON finance.invoices
      FOR SELECT
      USING (org_id = finance.current_org_id() OR finance.is_finance_admin());
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='invoices' AND policyname='finance_policy_invoices_manage'
  ) THEN
    CREATE POLICY finance_policy_invoices_manage ON finance.invoices
      FOR ALL
      USING (org_id = finance.current_org_id() OR finance.is_finance_admin() OR finance.user_has_role('service_role'))
      WITH CHECK (org_id = finance.current_org_id() OR finance.is_finance_admin() OR finance.user_has_role('service_role'));
  END IF;
END$$;

-- payment_requests: insert by authenticated (application) but status changes by service_role (webhooks)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='payment_requests' AND policyname='finance_policy_payment_requests_insert'
  ) THEN
    CREATE POLICY finance_policy_payment_requests_insert ON finance.payment_requests
      FOR INSERT
      WITH CHECK (org_id = finance.current_org_id() OR finance.user_has_role('service_role'));
  END IF;
END$$;

-- payment_requests: update enforcement (webhook/service_role)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='payment_requests' AND policyname='finance_policy_payment_requests_manage'
  ) THEN
    CREATE POLICY finance_policy_payment_requests_manage ON finance.payment_requests
      FOR UPDATE
      USING (org_id = finance.current_org_id() OR finance.user_has_role('service_role') OR finance.is_finance_admin())
      WITH CHECK (org_id = finance.current_org_id() OR finance.user_has_role('service_role') OR finance.is_finance_admin());
  END IF;
END$$;

-- tax_event_outbox: insert by finance functions/service_role; select by tax consumers (we recommend materialized view for tax)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='tax_event_outbox' AND policyname='finance_policy_tax_event_outbox_insert'
  ) THEN
    CREATE POLICY finance_policy_tax_event_outbox_insert ON finance.tax_event_outbox
      FOR INSERT
      WITH CHECK (finance.user_has_role('service_role') OR finance.is_finance_admin());
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='tax_event_outbox' AND policyname='finance_policy_tax_event_outbox_select'
  ) THEN
    CREATE POLICY finance_policy_tax_event_outbox_select ON finance.tax_event_outbox
      FOR SELECT
      USING (finance.user_has_role('service_role') OR finance.is_finance_admin());
  END IF;
END$$;

-- audit_snapshots: only auditor or service_role can select
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='finance' AND tablename='audit_snapshots' AND policyname='finance_policy_audit_snapshots_select'
  ) THEN
    CREATE POLICY finance_policy_audit_snapshots_select ON finance.audit_snapshots
      FOR SELECT
      USING (finance.user_has_role('auditor') OR finance.user_has_role('service_role') OR finance.is_finance_admin());
  END IF;
END$$;

-- Audit sink access (finance_audit.audit_events): insert by service_role
GRANT INSERT ON finance_audit.audit_events TO service_role;
GRANT SELECT ON finance.audit_snapshots TO finance_approver, treasury_manager, auditor, authenticated;
GRANT SELECT ON finance.journal_entries TO authenticated;

-- Revoke public access to sensitive objects
REVOKE ALL ON ALL TABLES IN SCHEMA finance FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA finance_ai FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA finance_audit FROM public;

-- Reset search_path
RESET search_path;
