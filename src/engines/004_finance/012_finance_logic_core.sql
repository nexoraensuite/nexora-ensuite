-- =====================================================================
-- 012_finance_logic_core.sql
-- Nexora Finance — LOGIC CORE (Final, idempotent, Supabase-ready)
-- Core posting, payment orchestration, tax-outbox emission,
-- append-only protections, audit events, and tenant audit generation.
-- Uses public.digest (pgcrypto in public).
-- =====================================================================

SET search_path = finance, finance_ai, finance_audit, public;

-- -------------------------
-- 0) Defensive: ensure pgcrypto available (no-op if already present)
-- -------------------------
DO $$
BEGIN
  BEGIN
    CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgcrypto creation skipped or not permitted: %', SQLERRM;
  END;
END;
$$;

-- -------------------------
-- 1) Append-only protections for sensitive tables
-- -------------------------
CREATE OR REPLACE FUNCTION finance.tg_prevent_modify_journal_entries()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'journal_entries is append-only; modifications are not allowed';
  RETURN NULL;
END;
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
             WHERE c.relname = 'journal_entries' AND n.nspname = 'finance') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger t
      WHERE t.tgname = 'prevent_modify_journal_entries' AND t.tgrelid = 'finance.journal_entries'::regclass
    ) THEN
      CREATE TRIGGER prevent_modify_journal_entries
        BEFORE UPDATE OR DELETE ON finance.journal_entries
        FOR EACH ROW EXECUTE FUNCTION finance.tg_prevent_modify_journal_entries();
    END IF;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION finance.tg_prevent_modify_tax_outbox()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'tax_event_outbox is append-only; modifications are not allowed';
  RETURN NULL;
END;
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
             WHERE c.relname = 'tax_event_outbox' AND n.nspname = 'finance') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger t
      WHERE t.tgname = 'prevent_modify_tax_event_outbox' AND t.tgrelid = 'finance.tax_event_outbox'::regclass
    ) THEN
      CREATE TRIGGER prevent_modify_tax_event_outbox
        BEFORE UPDATE OR DELETE ON finance.tax_event_outbox
        FOR EACH ROW EXECUTE FUNCTION finance.tg_prevent_modify_tax_outbox();
    END IF;
  END IF;
END;
$$;

-- -------------------------
-- 2) Canonical hashing helpers (idempotent)
-- -------------------------
CREATE OR REPLACE FUNCTION finance.payload_sha256(p_json jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT encode(public.digest(p_json::text, 'sha256'), 'hex');
$$;

CREATE OR REPLACE FUNCTION finance.text_sha256_hex(p_text text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT encode(public.digest(p_text, 'sha256'), 'hex');
$$;

-- -------------------------
-- 3) Emit tax event (idempotent-ish)
-- -------------------------
CREATE OR REPLACE FUNCTION finance.emit_tax_event(
  p_source_table text,
  p_source_id uuid,
  p_event_type text,
  p_payload jsonb
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_id uuid;
  v_hash text := finance.payload_sha256(p_payload);
BEGIN
  SELECT id INTO v_id
  FROM finance.tax_event_outbox
  WHERE source_table = p_source_table
    AND source_id = p_source_id
    AND payload_hash = v_hash
  LIMIT 1;

  IF v_id IS NOT NULL THEN
    RETURN v_id;
  END IF;

  INSERT INTO finance.tax_event_outbox (source_table, source_id, event_type, payload, payload_hash, created_at)
  VALUES (p_source_table, p_source_id, p_event_type, p_payload, v_hash, now())
  RETURNING id INTO v_id;

  INSERT INTO finance_audit.audit_events (entity, entity_id, action, payload, actor, created_at)
  VALUES (
    'tax_event_outbox',
    v_id::text,
    'emit',
    jsonb_build_object('source_table', p_source_table, 'source_id', p_source_id, 'event_type', p_event_type, 'payload_hash', v_hash),
    finance.current_user_id(),
    now()
  );

  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.emit_tax_event(text, uuid, text, jsonb) TO service_role;

-- -------------------------
-- 4) Posting engine: post_journal_batch
-- -------------------------
CREATE OR REPLACE FUNCTION finance.post_journal_batch(p_batch_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_debits numeric := 0;
  v_credits numeric := 0;
  v_org_id uuid;
BEGIN
  PERFORM 1 FROM finance.journal_batches WHERE id = p_batch_id AND posted = false;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Batch % not found or already posted', p_batch_id;
  END IF;

  SELECT coalesce(sum(case when dc = 'D' then amount else 0 end),0),
         coalesce(sum(case when dc = 'C' then amount else 0 end),0)
  INTO v_debits, v_credits
  FROM finance.journal_entries
  WHERE batch_id = p_batch_id;

  IF v_debits <> v_credits THEN
    RAISE EXCEPTION 'Batch % not balanced: debits=% credits=%', p_batch_id, v_debits, v_credits;
  END IF;

  UPDATE finance.journal_entries
  SET posted_at = now()
  WHERE batch_id = p_batch_id;

  UPDATE finance.journal_batches
  SET posted = true, sealed = true
  WHERE id = p_batch_id;

  SELECT org_id INTO v_org_id FROM finance.journal_entries WHERE batch_id = p_batch_id LIMIT 1;

  PERFORM finance.emit_tax_event(
    'journal_batches',
    p_batch_id,
    'journal_posted',
    jsonb_build_object('batch_id', p_batch_id, 'debits', v_debits, 'credits', v_credits, 'org_id', v_org_id)
  );

  INSERT INTO finance_audit.audit_events (entity, entity_id, action, payload, actor, created_at)
  VALUES ('journal_batches', p_batch_id::text, 'posted', jsonb_build_object('debits', v_debits, 'credits', v_credits), finance.current_user_id(), now());
END;
$$;

GRANT EXECUTE ON FUNCTION finance.post_journal_batch(uuid) TO finance_approver, service_role;

-- -------------------------
-- 5) Create payment request (idempotent)
-- -------------------------
CREATE OR REPLACE FUNCTION finance.create_payment_request(
  p_provider_id uuid,
  p_amount numeric,
  p_currency text,
  p_payee_id uuid,
  p_payer_id uuid,
  p_org_id uuid,
  p_idempotency_key text,
  p_request_payload jsonb DEFAULT '{}'::jsonb
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF p_idempotency_key IS NOT NULL THEN
    SELECT id INTO v_id FROM finance.payment_requests
    WHERE idempotency_key = p_idempotency_key LIMIT 1;
    IF v_id IS NOT NULL THEN
      RETURN v_id;
    END IF;
  END IF;

  INSERT INTO finance.payment_requests (provider_id, amount, currency, payee_id, payer_id, org_id, status, idempotency_key, request_payload, created_at)
  VALUES (p_provider_id, p_amount, p_currency, p_payee_id, p_payer_id, p_org_id, 'pending', p_idempotency_key, p_request_payload, now())
  RETURNING id INTO v_id;

  INSERT INTO finance_audit.audit_events (entity, entity_id, action, payload, actor, created_at)
  VALUES ('payment_requests', v_id::text, 'create', jsonb_build_object('provider_id', p_provider_id, 'amount', p_amount, 'currency', p_currency, 'org_id', p_org_id), finance.current_user_id(), now());

  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.create_payment_request(uuid, numeric, text, uuid, uuid, uuid, text, jsonb) TO authenticated, service_role;

-- -------------------------
-- 6) Webhook handler
-- -------------------------
CREATE OR REPLACE FUNCTION finance.handle_payment_webhook(
  p_provider_id uuid,
  p_external_id text,
  p_payload jsonb,
  p_idempotency_key text DEFAULT NULL
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_settlement_id uuid;
  v_req_id uuid;
BEGIN
  INSERT INTO finance.payment_webhooks (provider_id, external_id, payload, idempotency_key, received_at)
  VALUES (p_provider_id, p_external_id, p_payload, p_idempotency_key, now());

  SELECT id INTO v_req_id FROM finance.payment_requests
  WHERE (external_id = p_external_id OR idempotency_key = p_idempotency_key)
  LIMIT 1;

  IF v_req_id IS NULL THEN
    INSERT INTO finance.settlement_records (payment_request_id, amount, currency, settled_at, created_at)
    VALUES (NULL, (p_payload->>'amount')::numeric, (p_payload->>'currency')::text, now(), now())
    RETURNING id INTO v_settlement_id;
  ELSE
    UPDATE finance.payment_requests
    SET external_id = COALESCE(external_id, p_external_id), response_payload = p_payload, status = 'confirmed', processed_at = now()
    WHERE id = v_req_id;

    INSERT INTO finance.settlement_records (payment_request_id, amount, currency, settled_at, created_at)
    VALUES (v_req_id, (p_payload->>'amount')::numeric, (p_payload->>'currency')::text, now(), now())
    RETURNING id INTO v_settlement_id;
  END IF;

  INSERT INTO finance_audit.audit_events (entity, entity_id, action, payload, actor, created_at)
  VALUES ('payment_webhook', v_settlement_id::text, 'webhook_received', p_payload, finance.current_user_id(), now());

  RETURN v_settlement_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.handle_payment_webhook(uuid, text, jsonb, text) TO service_role;

-- -------------------------
-- 7) Reconcile statement stub
-- -------------------------
CREATE OR REPLACE FUNCTION finance.reconcile_statement(p_statement_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  INSERT INTO finance_audit.audit_events(entity, entity_id, action, payload, actor, created_at)
  VALUES ('reconciliation', p_statement_id::text, 'reconcile_invoked', '{}'::jsonb, finance.current_user_id(), now());
END;
$$;

GRANT EXECUTE ON FUNCTION finance.reconcile_statement(uuid) TO service_role;

-- -------------------------
-- 8) Tenant audit generator (single org)
-- -------------------------
CREATE OR REPLACE FUNCTION finance.generate_tenant_audit(
  p_org_id uuid,
  p_start date,
  p_end date
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_id uuid := gen_random_uuid();
  v_snapshot jsonb;
  v_invoice_count bigint := 0;
  v_invoice_total numeric := 0;
  v_supplier_count bigint := 0;
  v_supplier_total numeric := 0;
  v_payments jsonb := '{}'::jsonb;
  v_journal_stats jsonb := '{}'::jsonb;
  v_recon_unmatched bigint := 0;
  v_tax_pending bigint := 0;
BEGIN
  BEGIN
    SELECT count(*), coalesce(sum(total_amount),0) INTO v_invoice_count, v_invoice_total
    FROM finance.invoices
    WHERE org_id = p_org_id AND (issue_date BETWEEN p_start AND p_end);
  EXCEPTION WHEN undefined_table THEN
    v_invoice_count := 0; v_invoice_total := 0;
  END;

  BEGIN
    SELECT count(*), coalesce(sum(total_amount),0) INTO v_supplier_count, v_supplier_total
    FROM finance.supplier_invoices
    WHERE org_id = p_org_id AND (issue_date BETWEEN p_start AND p_end);
  EXCEPTION WHEN undefined_table THEN
    v_supplier_count := 0; v_supplier_total := 0;
  END;

  BEGIN
    SELECT coalesce(jsonb_object_agg(status, cnt), '{}'::jsonb) INTO v_payments FROM (
      SELECT status, count(*)::bigint AS cnt
      FROM finance.payment_requests
      WHERE org_id = p_org_id AND (created_at::date BETWEEN p_start AND p_end)
      GROUP BY status
    ) t;
  EXCEPTION WHEN undefined_table THEN
    v_payments := '{}'::jsonb;
  END;

  BEGIN
    SELECT jsonb_build_object(
      'entries_count', coalesce(count(*),0),
      'debits', coalesce(sum(case when dc = 'D' then amount else 0 end),0),
      'credits', coalesce(sum(case when dc = 'C' then amount else 0 end),0)
    ) INTO v_journal_stats
    FROM finance.journal_entries
    WHERE org_id = p_org_id AND (created_at::date BETWEEN p_start AND p_end);
  EXCEPTION WHEN undefined_table THEN
    v_journal_stats := jsonb_build_object('entries_count',0,'debits',0,'credits',0);
  END;

  BEGIN
    SELECT coalesce(count(*),0) INTO v_recon_unmatched
    FROM finance.reconciliation_results rr
    WHERE rr.created_at::date BETWEEN p_start AND p_end AND rr.matched_payment_request_id IS NULL;
  EXCEPTION WHEN undefined_table THEN
    v_recon_unmatched := 0;
  END;

  BEGIN
    SELECT coalesce(count(*),0) INTO v_tax_pending
    FROM finance.tax_event_outbox t
    WHERE t.created_at::date BETWEEN p_start AND p_end AND (t.payload->>'org_id') IS NOT NULL AND ((t.payload->>'org_id')::uuid = p_org_id);
  EXCEPTION WHEN undefined_table THEN
    v_tax_pending := 0;
  END;

  v_snapshot := jsonb_build_object(
    'org_id', p_org_id,
    'period_start', p_start,
    'period_end', p_end,
    'invoices', jsonb_build_object('count', v_invoice_count, 'total', v_invoice_total),
    'supplier_invoices', jsonb_build_object('count', v_supplier_count, 'total', v_supplier_total),
    'payments_summary', v_payments,
    'journal_stats', v_journal_stats,
    'reconciliation_unmatched', v_recon_unmatched,
    'tax_events_pending', v_tax_pending,
    'generated_at', now()
  );

  INSERT INTO finance.audit_snapshots (id, org_id, period_start, period_end, snapshot, created_by, created_at)
  VALUES (v_id, p_org_id, p_start, p_end, v_snapshot, finance.current_user_id(), now());

  INSERT INTO finance_audit.audit_events (entity, entity_id, action, payload, actor, created_at)
  VALUES ('audit_snapshot', v_id::text, 'create_snapshot', v_snapshot, finance.current_user_id(), now());

  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.generate_tenant_audit(uuid, date, date) TO service_role;

-- -------------------------
-- 9) Generate audits across active orgs for a period
-- -------------------------
CREATE OR REPLACE FUNCTION finance.generate_all_audits(p_period_start date, p_period_end date)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  rec record;
  v_count integer := 0;
BEGIN
  FOR rec IN
    SELECT DISTINCT org_id FROM (
      SELECT org_id FROM finance.invoices WHERE org_id IS NOT NULL AND issue_date BETWEEN p_period_start AND p_period_end
      UNION
      SELECT org_id FROM finance.supplier_invoices WHERE org_id IS NOT NULL AND issue_date BETWEEN p_period_start AND p_period_end
      UNION
      SELECT (request_payload->>'org_id')::uuid FROM finance.payment_requests WHERE (request_payload->>'org_id') IS NOT NULL AND created_at::date BETWEEN p_period_start AND p_period_end
    ) t
  LOOP
    IF rec.org_id IS NOT NULL THEN
      PERFORM finance.generate_tenant_audit(rec.org_id, p_period_start, p_period_end);
      v_count := v_count + 1;
    END IF;
  END LOOP;

  RETURN v_count;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.generate_all_audits(date, date) TO service_role;

-- -------------------------
-- Reset search_path
-- -------------------------
RESET search_path;
