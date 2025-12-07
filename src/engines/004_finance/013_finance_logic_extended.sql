-- =====================================================================
-- 013_finance_logic_extended.sql
-- Nexora Finance — LOGIC EXTENDED (Final, idempotent, Supabase-ready)
-- EXTENDS 012_finance_logic_core.sql (no duplication) with:
--   - robust outbound queue + attempts + DLQ
--   - adapter registry
--   - dynamic worker processing
--   - export pack v2 (signed via 012 payload_sha256)
--   - tax bundle helpers, settlement pack helpers
--   - AI prep extractors
--   - scheduler wrapper for processing batches
-- =====================================================================

SET search_path = finance, finance_ai, finance_audit, public;

-- Defensive: ensure pgcrypto available in public (no-op if present)
DO $$
BEGIN
  BEGIN
    CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgcrypto creation skipped or not permitted: %', SQLERRM;
  END;
END;
$$;

-- Defensive: ensure 012 core has been applied (payload_sha256)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_namespace n JOIN pg_proc p ON p.pronamespace = n.oid
    WHERE n.nspname = 'finance' AND p.proname = 'payload_sha256'
  ) THEN
    RAISE NOTICE 'WARN: finance.payload_sha256 not found; ensure 012_finance_logic_core.sql ran first';
  END IF;
END;
$$;

-- =====================================================================
-- 1) Outbound queue (append-only outbox pattern) + supporting tables
-- =====================================================================
CREATE TABLE IF NOT EXISTS finance.outbound_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  service text NOT NULL,             -- 'erp'|'tax'|'settlement'|'other'
  target text NOT NULL,              -- e.g., 'quickbooks','kra','bank'
  payload jsonb NOT NULL,
  payload_hash text NOT NULL,
  attempt_count int DEFAULT 0,
  next_attempt_at timestamptz DEFAULT now(),
  last_error text,
  status text DEFAULT 'queued',      -- queued|processing|done|failed|dlq
  tenant_org uuid,
  tags text[] DEFAULT '{}'::text[],
  metadata jsonb DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_outbound_queue_status_next ON finance.outbound_queue(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS finance.outbound_attempts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  queue_id uuid REFERENCES finance.outbound_queue(id) ON DELETE CASCADE,
  attempt_at timestamptz DEFAULT now(),
  attempt_payload jsonb,
  result jsonb,
  success boolean DEFAULT false,
  error_text text
);

CREATE TABLE IF NOT EXISTS finance.outbound_dead_letter_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  origin_queue_id uuid,
  failed_at timestamptz DEFAULT now(),
  last_error text,
  final_payload jsonb,
  metadata jsonb DEFAULT '{}'::jsonb
);

-- =====================================================================
-- 2) Adapter registry
-- Adapter functions (string names) are recorded here; workers call them.
-- =====================================================================
CREATE TABLE IF NOT EXISTS finance.outbound_adapter_registry (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  adapter_key text UNIQUE NOT NULL,  -- 'quickbooks','tally','kra','bank_gateway'
  adapter_fn text NOT NULL,          -- e.g. 'finance.adapter_quickbooks'
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now()
);

-- =====================================================================
-- 3) Utility: sign_export_pack wrapper
-- Uses core finance.payload_sha256 to ensure a single canonical hash implementation.
-- (012 defines finance.payload_sha256; 013 uses it.)
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.sign_payload_hex(p_json jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT finance.payload_sha256(p_json);
$$;

-- =====================================================================
-- 4) Enqueue outbound (idempotent by payload hash / idempotency key)
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.enqueue_outbound(
  p_service text,
  p_target text,
  p_payload jsonb,
  p_tenant_org uuid DEFAULT NULL,
  p_tags text[] DEFAULT NULL,
  p_metadata jsonb DEFAULT '{}'::jsonb,
  p_idempotency_key text DEFAULT NULL
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_hash text := finance.payload_sha256(p_payload);
  v_id uuid;
BEGIN
  -- idempotency by explicit key in metadata
  IF p_idempotency_key IS NOT NULL THEN
    SELECT id INTO v_id FROM finance.outbound_queue
    WHERE (metadata->>'idempotency_key') = p_idempotency_key
      AND service = p_service AND target = p_target
    LIMIT 1;
    IF v_id IS NOT NULL THEN RETURN v_id; END IF;
  END IF;

  -- dedupe by identical payload for same service/target/tenant
  SELECT id INTO v_id FROM finance.outbound_queue
  WHERE payload_hash = v_hash AND service = p_service AND target = p_target
    AND tenant_org IS NOT DISTINCT FROM p_tenant_org
  LIMIT 1;
  IF v_id IS NOT NULL THEN RETURN v_id; END IF;

  INSERT INTO finance.outbound_queue (service, target, payload, payload_hash, tenant_org, tags, metadata, next_attempt_at)
  VALUES (p_service, p_target, p_payload, v_hash, p_tenant_org, COALESCE(p_tags, '{}'::text[]), jsonb_set(p_metadata::jsonb, '{idempotency_key}', to_jsonb(p_idempotency_key::text), true), now())
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.enqueue_outbound(text, text, jsonb, uuid, text[], jsonb, text) TO service_role;

-- =====================================================================
-- 5) Dequeue for worker (claim for processing) — robust, FIFO by next_attempt_at
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.dequeue_outbound_for_worker(
  p_worker_name text,
  p_limit int DEFAULT 1
)
RETURNS TABLE(
  id uuid,
  service text,
  target text,
  payload jsonb,
  payload_hash text,
  tenant_org uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  rec record;
BEGIN
  FOR rec IN
    SELECT id, service, target, payload, payload_hash, tenant_org
    FROM finance.outbound_queue
    WHERE status IN ('queued','failed') AND next_attempt_at <= now()
    ORDER BY next_attempt_at ASC, created_at ASC
    LIMIT p_limit
  LOOP
    UPDATE finance.outbound_queue
    SET status = 'processing', last_error = NULL
    WHERE id = rec.id AND status IN ('queued','failed');

    IF FOUND THEN
      -- assign to OUT variables then emit the current row
      id := rec.id;
      service := rec.service;
      target := rec.target;
      payload := rec.payload;
      payload_hash := rec.payload_hash;
      tenant_org := rec.tenant_org;
      RETURN NEXT;
    END IF;
  END LOOP;

  RETURN;
END;
$$;

-- =====================================================================
-- 6) Mark success / failed (attempt recording, retry schedule, DLQ)
-- =====================================================================

-- mark success: record attempt and close queue item
CREATE OR REPLACE FUNCTION finance.mark_outbound_success(p_queue_id uuid, p_result jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_attempt_id uuid := gen_random_uuid();
BEGIN
  INSERT INTO finance.outbound_attempts (id, queue_id, attempt_at, attempt_payload, result, success)
  VALUES (v_attempt_id, p_queue_id, now(), (SELECT payload FROM finance.outbound_queue WHERE id = p_queue_id), p_result, true);

  UPDATE finance.outbound_queue
  SET status = 'done', attempt_count = COALESCE(attempt_count,0) + 1, next_attempt_at = NULL, last_error = NULL
  WHERE id = p_queue_id;

  -- audit
  BEGIN
    INSERT INTO finance_audit.audit_events(entity, entity_id, action, payload, actor, created_at)
    VALUES ('outbound_queue', p_queue_id::text, 'outbound_success', jsonb_build_object('result', p_result), finance.current_user_id(), now());
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'audit insert skipped: %', SQLERRM;
  END;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.mark_outbound_success(uuid, jsonb) TO service_role;

-- mark failed: insert attempt, schedule next attempt or move to DLQ
CREATE OR REPLACE FUNCTION finance.mark_outbound_failed(p_queue_id uuid, p_error text, p_result jsonb DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_attempt_id uuid := gen_random_uuid();
  v_attempt_count int;
  v_intervals int[] := ARRAY[60,300,900,3600,86400]; -- seconds: 1m,5m,15m,1h,1d
  v_idx int;
  v_next_at timestamptz;
BEGIN
  SELECT attempt_count INTO v_attempt_count FROM finance.outbound_queue WHERE id = p_queue_id;

  INSERT INTO finance.outbound_attempts (id, queue_id, attempt_at, attempt_payload, result, success, error_text)
  VALUES (v_attempt_id, p_queue_id, now(), (SELECT payload FROM finance.outbound_queue WHERE id = p_queue_id), p_result, false, p_error);

  v_attempt_count := COALESCE(v_attempt_count,0) + 1;

  IF v_attempt_count <= array_length(v_intervals,1) THEN
    v_idx := v_attempt_count;
    v_next_at := now() + make_interval(secs => v_intervals[v_idx]);
    UPDATE finance.outbound_queue
    SET attempt_count = v_attempt_count, next_attempt_at = v_next_at, last_error = left(p_error,4000), status = 'failed'
    WHERE id = p_queue_id;
  ELSE
    -- move to DLQ
    INSERT INTO finance.outbound_dead_letter_queue (origin_queue_id, failed_at, last_error, final_payload, metadata)
    SELECT id, now(), left(p_error,4000), payload, metadata FROM finance.outbound_queue WHERE id = p_queue_id;
    UPDATE finance.outbound_queue
    SET status = 'dlq', next_attempt_at = NULL, last_error = left(p_error,4000)
    WHERE id = p_queue_id;
  END IF;

  -- audit
  BEGIN
    INSERT INTO finance_audit.audit_events(entity, entity_id, action, payload, actor, created_at)
    VALUES ('outbound_queue', p_queue_id::text, 'outbound_failed', jsonb_build_object('error', left(p_error,2000), 'attempt', v_attempt_count), finance.current_user_id(), now());
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'audit insert skipped: %', SQLERRM;
  END;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.mark_outbound_failed(uuid, text, jsonb) TO service_role;

-- =====================================================================
-- 7) Process next outbound: atomic worker-side helper that calls adapter dynamically
-- Adapter functions must accept (jsonb) and return jsonb with 'status' or 'success' field.
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.process_next_outbound(p_worker_name text)
RETURNS TABLE(queue_id uuid, status text, result jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  rec record;
  v_adapter_fn text;
  v_result jsonb;
BEGIN
  -- claim one item atomically
  SELECT id, service, target, payload, payload_hash, tenant_org INTO rec
  FROM finance.outbound_queue
  WHERE status IN ('queued','failed') AND next_attempt_at <= now()
  ORDER BY next_attempt_at ASC, created_at ASC
  LIMIT 1
  FOR UPDATE SKIP LOCKED;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  UPDATE finance.outbound_queue SET status = 'processing', last_error = NULL WHERE id = rec.id;

  SELECT adapter_fn INTO v_adapter_fn FROM finance.outbound_adapter_registry WHERE adapter_key = rec.target LIMIT 1;

  IF v_adapter_fn IS NULL THEN
    v_result := jsonb_build_object('status','not_implemented','target', rec.target);
    PERFORM finance.mark_outbound_failed(rec.id, 'adapter_not_found: ' || rec.target, v_result);
    RETURN QUERY SELECT rec.id AS queue_id, 'not_implemented'::text AS status, v_result AS result;
    RETURN;
  END IF;

  BEGIN
    EXECUTE format('SELECT %I($1::jsonb)', v_adapter_fn) USING rec.payload INTO v_result;

    IF (coalesce(v_result->>'status','') = 'ok') OR (coalesce((v_result->>'success')::text,'false') = 'true') THEN
      PERFORM finance.mark_outbound_success(rec.id, v_result);
      RETURN QUERY SELECT rec.id AS queue_id, 'done'::text AS status, v_result AS result;
    ELSE
      PERFORM finance.mark_outbound_failed(rec.id, coalesce(v_result->>'error','adapter_failed'), v_result);
      RETURN QUERY SELECT rec.id AS queue_id, 'failed'::text AS status, v_result AS result;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    PERFORM finance.mark_outbound_failed(rec.id, SQLERRM, NULL);
    RETURN QUERY SELECT rec.id AS queue_id, 'failed'::text AS status, jsonb_build_object('error', SQLERRM) AS result;
  END;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.process_next_outbound(text) TO service_role;

-- =====================================================================
-- 8) Small mock adapter stubs (safe to override or replace in adapter registry)
-- These are lightweight placeholders; real workers should register production adapters.
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.adapter_stub_erp(p_payload jsonb) RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_build_object('status','ok','detail','stub_erp_received','payload',p_payload);
$$;

CREATE OR REPLACE FUNCTION finance.adapter_stub_tax(p_payload jsonb) RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_build_object('status','ok','detail','stub_tax_received','payload',p_payload);
$$;

CREATE OR REPLACE FUNCTION finance.adapter_stub_settlement(p_payload jsonb) RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_build_object('status','ok','detail','stub_settlement_received','payload',p_payload);
$$;

-- (optional) idempotently register stub adapters if registry empty for common keys
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM finance.outbound_adapter_registry WHERE adapter_key = 'stub_erp') THEN
    INSERT INTO finance.outbound_adapter_registry (adapter_key, adapter_fn, metadata) VALUES ('stub_erp','finance.adapter_stub_erp', jsonb_build_object('notes','autoregistered stub'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM finance.outbound_adapter_registry WHERE adapter_key = 'stub_tax') THEN
    INSERT INTO finance.outbound_adapter_registry (adapter_key, adapter_fn, metadata) VALUES ('stub_tax','finance.adapter_stub_tax', jsonb_build_object('notes','autoregistered stub'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM finance.outbound_adapter_registry WHERE adapter_key = 'stub_settlement') THEN
    INSERT INTO finance.outbound_adapter_registry (adapter_key, adapter_fn, metadata) VALUES ('stub_settlement','finance.adapter_stub_settlement', jsonb_build_object('notes','autoregistered stub'));
  END IF;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'adapter registry auto-register skipped: %', SQLERRM;
END;
$$;

-- =====================================================================
-- 9) Export Pack v2 (signed + optional enqueue)
--    Uses finance.sign_payload_hex which delegates to 012.payload_sha256
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.build_export_pack_v2(
  p_pack_type text,
  p_org_id uuid,
  p_from date,
  p_to date,
  p_enqueue_target text DEFAULT NULL,  -- e.g. 'quickbooks' or 'kra'
  p_enqueue_service text DEFAULT NULL  -- 'erp' or 'tax'
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_pack jsonb := '{}'::jsonb;
  v_content jsonb := '[]'::jsonb;
  v_signed text;
  v_queue_id uuid;
BEGIN
  IF p_pack_type = 'ledger' THEN
    BEGIN
      SELECT jsonb_agg(jsonb_build_object(
        'batch_id', jb.id,
        'reference', jb.reference,
        'created_at', jb.created_at,
        'entries', (SELECT jsonb_agg(jsonb_build_object('account', account_id, 'dc', dc, 'amount', amount, 'currency', currency)) FROM finance.journal_entries je WHERE je.batch_id = jb.id)
      )) INTO v_content
      FROM finance.journal_batches jb
      WHERE jb.created_at::date BETWEEN p_from AND p_to;
    EXCEPTION WHEN OTHERS THEN
      v_content := '[]'::jsonb;
    END;
  ELSIF p_pack_type = 'erp_invoice_pack' THEN
    BEGIN
      SELECT jsonb_agg(jsonb_build_object('id', id, 'reference', reference, 'date', issue_date, 'amount', total_amount, 'payload', payload))
      INTO v_content
      FROM finance.invoices
      WHERE org_id = p_org_id AND issue_date BETWEEN p_from AND p_to;
    EXCEPTION WHEN OTHERS THEN
      v_content := '[]'::jsonb;
    END;
  ELSIF p_pack_type = 'tax_vat' THEN
    BEGIN
      SELECT jsonb_agg(jsonb_build_object('id', id, 'event_type', event_type, 'payload', payload, 'created_at', created_at))
      INTO v_content
      FROM finance.tax_event_outbox t
      WHERE (t.payload->>'org_id')::uuid = p_org_id AND t.created_at::date BETWEEN p_from AND p_to;
    EXCEPTION WHEN OTHERS THEN
      v_content := '[]'::jsonb;
    END;
  ELSE
    v_content := jsonb_build_object('message','unknown_pack_type','pack_type',p_pack_type);
  END IF;

  v_pack := jsonb_build_object(
    'pack_type', p_pack_type,
    'org_id', p_org_id,
    'period', jsonb_build_object('from', p_from, 'to', p_to),
    'content', COALESCE(v_content, '[]'::jsonb),
    'generated_at', now(),
    'version', 'v2'
  );

  v_signed := finance.sign_payload_hex(v_pack);

  v_pack := jsonb_set(v_pack, '{signature}', to_jsonb(v_signed), true);
  v_pack := jsonb_set(v_pack, '{signed_at}', to_jsonb(now()), true);

  BEGIN
    INSERT INTO finance_audit.audit_events(entity, entity_id, action, payload, actor, created_at)
    VALUES ('export_pack', p_org_id::text, 'create_v2', v_pack, finance.current_user_id(), now());
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'audit insert skipped for export pack: %', SQLERRM;
  END;

  IF p_enqueue_target IS NOT NULL THEN
    v_queue_id := finance.enqueue_outbound(coalesce(p_enqueue_service,'erp'), p_enqueue_target, v_pack, p_org_id, ARRAY[p_pack_type], jsonb_build_object('pack_type', p_pack_type), v_signed);
  END IF;

  RETURN v_pack;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.build_export_pack_v2(text, uuid, date, date, text, text) TO service_role;

-- =====================================================================
-- 10) Tax helpers: bundle_vat_events + emit_tax_report
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.bundle_vat_events(p_org_id uuid, p_from date, p_to date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_bundle jsonb := '[]'::jsonb;
BEGIN
  BEGIN
    SELECT jsonb_agg(jsonb_build_object('id', id, 'event_type', event_type, 'payload', payload, 'created_at', created_at))
    INTO v_bundle
    FROM finance.tax_event_outbox t
    WHERE (t.payload->>'org_id')::uuid = p_org_id AND t.created_at::date BETWEEN p_from AND p_to;
  EXCEPTION WHEN OTHERS THEN
    v_bundle := '[]'::jsonb;
  END;
  RETURN v_bundle;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.bundle_vat_events(uuid, date, date) TO service_role;

CREATE OR REPLACE FUNCTION finance.emit_tax_report(p_org_id uuid, p_from date, p_to date, p_enqueue boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_bundle jsonb;
  v_pack jsonb;
BEGIN
  v_bundle := finance.bundle_vat_events(p_org_id, p_from, p_to);
  v_pack := finance.build_export_pack_v2('tax_vat', p_org_id, p_from, p_to, CASE WHEN p_enqueue THEN 'kra' ELSE NULL END, CASE WHEN p_enqueue THEN 'tax' ELSE NULL END);

  BEGIN
    INSERT INTO finance_audit.audit_events(entity, entity_id, action, payload, actor, created_at)
    VALUES ('tax_report', p_org_id::text, 'emit_tax_report', jsonb_build_object('bundle_count', jsonb_array_length(v_bundle), 'pack', v_pack), finance.current_user_id(), now());
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'audit insert skipped for tax report: %', SQLERRM;
  END;

  RETURN jsonb_build_object('bundle', v_bundle, 'pack', v_pack);
END;
$$;

GRANT EXECUTE ON FUNCTION finance.emit_tax_report(uuid, date, date, boolean) TO service_role;

-- =====================================================================
-- 11) Settlement pack generator + optional enqueue
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.generate_settlement_pack(p_from date, p_to date, p_org_id uuid DEFAULT NULL, p_enqueue boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_pack jsonb;
BEGIN
  v_pack := finance.build_export_pack_v2('settlement', coalesce(p_org_id, gen_random_uuid()), p_from, p_to, CASE WHEN p_enqueue THEN 'bank_gateway' ELSE NULL END, CASE WHEN p_enqueue THEN 'settlement' ELSE NULL END);
  RETURN v_pack;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.generate_settlement_pack(date, date, uuid, boolean) TO service_role;

-- =====================================================================
-- 12) Requeue DLQ entry (admin operation, idempotent-ish)
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.requeue_dead_letter(p_dlq_id uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_orig record;
  v_new_id uuid;
BEGIN
  SELECT * INTO v_orig FROM finance.outbound_dead_letter_queue WHERE id = p_dlq_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DLQ entry % not found', p_dlq_id;
  END IF;

  INSERT INTO finance.outbound_queue (service, target, payload, payload_hash, metadata, tenant_org, status, next_attempt_at)
  VALUES (
    COALESCE((v_orig.metadata->>'service')::text, 'other'),
    COALESCE((v_orig.metadata->>'target')::text, 'unknown'),
    v_orig.final_payload,
    finance.sign_payload_hex(v_orig.final_payload),
    COALESCE(v_orig.metadata, '{}'::jsonb),
    NULL,
    'queued',
    now()
  ) RETURNING id INTO v_new_id;

  DELETE FROM finance.outbound_dead_letter_queue WHERE id = p_dlq_id;

  RETURN v_new_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.requeue_dead_letter(uuid) TO service_role;

-- =====================================================================
-- 13) AI prep: lightweight feature extractor (non-PII)
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.extract_ai_finance_features(p_org_id uuid, p_from date, p_to date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_summary jsonb;
  v_mv jsonb;
  v_top_suppliers jsonb;
BEGIN
  BEGIN
    SELECT row_to_json(t) INTO v_mv FROM (SELECT * FROM finance.mv_org_financial_summary WHERE org_id = p_org_id) t;
  EXCEPTION WHEN OTHERS THEN
    v_mv := NULL;
  END;

  BEGIN
    SELECT jsonb_agg(jsonb_build_object('supplier_id', supplier_id, 'total', sum(amount))) INTO v_top_suppliers
    FROM finance.supplier_invoices
    WHERE org_id = p_org_id AND issue_date BETWEEN p_from AND p_to
    GROUP BY supplier_id
    ORDER BY sum(amount) DESC
    LIMIT 10;
  EXCEPTION WHEN OTHERS THEN
    v_top_suppliers := '[]'::jsonb;
  END;

  v_summary := jsonb_build_object(
    'org_id', p_org_id,
    'period', jsonb_build_object('from', p_from, 'to', p_to),
    'mv_summary', COALESCE(v_mv, jsonb_build_object()),
    'top_suppliers', v_top_suppliers,
    'generated_at', now()
  );

  RETURN v_summary;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.extract_ai_finance_features(uuid, date, date) TO service_role;

-- =====================================================================
-- 14) Scheduler wrapper: job to process outbound in batches (safe for pg_cron)
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.job_process_outbound_batch(p_batch_size int DEFAULT 10)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_processed int := 0;
  rec record;
  r record;
BEGIN
  LOOP
    SELECT queue_id, status, result INTO r.queue_id, r.status, r.result FROM finance.process_next_outbound('cron-worker') LIMIT 1;
    IF NOT FOUND THEN
      EXIT;
    END IF;
    v_processed := v_processed + 1;
    IF v_processed >= p_batch_size THEN
      EXIT;
    END IF;
  END LOOP;
  RETURN v_processed;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.job_process_outbound_batch(int) TO service_role;

-- =====================================================================
-- 15) Register adapter helper (idempotent)
-- =====================================================================
CREATE OR REPLACE FUNCTION finance.register_outbound_adapter(p_adapter_key text, p_adapter_fn text, p_metadata jsonb DEFAULT '{}'::jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_id uuid;
BEGIN
  SELECT id INTO v_id FROM finance.outbound_adapter_registry WHERE adapter_key = p_adapter_key LIMIT 1;
  IF v_id IS NOT NULL THEN
    UPDATE finance.outbound_adapter_registry SET adapter_fn = p_adapter_fn, metadata = p_metadata, created_at = now() WHERE id = v_id;
    RETURN v_id;
  END IF;

  INSERT INTO finance.outbound_adapter_registry (adapter_key, adapter_fn, metadata) VALUES (p_adapter_key, p_adapter_fn, p_metadata) RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION finance.register_outbound_adapter(text, text, jsonb) TO service_role;

-- =====================================================================
-- 16) Grants (best-effort; will not error if permissions unavailable)
-- =====================================================================
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    GRANT SELECT, INSERT, UPDATE ON finance.outbound_queue TO service_role;
    GRANT SELECT, INSERT ON finance.outbound_attempts TO service_role;
    GRANT SELECT, INSERT, DELETE ON finance.outbound_dead_letter_queue TO service_role;
    GRANT SELECT, INSERT, UPDATE ON finance.outbound_adapter_registry TO service_role;
  END IF;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'Granting outbound privileges skipped: %', SQLERRM;
END;
$$;

-- =====================================================================
-- Reset search_path
-- =====================================================================
RESET search_path;
