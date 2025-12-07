-- ==========================================================
-- 0000_preclean_foundation.sql
-- Drops old conflicting registry functions so 0001 can run.
-- Safe & idempotent. Does nothing if functions aren't present.
-- ==========================================================

-- Drop older version of foundation.register_policy if exists
drop function if exists foundation.register_policy(text, text, text, text, text);

-- Drop older version of foundation.register_constraint if exists
drop function if exists foundation.register_constraint(text, text, text, text, text);

-- Drop older version of foundation.registertable if exists
drop function if exists foundation.registertable(text, text, text, text, boolean, text);

-- Drop older version of foundation.registercolumn if exists
drop function if exists foundation.registercolumn(
  text, text, text, text, boolean, text, text, text
);

-- Optional: clean any half-installed internal helpers
drop function if exists foundation._upsert_registry_catalog(
  text, text, text, text, boolean, text, text
);

drop function if exists foundation._upsert_registry_column(
  text, text, text, text, boolean, text, text, text
);

-- seal note for logs
select 'foundation pre-clean complete' as status;
