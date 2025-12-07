//--------------------------------------------------------------
// NEXORA MICRO-WORKER (Stateless)
// Executes exactly ONE masterrouter action then exits.
//--------------------------------------------------------------

import { createClient } from '@supabase/supabase-js';
import pg from 'pg';

//--------------------------------------------------------------
// ENV VARS
//--------------------------------------------------------------
const DB_URL = process.env.DATABASE_URL!;
const SUPABASE_URL = process.env.SUPABASE_URL!;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;

// Supabase client (for future external integrations)
export const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// PostgreSQL pool (small + short-lived)
const pool = new pg.Pool({
  connectionString: DB_URL,
  max: 1,
  idleTimeoutMillis: 500,  // keep short
});

//--------------------------------------------------------------
// Fetch & lock a single action
//--------------------------------------------------------------
async function fetchOneAction(): Promise<any | null> {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT * FROM masterrouter.fetch_and_lock_next_action($1) LIMIT 1;`,
      ['micro-worker']
    );
    if (result.rows.length === 0) return null;
    return result.rows[0];
  } finally {
    client.release();
  }
}

//--------------------------------------------------------------
// Write action result back to DB
//--------------------------------------------------------------
async function setActionResult(
  id: string,
  status: 'done' | 'failed',
  response: any,
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query(
      `SELECT masterrouter.set_action_result($1,$2,$3);`,
      [id, status, response]
    );
  } finally {
    client.release();
  }
}

//--------------------------------------------------------------
// Execute a single action via connector dispatcher
//--------------------------------------------------------------
async function executeAction(action: any): Promise<void> {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT foundation.connector_dispatch($1,$2,$3) AS resp;`,
      [
        action.connector,
        action.action_name,
        action.params ?? {},
      ]
    );

    const resp = result.rows?.[0]?.resp ?? { ok: true };
    await setActionResult(action.id, 'done', resp);

  } catch (err: any) {
    console.error('Action execution failed:', err);
    await setActionResult(action.id, 'failed', {
      error: err.message ?? 'unknown error',
    });
  } finally {
    client.release();
  }
}

//--------------------------------------------------------------
// MAIN ENTRY — Execute exactly 1 action then exit
//--------------------------------------------------------------
export async function handleRequest() {
  const action = await fetchOneAction();

  if (!action) {
    return { ok: true, message: 'no actions available' };
  }

  await executeAction(action);

  return {
    ok: true,
    message: 'action executed',
    action_id: action.id,
  };
}

// Default export
export default handleRequest;
