import express from 'express';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE_PATH = path.join(__dirname, 'backend', 'bridge.py');
const PORT = Number(process.env.PORT ?? 3000);

function getClientIp(req: express.Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function logSafeError(label: string, err: unknown): void {
  const message = err instanceof Error ? err.message : 'Internal error';
  console.error(`${label}: ${message.slice(0, 160)}`);
}

function runPythonBridge<T>(payload: Record<string, unknown>): Promise<T> {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [BRIDGE_PATH], {
      cwd: __dirname,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf-8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf-8');
    });
    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(stderr || `Python bridge exited with code ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout) as T);
      } catch (err) {
        reject(err);
      }
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

type BridgePayload = Record<string, unknown> & {
  _http_error?: boolean;
  status_code?: number;
  detail?: string;
};

function sendBridgeResult(res: express.Response, result: unknown): void {
  if (
    result &&
    typeof result === 'object' &&
    (result as BridgePayload)._http_error === true
  ) {
    const errPayload = result as BridgePayload;
    const status =
      typeof errPayload.status_code === 'number' && errPayload.status_code >= 400
        ? errPayload.status_code
        : 400;
    res.status(status).json({
      detail: errPayload.detail ?? 'Request rejected',
    });
    return;
  }
  res.json(result);
}

async function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
  app.use(express.json({ limit: '128kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/api/analyze', async (req, res) => {
    const clientIp = getClientIp(req);
    const rawText = typeof req.body?.text === 'string' ? req.body.text : '';
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 2000) : null;
    const useAuxiliaryLlm = Boolean(req.body?.use_auxiliary_llm);
    const trimmed = rawText.trim().slice(0, 5000);

    if (!trimmed) {
      res.status(400).json({ detail: 'Message text is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'analyze',
        _client_ip: clientIp,
        text: trimmed,
        url: rawUrl,
        use_auxiliary_llm: useAuxiliaryLlm,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Analyze error', err);
      res.status(500).json({ detail: 'Analysis failed' });
    }
  });

  app.post('/api/analyze-batch', async (req, res) => {
    const clientIp = getClientIp(req);
    const rawMessages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    const cleaned = rawMessages
      .filter((m: unknown): m is string => typeof m === 'string' && m.trim().length > 0)
      .map((m: string) => m.trim().slice(0, 5000))
      .slice(0, 25);

    if (cleaned.length === 0) {
      res.status(400).json({ detail: 'At least one message is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'analyze_batch',
        _client_ip: clientIp,
        messages: cleaned,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Batch analyze error', err);
      res.status(500).json({ detail: 'Batch analysis failed' });
    }
  });

  app.post('/api/inspect-url', async (req, res) => {
    const clientIp = getClientIp(req);
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 2000) : '';
    const includeIntel = req.body?.include_intel !== false;
    if (rawUrl.length < 3) {
      res.status(400).json({ detail: 'Valid URL is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'inspect_url',
        _client_ip: clientIp,
        url: rawUrl,
        include_intel: includeIntel,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('URL inspection error', err);
      res.status(500).json({ detail: 'URL inspection failed' });
    }
  });

  app.post('/api/sandbox-url', async (req, res) => {
    const clientIp = getClientIp(req);
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 2000) : '';
    if (rawUrl.length < 3) {
      res.status(400).json({ detail: 'Valid URL is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'sandbox_url',
        _client_ip: clientIp,
        url: rawUrl,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('URL sandbox error', err);
      res.status(500).json({ detail: 'URL sandbox detonation failed' });
    }
  });

  app.post('/api/academic/analyze', async (req, res) => {
    const clientIp = getClientIp(req);
    const text = typeof req.body?.text === 'string' ? req.body.text.trim().slice(0, 15000) : '';
    const referenceText =
      typeof req.body?.reference_text === 'string'
        ? req.body.reference_text.trim().slice(0, 15000)
        : null;
    const behavior =
      req.body?.behavior && typeof req.body.behavior === 'object' ? req.body.behavior : null;

    if (text.length < 10) {
      res.status(400).json({ detail: 'Academic text must be at least 10 characters' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'academic_analyze',
        _client_ip: clientIp,
        text,
        reference_text: referenceText,
        behavior,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Academic analyze error', err);
      res.status(500).json({ detail: 'Academic analysis failed' });
    }
  });

  app.post('/api/dlp/scan', async (req, res) => {
    const clientIp = getClientIp(req);
    const text = typeof req.body?.text === 'string' ? req.body.text.trim().slice(0, 20000) : '';
    if (!text) {
      res.status(400).json({ detail: 'Content text is required for DLP scan' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'dlp_scan',
        _client_ip: clientIp,
        text,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('DLP scan error', err);
      res.status(500).json({ detail: 'DLP scan failed' });
    }
  });

  app.post('/api/certificates/issue', async (req, res) => {
    const clientIp = getClientIp(req);
    const title = typeof req.body?.title === 'string' ? req.body.title.trim().slice(0, 160) : '';
    const author = typeof req.body?.author === 'string' ? req.body.author.trim().slice(0, 100) : '';
    const institution =
      typeof req.body?.institution === 'string' ? req.body.institution.trim().slice(0, 120) : '';
    const text = typeof req.body?.text === 'string' ? req.body.text.trim().slice(0, 15000) : '';
    const originalityScore = Number(req.body?.originality_score ?? 0);

    if (title.length < 2 || author.length < 2 || text.length < 10) {
      res.status(400).json({ detail: 'Title, author, and text are required' });
      return;
    }
    if (!Number.isFinite(originalityScore) || originalityScore < 0 || originalityScore > 100) {
      res.status(400).json({ detail: 'originality_score must be between 0 and 100' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'cert_issue',
        _client_ip: clientIp,
        title,
        author,
        institution,
        text,
        originality_score: Math.round(originalityScore),
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Certificate issue error', err);
      res.status(500).json({ detail: 'Failed to issue certificate' });
    }
  });

  app.get('/api/certificates/verify', async (req, res) => {
    const query = typeof req.query?.q === 'string' ? req.query.q.trim().slice(0, 128) : '';
    try {
      const result = await runPythonBridge({
        action: 'cert_verify',
        query,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Certificate verify error', err);
      res.status(500).json({ detail: 'Failed to verify certificate' });
    }
  });

  app.get('/api/dashboard', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'dashboard' });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dashboard error', err);
      res.status(500).json({ detail: 'Failed to load dashboard summary' });
    }
  });

  app.post('/api/sandbox/benchmark', async (req, res) => {
    const clientIp = getClientIp(req);
    const department =
      typeof req.body?.department === 'string' ? req.body.department.trim().slice(0, 140) : '';
    const loadSize = Number(req.body?.load_size ?? 30);
    try {
      const result = await runPythonBridge({
        action: 'sandbox_benchmark',
        _client_ip: clientIp,
        department,
        load_size: Number.isFinite(loadSize) ? loadSize : 30,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Sandbox benchmark error', err);
      res.status(500).json({ detail: 'Sandbox benchmark failed' });
    }
  });

  app.get('/api/sandbox/runs', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'sandbox_runs' });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Sandbox runs error', err);
      res.status(500).json({ detail: 'Failed to load sandbox runs' });
    }
  });

  app.get('/api/saas/tenants', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'saas_list' });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('SaaS list error', err);
      res.status(500).json({ detail: 'Failed to load SaaS tenants' });
    }
  });

  app.post('/api/saas/tenants', async (req, res) => {
    const clientIp = getClientIp(req);
    const universityName =
      typeof req.body?.university_name === 'string'
        ? req.body.university_name.trim().slice(0, 140)
        : '';
    const studentCount = Number(req.body?.student_count ?? 1000);
    const facultyCount = Number(req.body?.faculty_count ?? 50);
    const planTier = typeof req.body?.plan_tier === 'string' ? req.body.plan_tier : 'campus';

    if (universityName.length < 2) {
      res.status(400).json({ detail: 'University name is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'saas_register',
        _client_ip: clientIp,
        university_name: universityName,
        student_count: Number.isFinite(studentCount) ? studentCount : 1000,
        faculty_count: Number.isFinite(facultyCount) ? facultyCount : 50,
        plan_tier: planTier,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('SaaS register error', err);
      res.status(500).json({ detail: 'Failed to register university tenant' });
    }
  });

  app.delete('/api/saas/tenants/:code', async (req, res) => {
    const clientIp = getClientIp(req);
    const code = typeof req.params?.code === 'string' ? req.params.code.trim() : '';
    if (!/^IQ-UNI-\d{3,6}$/.test(code)) {
      res.status(400).json({ detail: 'Invalid tenant code format' });
      return;
    }
    try {
      const result = await runPythonBridge({
        action: 'saas_delete',
        _client_ip: clientIp,
        tenant_code: code,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('SaaS delete error', err);
      res.status(500).json({ detail: 'Failed to remove university tenant' });
    }
  });

  app.get('/api/quiz', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'quiz' });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Quiz load error', err);
      res.status(500).json({ detail: 'Failed to load quiz' });
    }
  });

  app.post('/api/quiz/verify', async (req, res) => {
    const id = typeof req.body?.id === 'string' ? req.body.id.trim().slice(0, 64) : '';
    const isScam = Boolean(req.body?.is_scam);
    const lang = req.body?.lang === 'en' ? 'en' : 'ar';
    if (!id) {
      res.status(400).json({ detail: 'Scenario id is required' });
      return;
    }
    try {
      const result = await runPythonBridge({
        action: 'quiz_verify',
        id,
        is_scam: isScam,
        lang,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Quiz verify error', err);
      res.status(500).json({ detail: 'Quiz verification failed' });
    }
  });

  app.post('/api/report', async (req, res) => {
    const clientIp = getClientIp(req);
    const category =
      typeof req.body?.category === 'string' ? req.body.category.slice(0, 64) : 'other';
    const score = Number(req.body?.score ?? 0);
    const fingerprint =
      typeof req.body?.fingerprint === 'string' ? req.body.fingerprint.trim().slice(0, 64) : '';

    if (fingerprint.length < 8) {
      res.status(400).json({ detail: 'Valid fingerprint is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'report',
        _client_ip: clientIp,
        category,
        score: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 0,
        fingerprint,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Report error', err);
      res.status(500).json({ detail: 'Failed to save report' });
    }
  });

  app.get('/api/trending', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'trending' });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Trending error', err);
      res.status(500).json({ detail: 'Failed to load trending scams' });
    }
  });

  app.get('/api/evaluation', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({ action: 'evaluate', _client_ip: clientIp });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Evaluation error', err);
      res.status(500).json({ detail: 'Failed to run model evaluation' });
    }
  });

  app.get('/api/public-config', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'public_config' });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Public config error', err);
      res.status(500).json({ detail: 'Failed to load public configuration' });
    }
  });

  app.post('/api/dev/bootstrap', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_bootstrap',
        _client_ip: clientIp,
        name: typeof req.body?.name === 'string' ? req.body.name : '',
        email: typeof req.body?.email === 'string' ? req.body.email : '',
        password: typeof req.body?.password === 'string' ? req.body.password : '',
        bootstrap_key: typeof req.body?.bootstrap_key === 'string' ? req.body.bootstrap_key : null,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev bootstrap error', err);
      res.status(500).json({ detail: 'Developer bootstrap failed' });
    }
  });

  app.post('/api/dev/login', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_login',
        _client_ip: clientIp,
        email: typeof req.body?.email === 'string' ? req.body.email : '',
        password: typeof req.body?.password === 'string' ? req.body.password : '',
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev login error', err);
      res.status(500).json({ detail: 'Developer sign-in failed' });
    }
  });

  app.post('/api/dev/invite/claim', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_invite_claim',
        _client_ip: clientIp,
        invite_token: typeof req.body?.invite_token === 'string' ? req.body.invite_token : '',
        name: typeof req.body?.name === 'string' ? req.body.name : '',
        email: typeof req.body?.email === 'string' ? req.body.email : '',
        password: typeof req.body?.password === 'string' ? req.body.password : '',
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev invite claim error', err);
      res.status(500).json({ detail: 'Invite claim failed' });
    }
  });

  app.get('/api/dev/overview', async (req, res) => {
    try {
      const result = await runPythonBridge({
        action: 'dev_overview',
        auth_header: req.headers.authorization ?? '',
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev overview error', err);
      res.status(500).json({ detail: 'Failed to load developer overview' });
    }
  });

  app.put('/api/dev/settings', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_settings_update',
        _client_ip: clientIp,
        auth_header: req.headers.authorization ?? '',
        settings: req.body && typeof req.body === 'object' ? req.body : {},
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev settings update error', err);
      res.status(500).json({ detail: 'Failed to update settings' });
    }
  });

  app.post('/api/dev/domain-rules', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_domain_add',
        _client_ip: clientIp,
        auth_header: req.headers.authorization ?? '',
        domain: typeof req.body?.domain === 'string' ? req.body.domain : '',
        rule_type: typeof req.body?.rule_type === 'string' ? req.body.rule_type : 'blocklist',
        note: typeof req.body?.note === 'string' ? req.body.note : '',
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev domain add error', err);
      res.status(500).json({ detail: 'Failed to save domain rule' });
    }
  });

  app.delete('/api/dev/domain-rules/:domain', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_domain_delete',
        _client_ip: clientIp,
        auth_header: req.headers.authorization ?? '',
        domain: typeof req.params?.domain === 'string' ? req.params.domain : '',
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev domain delete error', err);
      res.status(500).json({ detail: 'Failed to delete domain rule' });
    }
  });

  app.post('/api/dev/invites', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_invite_create',
        _client_ip: clientIp,
        auth_header: req.headers.authorization ?? '',
        role: typeof req.body?.role === 'string' ? req.body.role : 'viewer',
        note: typeof req.body?.note === 'string' ? req.body.note : '',
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev invite create error', err);
      res.status(500).json({ detail: 'Failed to create invite link' });
    }
  });

  app.patch('/api/dev/users/:userId', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
      const result = await runPythonBridge({
        action: 'dev_user_update',
        _client_ip: clientIp,
        auth_header: req.headers.authorization ?? '',
        target_user_id: Number(req.params?.userId ?? 0),
        role: typeof req.body?.role === 'string' ? req.body.role : null,
        active: typeof req.body?.active === 'boolean' ? req.body.active : null,
      });
      sendBridgeResult(res, result);
    } catch (err) {
      logSafeError('Dev user update error', err);
      res.status(500).json({ detail: 'Failed to update developer access' });
    }
  });

  const httpServer = http.createServer(app);
  const distDir = path.join(__dirname, 'dist');
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(distDir);

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        ws: { server: httpServer },
        watch: null,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Kashf server listening on http://0.0.0.0:${PORT}`);
  });
}

void createApp();
