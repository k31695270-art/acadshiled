import express from 'express';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE_PATH = path.join(__dirname, 'backend', 'bridge.py');
const PORT = Number(process.env.PORT ?? 3000);

const RATE_LIMIT_MAX = 30;
const RATE_LIMIT_WINDOW_MS = 60_000;
const rateBuckets = new Map<string, number[]>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  if (rateBuckets.size > 512) {
    for (const [key, list] of rateBuckets.entries()) {
      const fresh = list.filter((ts) => ts >= cutoff);
      if (fresh.length === 0) {
        rateBuckets.delete(key);
      } else {
        rateBuckets.set(key, fresh);
      }
    }
  }
  const timestamps = (rateBuckets.get(ip) ?? []).filter((ts) => ts >= cutoff);
  if (timestamps.length >= RATE_LIMIT_MAX) {
    rateBuckets.set(ip, timestamps);
    return true;
  }
  timestamps.push(now);
  rateBuckets.set(ip, timestamps);
  return false;
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
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }

    const rawText = typeof req.body?.text === 'string' ? req.body.text : '';
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : null;
    const useAuxiliaryLlm = Boolean(req.body?.use_auxiliary_llm);
    const trimmed = rawText.trim().slice(0, 5000);

    if (!trimmed) {
      res.status(400).json({ detail: 'Message text is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'analyze',
        text: trimmed,
        url: rawUrl,
        use_auxiliary_llm: useAuxiliaryLlm,
      });
      res.json(result);
    } catch {
      res.status(500).json({ detail: 'Analysis failed' });
    }
  });

  app.post('/api/analyze-batch', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }

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
        messages: cleaned,
      });
      res.json(result);
    } catch (err) {
      console.error('Batch analyze error:', err);
      res.status(500).json({ detail: 'Batch analysis failed' });
    }
  });

  app.post('/api/inspect-url', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }

    const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 2000) : '';
    const includeIntel = req.body?.include_intel !== false;
    if (rawUrl.length < 3) {
      res.status(400).json({ detail: 'Valid URL is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'inspect_url',
        url: rawUrl,
        include_intel: includeIntel,
      });
      res.json(result);
    } catch {
      res.status(500).json({ detail: 'URL inspection failed' });
    }
  });

  app.post('/api/sandbox-url', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }

    const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim().slice(0, 2000) : '';
    if (rawUrl.length < 3) {
      res.status(400).json({ detail: 'Valid URL is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'sandbox_url',
        url: rawUrl,
      });
      res.json(result);
    } catch (err) {
      console.error('URL sandbox error:', err);
      res.status(500).json({ detail: 'URL sandbox detonation failed' });
    }
  });

  app.post('/api/academic/analyze', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }

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
        text,
        reference_text: referenceText,
        behavior,
      });
      res.json(result);
    } catch (err) {
      console.error('Academic analyze error:', err);
      res.status(500).json({ detail: 'Academic analysis failed' });
    }
  });

  app.post('/api/dlp/scan', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }

    const text = typeof req.body?.text === 'string' ? req.body.text.trim().slice(0, 20000) : '';
    if (!text) {
      res.status(400).json({ detail: 'Content text is required for DLP scan' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'dlp_scan',
        text,
      });
      res.json(result);
    } catch (err) {
      console.error('DLP scan error:', err);
      res.status(500).json({ detail: 'DLP scan failed' });
    }
  });

  app.post('/api/certificates/issue', async (req, res) => {
    const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
    const author = typeof req.body?.author === 'string' ? req.body.author.trim() : '';
    const institution = typeof req.body?.institution === 'string' ? req.body.institution.trim() : '';
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    const originalityScore = Number(req.body?.originality_score ?? 0);

    if (title.length < 2 || author.length < 2 || text.length < 10) {
      res.status(400).json({ detail: 'Title, author, and text are required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'cert_issue',
        title,
        author,
        institution,
        text,
        originality_score: Number.isFinite(originalityScore) ? originalityScore : 0,
      });
      res.json(result);
    } catch (err) {
      console.error('Certificate issue error:', err);
      res.status(500).json({ detail: 'Failed to issue certificate' });
    }
  });

  app.get('/api/certificates/verify', async (req, res) => {
    const query = typeof req.query?.q === 'string' ? req.query.q.trim() : '';
    try {
      const result = await runPythonBridge({
        action: 'cert_verify',
        query,
      });
      res.json(result);
    } catch (err) {
      console.error('Certificate verify error:', err);
      res.status(500).json({ detail: 'Failed to verify certificate' });
    }
  });

  app.get('/api/dashboard', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'dashboard' });
      res.json(result);
    } catch (err) {
      console.error('Dashboard error:', err);
      res.status(500).json({ detail: 'Failed to load dashboard summary' });
    }
  });

  app.post('/api/sandbox/benchmark', async (req, res) => {
    const department =
      typeof req.body?.department === 'string' ? req.body.department.trim().slice(0, 140) : '';
    const loadSize = Number(req.body?.load_size ?? 30);
    try {
      const result = await runPythonBridge({
        action: 'sandbox_benchmark',
        department,
        load_size: Number.isFinite(loadSize) ? loadSize : 30,
      });
      res.json(result);
    } catch (err) {
      console.error('Sandbox benchmark error:', err);
      res.status(500).json({ detail: 'Sandbox benchmark failed' });
    }
  });

  app.get('/api/sandbox/runs', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'sandbox_runs' });
      res.json(result);
    } catch (err) {
      console.error('Sandbox runs error:', err);
      res.status(500).json({ detail: 'Failed to load sandbox runs' });
    }
  });

  app.get('/api/saas/tenants', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'saas_list' });
      res.json(result);
    } catch (err) {
      console.error('SaaS list error:', err);
      res.status(500).json({ detail: 'Failed to load SaaS tenants' });
    }
  });

  app.post('/api/saas/tenants', async (req, res) => {
    const universityName =
      typeof req.body?.university_name === 'string' ? req.body.university_name.trim() : '';
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
        university_name: universityName,
        student_count: Number.isFinite(studentCount) ? studentCount : 1000,
        faculty_count: Number.isFinite(facultyCount) ? facultyCount : 50,
        plan_tier: planTier,
      });
      res.json(result);
    } catch (err) {
      console.error('SaaS register error:', err);
      res.status(500).json({ detail: 'Failed to register university tenant' });
    }
  });

  app.delete('/api/saas/tenants/:code', async (req, res) => {
    const code = typeof req.params?.code === 'string' ? req.params.code.trim() : '';
    try {
      const result = await runPythonBridge({
        action: 'saas_delete',
        tenant_code: code,
      });
      res.json(result);
    } catch (err) {
      console.error('SaaS delete error:', err);
      res.status(500).json({ detail: 'Failed to remove university tenant' });
    }
  });

  app.get('/api/quiz', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'quiz' });
      res.json(result);
    } catch (err) {
      console.error('Quiz load error:', err);
      res.status(500).json({ detail: 'Failed to load quiz' });
    }
  });

  app.post('/api/quiz/verify', async (req, res) => {
    const id = typeof req.body?.id === 'string' ? req.body.id.trim() : '';
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
      res.json(result);
    } catch (err) {
      console.error('Quiz verify error:', err);
      res.status(500).json({ detail: 'Quiz verification failed' });
    }
  });

  app.post('/api/report', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }
    const category = typeof req.body?.category === 'string' ? req.body.category : 'other';
    const score = Number(req.body?.score ?? 0);
    const fingerprint =
      typeof req.body?.fingerprint === 'string' ? req.body.fingerprint.trim() : '';

    if (fingerprint.length < 8) {
      res.status(400).json({ detail: 'Valid fingerprint is required' });
      return;
    }

    try {
      const result = await runPythonBridge({
        action: 'report',
        category,
        score: Number.isFinite(score) ? score : 0,
        fingerprint,
      });
      res.json(result);
    } catch {
      res.status(500).json({ detail: 'Failed to save report' });
    }
  });

  app.get('/api/trending', async (_req, res) => {
    try {
      const result = await runPythonBridge({ action: 'trending' });
      res.json(result);
    } catch {
      res.status(500).json({ detail: 'Failed to load trending scams' });
    }
  });

  app.get('/api/evaluation', async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.status(429).json({
        detail: 'تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.',
      });
      return;
    }
    try {
      const result = await runPythonBridge({ action: 'evaluate' });
      res.json(result);
    } catch {
      res.status(500).json({ detail: 'Failed to run model evaluation' });
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
