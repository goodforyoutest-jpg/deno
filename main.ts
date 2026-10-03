// Good for You Test Engine - Deno Deploy (Improved version with better errors)

import { create } from "https://deno.land/x/djwt@v3.0.2/mod.ts";

const PROJECT_ID = Deno.env.get("FB_ADMIN_PROJECT_ID") || "";
const CLIENT_EMAIL = Deno.env.get("FB_ADMIN_CLIENT_EMAIL") || "";
const PRIVATE_KEY = (Deno.env.get("FB_ADMIN_PRIVATE_KEY") || "").replace(/\\n/g, "\n");

// ---------- Helpers ----------
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json",
  };
}

function respond(status: number, data: any) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(),
  });
}

// Convert PEM private key to ArrayBuffer
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Get Google access token
async function getAccessToken(): Promise<string> {
  if (!PROJECT_ID || !CLIENT_EMAIL || !PRIVATE_KEY) {
    throw new Error("Missing environment variables. Check FB_ADMIN_PROJECT_ID, FB_ADMIN_CLIENT_EMAIL, FB_ADMIN_PRIVATE_KEY");
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  let key;
  try {
    key = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(PRIVATE_KEY),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } catch (e) {
    throw new Error("Invalid PRIVATE_KEY format. Make sure it includes -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----");
  }

  const jwt = await create(header, claim, key);

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const data = await res.json();
  if (!data.access_token) {
    throw new Error("Failed to get access token: " + JSON.stringify(data));
  }
  return data.access_token;
}

// Verify Firebase ID Token (basic but working)
async function verifyIdToken(idToken: string): Promise<{ uid: string }> {
  const [headerB64, payloadB64] = idToken.split(".");
  if (!headerB64 || !payloadB64) throw new Error("Invalid token format");

  const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));

  if (payload.aud !== PROJECT_ID) throw new Error("Invalid audience");
  if (payload.iss !== `https://securetoken.google.com/${PROJECT_ID}`) throw new Error("Invalid issuer");
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error("Token expired");

  return { uid: payload.user_id || payload.sub };
}

// Firestore helpers with better errors
async function firestoreGet(path: string, token: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (res.status === 404) return null;

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Firestore get failed: ${res.status} - ${errorText}`);
  }

  return await res.json();
}

async function firestoreSet(path: string, fields: any, token: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}`;
  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fields: toFirestoreFields(fields) }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Firestore set failed: ${res.status} - ${errorText}`);
  }

  return await res.json();
}

function toFirestoreFields(obj: any): any {
  const fields: any = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) fields[k] = { nullValue: null };
    else if (typeof v === "string") fields[k] = { stringValue: v };
    else if (typeof v === "number") {
      fields[k] = Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
    }
    else if (typeof v === "boolean") fields[k] = { booleanValue: v };
    else if (Array.isArray(v)) {
      fields[k] = {
        arrayValue: {
          values: v.map((item) => {
            if (item === null || item === undefined) return { nullValue: null };
            if (typeof item === "string") return { stringValue: item };
            if (typeof item === "number") {
              return Number.isInteger(item) ? { integerValue: String(item) } : { doubleValue: item };
            }
            if (typeof item === "boolean") return { booleanValue: item };
            if (typeof item === "object") return { mapValue: { fields: toFirestoreFields(item) } };
            return { stringValue: String(item) };
          }),
        },
      };
    } else if (typeof v === "object") {
      fields[k] = { mapValue: { fields: toFirestoreFields(v) } };
    }
  }
  return fields;
}

function fromFirestoreValue(v: any): any {
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.integerValue !== undefined) return parseInt(v.integerValue);
  if (v.doubleValue !== undefined) return parseFloat(v.doubleValue);
  if (v.booleanValue !== undefined) return v.booleanValue;
  if (v.nullValue !== undefined) return null;
  if (v.arrayValue) return (v.arrayValue.values || []).map(fromFirestoreValue);
  if (v.mapValue) {
    const obj: any = {};
    for (const [k, val] of Object.entries(v.mapValue.fields || {})) {
      obj[k] = fromFirestoreValue(val);
    }
    return obj;
  }
  return null;
}

function fromFirestoreDoc(doc: any): any {
  if (!doc || !doc.fields) return null;
  const obj: any = {};
  for (const [k, v] of Object.entries(doc.fields)) {
    obj[k] = fromFirestoreValue(v);
  }
  return obj;
}

// ---------- Guest-test helpers ----------

// Short, unambiguous random ID for public guest-test share links
// (excludes 0/O/1/l/I to avoid misreads when read aloud or handwritten).
function genShortId(len = 10): string {
  const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

async function firestoreDelete(path: string, token: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok && res.status !== 404) {
    const errorText = await res.text();
    throw new Error(`Firestore delete failed: ${res.status} - ${errorText}`);
  }
}

// Lists every document ID in a collection (paginated, name-only — cheap).
async function firestoreListIds(collection: string, token: string): Promise<string[]> {
  const ids: string[] = [];
  let pageToken = "";
  do {
    const url = new URL(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${collection}`
    );
    url.searchParams.set("pageSize", "300");
    url.searchParams.set("mask.fieldPaths", "__name__");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`Firestore list failed: ${res.status} - ${errorText}`);
    }
    const data = await res.json();
    for (const doc of data.documents || []) {
      ids.push(doc.name.split("/").pop());
    }
    pageToken = data.nextPageToken || "";
  } while (pageToken);
  return ids;
}

// Deletes every document in a collection, a small batch at a time.
async function wipeCollection(collection: string, token: string): Promise<number> {
  const ids = await firestoreListIds(collection, token);
  const BATCH = 20;
  for (let i = 0; i < ids.length; i += BATCH) {
    const chunk = ids.slice(i, i + BATCH);
    await Promise.all(chunk.map((id) => firestoreDelete(`${collection}/${id}`, token)));
  }
  return ids.length;
}

// Finds docs in `collection` where `field` == `value` (used to pull a guest
// test's results for the owner's results view / Excel export).
async function firestoreQueryEquals(collection: string, field: string, value: string, token: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: collection }],
        where: {
          fieldFilter: {
            field: { fieldPath: field },
            op: "EQUAL",
            value: { stringValue: value },
          },
        },
      },
    }),
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Firestore query failed: ${res.status} - ${errorText}`);
  }
  const rows = await res.json();
  return (rows || []).filter((r: any) => r.document).map((r: any) => fromFirestoreDoc(r.document));
}

// Shared by /start-test and /guest-start-test: turns raw stored question
// objects into the shape the test-taking client expects (no ans/exp here —
// those live only in the separate *Answers collections).
function normalisePublicQuestions(rawQuestions: any[]): any[] {
  return (rawQuestions || [])
    .map((q: any) => ({
      q: q.q || q.question || "",
      opts: q.opts || q.options || [],
      section: q.section || "",
      passage: q.passage || "",
      image: q.image || null,
      imageCaption: q.imageCaption || "",
    }))
    .filter((q: any) => q.q && Array.isArray(q.opts) && q.opts.length >= 2);
}

function validateStudentInfo(infoFields: any[], studentInfo: any): string | null {
  if (!studentInfo || typeof studentInfo !== "object") return "Missing student information";
  for (const f of infoFields || []) {
    if (f.required) {
      const v = studentInfo[f.key];
      if (typeof v !== "string" || !v.trim()) return `"${f.label}" is required`;
    }
  }
  return null;
}

// Keeps only the keys the test actually declared, so a student can't inject
// arbitrary extra fields into their own result document.
function sanitizeStudentInfo(infoFields: any[], studentInfo: any): any {
  const clean: any = {};
  for (const f of infoFields || []) {
    const v = studentInfo?.[f.key];
    clean[f.key] = typeof v === "string" ? v.trim().slice(0, 200) : "";
  }
  return clean;
}

// ---------- Main Handler ----------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  if (req.method !== "POST") {
    return respond(405, { error: "Only POST method is supported" });
  }

  const url = new URL(req.url);
  const path = url.pathname;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return respond(400, { error: "Invalid JSON body" });
  }

  // ==================== GUEST-CREATE-TEST (public — no account needed) ====================
  // Anyone can call this; that's the point of the feature. Keep validation
  // tight since it's the one endpoint with zero auth.
  if (path.endsWith("/guest-create-test")) {
    try {
      const title = typeof body.title === "string" ? body.title.trim().slice(0, 200) : "";
      if (!title) return respond(400, { error: "Test title is required" });

      const rawQuestions = Array.isArray(body.questions) ? body.questions.slice(0, 200) : [];
      if (rawQuestions.length === 0) return respond(400, { error: "At least one question is required" });

      const infoFieldsIn = Array.isArray(body.infoFields) ? body.infoFields.slice(0, 20) : [];
      const infoFields = infoFieldsIn
        .filter(
          (f: any) =>
            f && typeof f.key === "string" && typeof f.label === "string" && f.key.trim() && f.label.trim()
        )
        .map((f: any) => ({
          key: f.key.trim().slice(0, 60),
          label: f.label.trim().slice(0, 100),
          required: !!f.required,
        }));
      if (infoFields.length === 0) {
        return respond(400, { error: "At least one student info field is required" });
      }

      const publicQuestions = rawQuestions
        .map((q: any) => ({
          q: typeof q.q === "string" ? q.q : "",
          opts: Array.isArray(q.opts) ? q.opts.map((o: any) => String(o)) : [],
          section: typeof q.section === "string" ? q.section : "",
          passage: typeof q.passage === "string" ? q.passage : "",
          image: q.image || null,
          imageCaption: typeof q.imageCaption === "string" ? q.imageCaption : "",
        }))
        .filter((q: any) => q.q && q.opts.length >= 2);
      if (publicQuestions.length === 0) {
        return respond(400, { error: "No valid questions were provided" });
      }

      const answerKey = rawQuestions.map((q: any) => ({
        ans: typeof q.ans === "number" && Number.isInteger(q.ans) ? q.ans : null,
        exp: typeof q.exp === "string" ? q.exp : "",
      }));

      const durationMinutes = parseFloat(body.durationMinutes) || 60;
      const marksCorrect = parseFloat(body.marksCorrect) || 1;
      const negativeMarking = body.negativeMarking === true;
      const marksWrong = negativeMarking ? parseFloat(body.marksWrong) || 0.25 : 0;
      const randomizeQuestions = body.randomizeQuestions === true;

      const token = await getAccessToken();
      const guestTestId = genShortId(10);
      const ownerKey = crypto.randomUUID();
      const createdAt = new Date().toISOString();

      await firestoreSet(
        `guestTests/${guestTestId}`,
        {
          title,
          subject: typeof body.subject === "string" ? body.subject.trim().slice(0, 200) : "",
          durationMinutes,
          questions: publicQuestions,
          active: true,
          negativeMarking,
          marksCorrect,
          marksWrong,
          randomizeQuestions,
          infoFields,
          ownerKey,
          createdAt,
        },
        token
      );
      await firestoreSet(`guestTestAnswers/${guestTestId}`, { answers: answerKey }, token);

      return respond(200, { guestTestId, ownerKey });
    } catch (e: any) {
      console.error(e);
      return respond(500, { error: e.message || "Server error", details: String(e) });
    }
  }

  // ==================== GUEST-RESULTS (gated by ownerKey, not login) ====================
  if (path.endsWith("/guest-results")) {
    try {
      const guestTestId = typeof body.guestTestId === "string" ? body.guestTestId.trim() : "";
      const ownerKey = typeof body.ownerKey === "string" ? body.ownerKey.trim() : "";
      if (!guestTestId || !ownerKey) return respond(400, { error: "Missing guestTestId or ownerKey" });

      const token = await getAccessToken();
      const testDoc = await firestoreGet(`guestTests/${guestTestId}`, token);
      if (!testDoc) return respond(404, { error: "Guest test not found (it may have already expired)" });
      const test = fromFirestoreDoc(testDoc);

      if (test.ownerKey !== ownerKey) {
        return respond(403, { error: "Invalid access key for this test" });
      }

      const results = await firestoreQueryEquals("guestResults", "guestTestId", guestTestId, token);

      return respond(200, {
        test: { title: test.title, subject: test.subject, infoFields: test.infoFields || [] },
        results,
      });
    } catch (e: any) {
      console.error(e);
      return respond(500, { error: e.message || "Server error", details: String(e) });
    }
  }

  // ==================== GUEST-TEST-INFO (public — powers the student info form) ====================
  // Returns only what the gate screen needs. No questions, no answers, no ownerKey.
  if (path.endsWith("/guest-test-info")) {
    try {
      const guestTestId = typeof body.guestTestId === "string" ? body.guestTestId.trim() : "";
      if (!guestTestId) return respond(400, { error: "Missing guestTestId" });

      const token = await getAccessToken();
      const testDoc = await firestoreGet(`guestTests/${guestTestId}`, token);
      if (!testDoc) {
        return respond(404, { error: "This guest test no longer exists. Guest tests are deleted every night at midnight IST." });
      }
      const test = fromFirestoreDoc(testDoc);
      if (test.active === false) return respond(403, { error: "This test is not currently open" });

      return respond(200, {
        title: test.title || "Guest Test",
        subject: test.subject || "",
        durationMinutes: parseFloat(test.durationMinutes) || 0,
        questionCount: normalisePublicQuestions(test.questions).length,
        infoFields: (test.infoFields || []).map((f: any) => ({
          key: f.key,
          label: f.label,
          required: !!f.required,
        })),
      });
    } catch (e: any) {
      console.error(e);
      return respond(500, { error: e.message || "Server error", details: String(e) });
    }
  }

  // Every remaining route needs a signed-in (or anonymous) Firebase user.
  let uid: string;
  try {
    const authHeader = req.headers.get("Authorization") || "";
    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match) throw new Error("Not signed in. Missing Authorization header.");
    const decoded = await verifyIdToken(match[1]);
    uid = decoded.uid;
  } catch (e: any) {
    return respond(401, { error: e.message || "Authentication failed" });
  }

  try {
    const token = await getAccessToken();

    // ==================== START-TEST ====================
    if (path.endsWith("/start-test") || path === "/start-test") {
      const testId = typeof body.testId === "string" ? body.testId.trim() : "";
      if (!testId) return respond(400, { error: "Missing testId" });

      const testDoc = await firestoreGet(`tests/${testId}`, token);
      if (!testDoc) return respond(404, { error: "Test not found" });
      const test = fromFirestoreDoc(testDoc);

      if (test.active !== true) {
        return respond(403, { error: "This test is not currently live" });
      }

      const userDoc = await firestoreGet(`users/${uid}`, token);
      const user = fromFirestoreDoc(userDoc) || {};
      const userOrg = user.orgCode || null;

      if (test.orgCode && userOrg && test.orgCode !== userOrg) {
        return respond(403, { error: "This test is not available to your organisation" });
      }

      const attemptPath = `attempts/${testId}_${uid}`;
      const attemptDoc = await firestoreGet(attemptPath, token);

      if (attemptDoc) {
        const attempt = fromFirestoreDoc(attemptDoc);
        if (attempt.status === "completed") {
          return respond(200, {
            status: "completed",
            resultId: attempt.resultId || null,
          });
        }

        // Resume
        return respond(200, {
          status: "in-progress",
          attemptDocId: `${testId}_${uid}`,
          testTitle: test.title || "Live Test",
          questions: attempt.questionsSnapshot || [],
          answered: attempt.answered || [],
          currentQ: attempt.currentQ || 0,
          tabSwitchCount: attempt.tabSwitchCount || 0,
          cheatLog: attempt.cheatLog || [],
          remainingSecs: 0,
          durationMinutes: attempt.durationMinutes || 0,
          marksCorrect: attempt.marksCorrect ?? 1,
          marksWrong: attempt.marksWrong ?? 0,
          negativeMarking: !!attempt.negativeMarking,
          reloadIsViolation: true,
          autoSubmitReason: null,
        });
      }

      // Fresh start
      const publicQuestions = normalisePublicQuestions(test.questions);

      if (publicQuestions.length === 0) {
        return respond(400, { error: "This test has no valid questions" });
      }

      let order = publicQuestions.map((_: any, i: number) => i);
      if (test.randomizeQuestions) {
        for (let i = order.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [order[i], order[j]] = [order[j], order[i]];
        }
      }
      const shown = order.map((i: number) => publicQuestions[i]);

      const durationMinutes = parseFloat(test.durationMinutes) || 0;
      const marksCorrect = parseFloat(test.marksCorrect) || 1;
      const marksWrong = parseFloat(test.marksWrong) || 0;
      const negativeMarking = test.negativeMarking === true;

      await firestoreSet(
        attemptPath,
        {
          userId: uid,
          orgCode: userOrg,
          testId,
          durationMinutes,
          marksCorrect,
          marksWrong,
          negativeMarking,
          answerKeyOrder: order,
          questionsSnapshot: shown,
          answered: new Array(shown.length).fill(null),
          currentQ: 0,
          tabSwitchCount: 0,
          cheatLog: [],
          status: "in-progress",
        },
        token
      );

      return respond(200, {
        status: "in-progress",
        attemptDocId: `${testId}_${uid}`,
        testTitle: test.title || "Live Test",
        questions: shown,
        answered: new Array(shown.length).fill(null),
        currentQ: 0,
        tabSwitchCount: 0,
        cheatLog: [],
        remainingSecs: durationMinutes * 60,
        durationMinutes,
        marksCorrect,
        marksWrong,
        negativeMarking,
        reloadIsViolation: false,
        autoSubmitReason: null,
      });
    }

    // ==================== SUBMIT-TEST ====================
    if (path.endsWith("/submit-test") || path === "/submit-test") {
      const testId = typeof body.testId === "string" ? body.testId.trim() : "";
      if (!testId) return respond(400, { error: "Missing testId" });

      const attemptPath = `attempts/${testId}_${uid}`;
      const attemptDoc = await firestoreGet(attemptPath, token);
      if (!attemptDoc) {
        return respond(400, { error: "No in-progress attempt found" });
      }
      const attempt = fromFirestoreDoc(attemptDoc);

      if (attempt.status === "completed") {
        return respond(200, {
          alreadyCompleted: true,
          resultId: attempt.resultId || null,
        });
      }

      const keyDoc = await firestoreGet(`testAnswers/${testId}`, token);
      if (!keyDoc) {
        return respond(500, { error: "Answer key missing for this test" });
      }
      const keyData = fromFirestoreDoc(keyDoc);
      const keyArr = keyData.answers || [];

      const order = attempt.answerKeyOrder || [];
      const shown = attempt.questionsSnapshot || [];
      const n = shown.length;

      const answeredIn = Array.isArray(body.answered) ? body.answered : attempt.answered || [];
      const answered = new Array(n).fill(null);
      for (let i = 0; i < n; i++) {
        const v = answeredIn[i];
        const optCount = Array.isArray(shown[i]?.opts) ? shown[i].opts.length : 0;
        answered[i] = Number.isInteger(v) && v >= 0 && v < optCount ? v : null;
      }

      let correct = 0;
      let wrongCount = 0;
      const sectionStats: any = {};
      const graded = [];

      for (let i = 0; i < n; i++) {
        const key = keyArr[order[i]] || {};
        const ans = Number.isInteger(key.ans) ? key.ans : null;
        const exp = typeof key.exp === "string" ? key.exp : "";
        graded.push({ ans, exp });

        const sel = answered[i];
        const isSkip = sel === null;
        const isOk = !isSkip && ans !== null && sel === ans;

        if (isOk) correct++;
        if (!isSkip && !isOk) wrongCount++;

        const sec = shown[i].section || "General";
        if (!sectionStats[sec]) sectionStats[sec] = { c: 0, w: 0, u: 0, t: 0 };
        sectionStats[sec].t++;
        if (isOk) sectionStats[sec].c++;
        else if (isSkip) sectionStats[sec].u++;
        else sectionStats[sec].w++;
      }

      const total = n;
      const unattempted = answered.filter((a) => a === null).length;
      const accuracy = total - unattempted > 0 ? Math.round((correct / (total - unattempted)) * 100) : 0;

      const marksCorrect = attempt.marksCorrect ?? 1;
      const marksWrong = attempt.marksWrong ?? 0;
      const negativeMarking = !!attempt.negativeMarking;

      const rawScore = correct * marksCorrect - (negativeMarking ? wrongCount * marksWrong : 0);
      const maxScore = total * marksCorrect;
      const finalScore = Math.max(0, rawScore);
      const pct = maxScore > 0 ? Math.min(100, Math.round((finalScore / maxScore) * 100)) : 0;

      const resultId = crypto.randomUUID();
      const resultPath = `results/${resultId}`;

      await firestoreSet(
        resultPath,
        {
          userId: uid,
          orgCode: attempt.orgCode || null,
          testId,
          testTitle: "Live Test",
          correct,
          wrong: wrongCount,
          skipped: unattempted,
          total,
          percentage: pct,
          accuracy,
          finalScore,
          maxScore,
          marksCorrect,
          marksWrong: negativeMarking ? marksWrong : 0,
          negativeMarking,
          timeTaken: body.timerSeconds || 0,
          sectionStats,
          autoSubmitted: !!body.autoSubmit,
          tabSwitchCount: body.tabSwitchCount || 0,
          answers: answered,
          questionsSnapshot: shown.map((q: any, i: number) => ({
            ...q,
            ans: graded[i].ans,
            exp: graded[i].exp,
          })),
        },
        token
      );

      await firestoreSet(
        attemptPath,
        {
          ...attempt,
          status: "completed",
          resultId,
          answered,
        },
        token
      );

      return respond(200, {
        correct,
        wrong: wrongCount,
        unattempted,
        total,
        pct,
        accuracy,
        finalScore,
        maxScore,
        marksCorrect,
        marksWrong: negativeMarking ? marksWrong : 0,
        negativeMarking,
        sectionStats,
        rank: 1,
        resultId,
        graded,
      });
    }

    // ==================== GUEST-START-TEST ====================
    if (path.endsWith("/guest-start-test")) {
      const guestTestId = typeof body.guestTestId === "string" ? body.guestTestId.trim() : "";
      if (!guestTestId) return respond(400, { error: "Missing guestTestId" });

      const testDoc = await firestoreGet(`guestTests/${guestTestId}`, token);
      if (!testDoc) return respond(404, { error: "This guest test no longer exists (it may have expired)" });
      const test = fromFirestoreDoc(testDoc);

      const infoFields = test.infoFields || [];
      const infoError = validateStudentInfo(infoFields, body.studentInfo);
      if (infoError) return respond(400, { error: infoError });
      const studentInfo = sanitizeStudentInfo(infoFields, body.studentInfo);

      const attemptPath = `guestAttempts/${guestTestId}_${uid}`;
      const attemptDoc = await firestoreGet(attemptPath, token);

      if (attemptDoc) {
        const attempt = fromFirestoreDoc(attemptDoc);
        if (attempt.status === "completed") {
          return respond(200, { status: "completed", resultId: attempt.resultId || null });
        }

        // Resume. The clock is derived from the stored start time so a refresh
        // can't reset or zero it, and the reload itself counts as one strike
        // (the test page tells students that reloading is recorded).
        const resumeDuration = attempt.durationMinutes || 0;
        let remainingSecs = 0;
        let autoSubmitReason: string | null = null;
        if (resumeDuration > 0) {
          remainingSecs = attempt.startedAt
            ? Math.max(0, Math.round(resumeDuration * 60 - (Date.now() - attempt.startedAt) / 1000))
            : resumeDuration * 60;
          if (remainingSecs <= 0) autoSubmitReason = "time";
        }

        const resumedStrikes = (attempt.tabSwitchCount || 0) + 1;
        const resumedLog = [
          ...(Array.isArray(attempt.cheatLog) ? attempt.cheatLog : []),
          { type: "reload", source: "resume", ts: Date.now(), count: resumedStrikes },
        ].slice(-50);
        if (resumedStrikes >= 4) autoSubmitReason = "violations";

        await firestoreSet(
          attemptPath,
          { ...attempt, tabSwitchCount: resumedStrikes, cheatLog: resumedLog },
          token
        );

        return respond(200, {
          status: "in-progress",
          attemptDocId: `${guestTestId}_${uid}`,
          testTitle: test.title || "Guest Test",
          questions: attempt.questionsSnapshot || [],
          answered: attempt.answered || [],
          currentQ: attempt.currentQ || 0,
          tabSwitchCount: resumedStrikes,
          cheatLog: resumedLog,
          remainingSecs,
          durationMinutes: resumeDuration,
          marksCorrect: attempt.marksCorrect ?? 1,
          marksWrong: attempt.marksWrong ?? 0,
          negativeMarking: !!attempt.negativeMarking,
          reloadIsViolation: true,
          autoSubmitReason,
        });
      }

      // Fresh start
      const publicQuestions = normalisePublicQuestions(test.questions);
      if (publicQuestions.length === 0) {
        return respond(400, { error: "This test has no valid questions" });
      }

      let order = publicQuestions.map((_: any, i: number) => i);
      if (test.randomizeQuestions) {
        for (let i = order.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [order[i], order[j]] = [order[j], order[i]];
        }
      }
      const shown = order.map((i: number) => publicQuestions[i]);

      const durationMinutes = parseFloat(test.durationMinutes) || 0;
      const marksCorrect = parseFloat(test.marksCorrect) || 1;
      const marksWrong = parseFloat(test.marksWrong) || 0;
      const negativeMarking = test.negativeMarking === true;

      await firestoreSet(
        attemptPath,
        {
          userId: uid,
          guestTestId,
          studentInfo,
          startedAt: Date.now(),
          durationMinutes,
          marksCorrect,
          marksWrong,
          negativeMarking,
          answerKeyOrder: order,
          questionsSnapshot: shown,
          answered: new Array(shown.length).fill(null),
          currentQ: 0,
          tabSwitchCount: 0,
          cheatLog: [],
          status: "in-progress",
        },
        token
      );

      return respond(200, {
        status: "in-progress",
        attemptDocId: `${guestTestId}_${uid}`,
        testTitle: test.title || "Guest Test",
        questions: shown,
        answered: new Array(shown.length).fill(null),
        currentQ: 0,
        tabSwitchCount: 0,
        cheatLog: [],
        remainingSecs: durationMinutes * 60,
        durationMinutes,
        marksCorrect,
        marksWrong,
        negativeMarking,
        reloadIsViolation: false,
        autoSubmitReason: null,
      });
    }

    // ==================== GUEST-SUBMIT-TEST ====================
    if (path.endsWith("/guest-submit-test")) {
      const guestTestId = typeof body.guestTestId === "string" ? body.guestTestId.trim() : "";
      if (!guestTestId) return respond(400, { error: "Missing guestTestId" });

      const attemptPath = `guestAttempts/${guestTestId}_${uid}`;
      const attemptDoc = await firestoreGet(attemptPath, token);
      if (!attemptDoc) {
        return respond(400, { error: "No in-progress attempt found" });
      }
      const attempt = fromFirestoreDoc(attemptDoc);

      if (attempt.status === "completed") {
        return respond(200, {
          alreadyCompleted: true,
          resultId: attempt.resultId || null,
        });
      }

      const keyDoc = await firestoreGet(`guestTestAnswers/${guestTestId}`, token);
      if (!keyDoc) {
        return respond(500, { error: "Answer key missing for this test" });
      }
      const keyData = fromFirestoreDoc(keyDoc);
      const keyArr = keyData.answers || [];

      const order = attempt.answerKeyOrder || [];
      const shown = attempt.questionsSnapshot || [];
      const n = shown.length;

      const answeredIn = Array.isArray(body.answered) ? body.answered : attempt.answered || [];
      const answered = new Array(n).fill(null);
      for (let i = 0; i < n; i++) {
        const v = answeredIn[i];
        const optCount = Array.isArray(shown[i]?.opts) ? shown[i].opts.length : 0;
        answered[i] = Number.isInteger(v) && v >= 0 && v < optCount ? v : null;
      }

      let correct = 0;
      let wrongCount = 0;
      const sectionStats: any = {};
      const graded = [];

      for (let i = 0; i < n; i++) {
        const key = keyArr[order[i]] || {};
        const ans = Number.isInteger(key.ans) ? key.ans : null;
        const exp = typeof key.exp === "string" ? key.exp : "";
        graded.push({ ans, exp });

        const sel = answered[i];
        const isSkip = sel === null;
        const isOk = !isSkip && ans !== null && sel === ans;

        if (isOk) correct++;
        if (!isSkip && !isOk) wrongCount++;

        const sec = shown[i].section || "General";
        if (!sectionStats[sec]) sectionStats[sec] = { c: 0, w: 0, u: 0, t: 0 };
        sectionStats[sec].t++;
        if (isOk) sectionStats[sec].c++;
        else if (isSkip) sectionStats[sec].u++;
        else sectionStats[sec].w++;
      }

      const total = n;
      const unattempted = answered.filter((a) => a === null).length;
      const accuracy = total - unattempted > 0 ? Math.round((correct / (total - unattempted)) * 100) : 0;

      const marksCorrect = attempt.marksCorrect ?? 1;
      const marksWrong = attempt.marksWrong ?? 0;
      const negativeMarking = !!attempt.negativeMarking;

      const rawScore = correct * marksCorrect - (negativeMarking ? wrongCount * marksWrong : 0);
      const maxScore = total * marksCorrect;
      const finalScore = Math.max(0, rawScore);
      const pct = maxScore > 0 ? Math.min(100, Math.round((finalScore / maxScore) * 100)) : 0;

      const resultId = crypto.randomUUID();
      const resultPath = `guestResults/${resultId}`;

      await firestoreSet(
        resultPath,
        {
          guestTestId,
          studentInfo: attempt.studentInfo || {},
          testTitle: "Guest Test",
          correct,
          wrong: wrongCount,
          skipped: unattempted,
          total,
          percentage: pct,
          accuracy,
          finalScore,
          maxScore,
          marksCorrect,
          marksWrong: negativeMarking ? marksWrong : 0,
          negativeMarking,
          timeTaken: body.timerSeconds || 0,
          sectionStats,
          autoSubmitted: !!body.autoSubmit,
          tabSwitchCount: body.tabSwitchCount || 0,
          answers: answered,
          questionsSnapshot: shown.map((q: any, i: number) => ({
            ...q,
            ans: graded[i].ans,
            exp: graded[i].exp,
          })),
        },
        token
      );

      await firestoreSet(
        attemptPath,
        {
          ...attempt,
          status: "completed",
          resultId,
          answered,
        },
        token
      );

      return respond(200, {
        correct,
        wrong: wrongCount,
        unattempted,
        total,
        pct,
        accuracy,
        finalScore,
        maxScore,
        marksCorrect,
        marksWrong: negativeMarking ? marksWrong : 0,
        negativeMarking,
        sectionStats,
        rank: 1,
        resultId,
        graded,
      });
    }

    // ==================== GUEST-SAVE-PROGRESS ====================
    // Autosave for the test page. Guest collections have no client access,
    // so the browser sends progress here. Firestore PATCH without a mask
    // replaces the whole doc, so the stored attempt is spread back in.
    if (path.endsWith("/guest-save-progress")) {
      const guestTestId = typeof body.guestTestId === "string" ? body.guestTestId.trim() : "";
      if (!guestTestId) return respond(400, { error: "Missing guestTestId" });

      const attemptPath = `guestAttempts/${guestTestId}_${uid}`;
      const attemptDoc = await firestoreGet(attemptPath, token);
      if (!attemptDoc) return respond(404, { error: "No attempt found" });
      const attempt = fromFirestoreDoc(attemptDoc);

      // Never write over a submitted attempt.
      if (attempt.status === "completed") return respond(200, { ok: true, completed: true });

      const shown = attempt.questionsSnapshot || [];
      const n = shown.length;

      const answeredIn = Array.isArray(body.answered) ? body.answered : attempt.answered || [];
      const answered = new Array(n).fill(null);
      for (let i = 0; i < n; i++) {
        const v = answeredIn[i];
        const optCount = Array.isArray(shown[i]?.opts) ? shown[i].opts.length : 0;
        answered[i] = Number.isInteger(v) && v >= 0 && v < optCount ? v : null;
      }

      const rawQ = Number.isInteger(body.currentQ) ? body.currentQ : 0;
      const currentQ = Math.min(Math.max(rawQ, 0), Math.max(n - 1, 0));

      // Strike count can only go up — a client can't wipe its own violations.
      const clientStrikes = Number.isInteger(body.tabSwitchCount) ? body.tabSwitchCount : 0;
      const tabSwitchCount = Math.min(Math.max(attempt.tabSwitchCount || 0, clientStrikes), 4);

      const storedLog = Array.isArray(attempt.cheatLog) ? attempt.cheatLog : [];
      const incomingLog = (Array.isArray(body.cheatLog) ? body.cheatLog : [])
        .slice(-50)
        .map((e: any) => ({
          type: typeof e?.type === "string" ? e.type.slice(0, 30) : "tab_switch",
          source: typeof e?.source === "string" ? e.source.slice(0, 30) : "",
          ts: Number.isFinite(e?.ts) ? Math.floor(e.ts) : 0,
          count: Number.isInteger(e?.count) ? e.count : 0,
        }));
      // Keep whichever log is longer so server-side reload entries survive.
      const cheatLog = incomingLog.length >= storedLog.length ? incomingLog : storedLog;

      await firestoreSet(
        attemptPath,
        { ...attempt, answered, currentQ, tabSwitchCount, cheatLog },
        token
      );
      return respond(200, { ok: true });
    }

    return respond(404, { error: "Not found. Use /start-test or /submit-test" });
  } catch (e: any) {
    console.error(e);
    return respond(500, {
      error: e.message || "Server error",
      details: String(e),
    });
  }
});

// ---------- Nightly guest-data wipe ----------
// 30 18 * * * UTC == 00:00 IST. Guest tests are meant to be same-day-only —
// everything under guestTests/guestTestAnswers/guestAttempts/guestResults
// is unconditionally deleted every night, no per-document expiry check needed.
Deno.cron("wipe guest test data", "30 18 * * *", async () => {
  try {
    const token = await getAccessToken();
    const collections = ["guestTests", "guestTestAnswers", "guestAttempts", "guestResults"];
    for (const collection of collections) {
      const count = await wipeCollection(collection, token);
      console.log(`[guest-wipe] removed ${count} doc(s) from ${collection}`);
    }
  } catch (e) {
    console.error("[guest-wipe] failed:", e);
  }
});
