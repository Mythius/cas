const test = require("node:test");
const assert = require("node:assert");
const { resolveMicrosoftEmail, PERSONAL_ACCOUNT_TENANT } = require("../auth/microsoftIdentity.js");

const CLIENT_ID = "ed29c5c0-2bb2-4cc1-8c6e-13fa647f45b0";
const WORK_TID = "11111111-2222-3333-4444-555555555555";

function idToken(overrides = {}) {
  const claims = {
    aud: CLIENT_ID,
    tid: WORK_TID,
    iss: `https://login.microsoftonline.com/${overrides.tid ?? WORK_TID}/v2.0`,
    exp: Math.floor(Date.now() / 1000) + 600,
    email: "jane@partner.org",
    ...overrides,
  };
  for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "RS256" })}.${enc(claims)}.sig`;
}
const resolve = (token, extra = {}) =>
  resolveMicrosoftEmail({ idToken: token, clientId: CLIENT_ID, profile: {}, ...extra });

test("work account with xms_edov=true is accepted via the email claim", () => {
  const r = resolve(idToken({ xms_edov: true }));
  assert.deepStrictEqual(r, { email: "jane@partner.org", tid: WORK_TID, method: "xms_edov" });
});

test("work account WITHOUT xms_edov is rejected even if Graph mail says otherwise", () => {
  const r = resolve(idToken(), { profile: { mail: "ceo@cgcharitable.org", userPrincipalName: "x@evil.onmicrosoft.com" } });
  assert.ok(r.error);
  assert.strictEqual(r.email, undefined);
});

test("work account with xms_edov=false is rejected", () => {
  assert.ok(resolve(idToken({ xms_edov: false })).error);
});

test("personal Microsoft account uses the email claim", () => {
  const r = resolve(idToken({ tid: PERSONAL_ACCOUNT_TENANT, email: "sam@outlook.com" }));
  assert.strictEqual(r.email, "sam@outlook.com");
  assert.strictEqual(r.method, "microsoft-personal");
});

test("personal account with no email claim is rejected", () => {
  assert.ok(resolve(idToken({ tid: PERSONAL_ACCOUNT_TENANT, email: undefined })).error);
});

test("UPN fallback is off by default and used only when enabled", () => {
  const profile = { userPrincipalName: "jane@partner.org" };
  const token = idToken({ email: undefined });
  assert.ok(resolve(token, { profile }).error);
  assert.strictEqual(resolve(token, { profile, allowUpnFallback: true }).email, "jane@partner.org");
});

test("UPN fallback never reads Graph mail", () => {
  const r = resolve(idToken({ email: undefined }), { profile: { mail: "ceo@cgcharitable.org" }, allowUpnFallback: true });
  assert.ok(r.error);
});

test("token for a different app, wrong issuer, or expired is rejected", () => {
  assert.ok(resolve(idToken({ xms_edov: true, aud: "someone-else" })).error);
  assert.ok(resolve(idToken({ xms_edov: true, iss: "https://evil.example/v2.0" })).error);
  assert.ok(resolve(idToken({ xms_edov: true, exp: 1 })).error);
});

test("missing, malformed or tenant-less tokens are rejected", () => {
  assert.ok(resolve(undefined).error);
  assert.ok(resolve("not.a.jwt").error);
  assert.ok(resolve(idToken({ xms_edov: true, tid: undefined })).error);
});

test("emails with header/shell-unsafe characters are rejected", () => {
  for (const bad of ["a b@x.org", "a@x.org\nBcc: v@y.org", "a@x.org;ls", "<a@x.org>"]) {
    assert.ok(resolve(idToken({ xms_edov: true, email: bad })).error, bad);
  }
});
