// Deciding which email a Microsoft sign-in is allowed to claim.
//
// Our app registration accepts ANY Microsoft tenant plus personal accounts, and
// downstream apps treat the email we sign as proof the user owns it. Graph's
// `mail` field (what this used to read) is free text that an admin of any
// tenant can set to anyone's address, so it proves nothing. We only accept an
// email Microsoft itself vouches for:
//
//   - personal Microsoft accounts (tid 9188040d-…): the `email` ID-token claim,
//     which Microsoft verifies when the account is created;
//   - work/school accounts: the `email` claim, but only when the `xms_edov`
//     optional claim says the tenant has verified ownership of that email's
//     domain (Azure: App registration → Token configuration → Add optional
//     claim → ID → `email` and `xms_edov`);
//   - optionally (MS_ALLOW_UPN_FALLBACK=true, a migration aid for before the
//     optional claims are configured): the work account's userPrincipalName,
//     which a tenant can only set to domains it has verified.
//
// The ID token comes straight from Microsoft's token endpoint over TLS in
// exchange for our one-time code and client secret, so its signature isn't
// re-verified here; aud/iss/exp are still checked as cheap sanity guards.

const PERSONAL_ACCOUNT_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

// Same shape of check the email-login path uses — the address ends up in mail
// headers and JWTs, so keep it to plain characters.
const EMAIL_RE = /^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;

function decodeIdToken(idToken) {
  if (typeof idToken !== "string") return null;
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function isTrue(v) {
  return v === true || v === 1 || v === "1" || v === "true" || v === "True";
}

// Returns { email, tid, method } or { error } — never both.
function resolveMicrosoftEmail({ idToken, profile, clientId, allowUpnFallback = false, now = Date.now() }) {
  const claims = decodeIdToken(idToken);
  if (!claims) return { error: "Microsoft did not return a usable ID token" };

  const tid = claims.tid;
  if (typeof tid !== "string" || !tid) return { error: "Microsoft ID token has no tenant" };
  if (claims.aud !== clientId) return { error: "Microsoft ID token is for a different app" };
  if (claims.iss !== `https://login.microsoftonline.com/${tid}/v2.0`) {
    return { error: "Microsoft ID token has an unexpected issuer" };
  }
  if (typeof claims.exp !== "number" || claims.exp * 1000 < now) {
    return { error: "Microsoft ID token has expired" };
  }

  const accept = (email, method) =>
    typeof email === "string" && EMAIL_RE.test(email) && email.length <= 254
      ? { email, tid, method }
      : null;

  if (tid === PERSONAL_ACCOUNT_TENANT) {
    const ok = accept(claims.email, "microsoft-personal");
    if (ok) return ok;
    return { error: "Your Microsoft account has no verified email address" };
  }

  if (isTrue(claims.xms_edov)) {
    const ok = accept(claims.email, "xms_edov");
    if (ok) return ok;
  }

  if (allowUpnFallback) {
    const ok = accept(profile && profile.userPrincipalName, "upn");
    if (ok) return ok;
  }

  return {
    error:
      "Microsoft could not verify that your organization owns this email address, so it can't be used to sign in. " +
      "Try Google sign-in instead.",
  };
}

module.exports = { resolveMicrosoftEmail, decodeIdToken, PERSONAL_ACCOUNT_TENANT };
