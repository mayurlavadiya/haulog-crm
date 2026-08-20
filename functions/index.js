const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2/options');
const admin = require('firebase-admin');
const crypto = require('crypto');

admin.initializeApp();
setGlobalOptions({ region: 'us-central1', maxInstances: 10 });

const db = admin.firestore();
const auth = admin.auth();
const APP_URL = (process.env.APP_URL || 'https://haulog-crm.web.app').replace(/\/$/, '');
const INVITE_TTL_MS = 48 * 60 * 60 * 1000;

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function isAdminRequest(request) {
  return !!request.auth && ['Admin', 'Super Admin'].includes(request.auth.token?.role);
}

async function isAdminFromFirestore(uid) {
  const snap = await db.collection('users').doc(uid).get();
  return snap.exists && ['Admin', 'Super Admin'].includes(snap.data()?.role);
}

function cleanRoleName(value) {
  return String(value || '').trim();
}

exports.adminCreateUserInvite = onCall(async (request) => {
  if (!request.auth || !(await isAdminFromFirestore(request.auth.uid))) {
    throw new HttpsError('permission-denied', 'Only Admin / Super Admin can create users.');
  }

  const data = request.data || {};
  const name = String(data.name || '').trim();
  const email = normalizeEmail(data.email);
  const phone = String(data.phone || '').replace(/\D/g, '');
  const roleName = cleanRoleName(data.role);

  if (!name || !email || !roleName) {
    throw new HttpsError('invalid-argument', 'Name, email and role are required.');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpsError('invalid-argument', 'Enter a valid email address.');
  }
  if (phone && !/^\d{10}$/.test(phone)) {
    throw new HttpsError('invalid-argument', 'Enter a valid 10-digit phone number.');
  }

  const roleSnap = await db.collection('roles').where('name', '==', roleName).limit(1).get();
  if (roleSnap.empty) {
    throw new HttpsError('failed-precondition', 'The selected role does not exist.');
  }
  const role = roleSnap.docs[0].data();

  try {
    // Prevent duplicate Auth accounts.
    try {
      await auth.getUserByEmail(email);
      throw new HttpsError('already-exists', 'A user with this email already exists.');
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      if (err.code !== 'auth/user-not-found') throw err;
    }

    // Firebase Auth account is created without a usable password. The user sets it
    // through the one-time invitation flow below.
    const userRecord = await auth.createUser({
      email,
      emailVerified: false,
      displayName: name,
      ...(phone ? { phoneNumber: `+91${phone}` } : {}),
      disabled: false,
    });

    const uid = userRecord.uid;
    const now = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + INVITE_TTL_MS);
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);

    await db.collection('users').doc(uid).set({
      name,
      email,
      phone,
      role: roleName,
      responsibilities: role.responsibilities || '',
      permissions: role.permissions || [],
      status: 'Active',
      invitationStatus: 'Pending',
      invitedByUid: request.auth.uid,
      invitedAt: now,
      createdAt: now,
    });

    await db.collection('userInvites').doc(tokenHash).set({
      uid,
      name,
      email,
      role: roleName,
      createdAt: now,
      expiresAt,
      used: false,
    });

    const inviteUrl = `${APP_URL}/?invite=${encodeURIComponent(rawToken)}`;
    const inviterSnap = await db.collection('users').doc(request.auth.uid).get();
    const inviterName = inviterSnap.exists ? (inviterSnap.data()?.name || 'Haulog CRM Admin') : 'Haulog CRM Admin';

    // Requires the official Firebase Trigger Email extension on the `mail` collection.
    // The extension handles SMTP delivery; no SMTP credentials are stored in this code.
    await db.collection('mail').add({
      to: email,
      message: {
        subject: 'Your Haulog CRM account invitation',
        text: `Hello ${name},\n\n${inviterName} has created your Haulog CRM account with the ${roleName} role.\n\nActivate your account and create your password here:\n${inviteUrl}\n\nThis invitation expires in 48 hours and can be used only once.\n\nHaulog CRM`,
        html: `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#111827;line-height:1.6"><div style="max-width:620px;margin:auto;padding:32px"><h2 style="color:#0000FE">Welcome to Haulog CRM</h2><p>Hello ${escapeHtml(name)},</p><p><strong>${escapeHtml(inviterName)}</strong> has created your Haulog CRM account.</p><p><strong>Assigned role:</strong> ${escapeHtml(roleName)}</p><p>Click the button below to create your password and activate your account.</p><p><a href="${escapeAttr(inviteUrl)}" style="display:inline-block;background:#0000FE;color:#fff;text-decoration:none;padding:12px 20px;border-radius:9px;font-weight:700">Activate My Account</a></p><p style="font-size:13px;color:#6b7280">This invitation expires in 48 hours and can be used only once.</p><p>Haulog CRM Team</p></div></body></html>`,
      },
    });

    return { ok: true, uid, email, role: roleName };
  } catch (err) {
    console.error('adminCreateUserInvite failed', err);
    throw err instanceof HttpsError
      ? err
      : new HttpsError('internal', err.message || 'Unable to create user invitation.');
  }
});

exports.inspectUserInvite = onCall(async (request) => {
  const token = String(request.data?.token || '').trim();
  if (!token) throw new HttpsError('invalid-argument', 'Invitation token is missing.');

  const snap = await db.collection('userInvites').doc(hashToken(token)).get();
  if (!snap.exists) throw new HttpsError('not-found', 'This invitation is invalid or expired.');
  const invite = snap.data();
  if (invite.used === true || invite.expiresAt.toMillis() < Date.now()) {
    throw new HttpsError('failed-precondition', 'This invitation is invalid or expired.');
  }
  return { name: invite.name, email: invite.email, role: invite.role };
});

exports.completeUserInvite = onCall(async (request) => {
  const token = String(request.data?.token || '').trim();
  const password = String(request.data?.password || '');
  if (!token || password.length < 8) {
    throw new HttpsError('invalid-argument', 'A valid invitation token and an 8-character minimum password are required.');
  }

  const ref = db.collection('userInvites').doc(hashToken(token));
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError('not-found', 'This invitation is invalid or expired.');
  const invite = snap.data();
  if (invite.used === true || invite.expiresAt.toMillis() < Date.now()) {
    throw new HttpsError('failed-precondition', 'This invitation is invalid or expired.');
  }

  // Claim the invitation first to prevent two simultaneous activations.
  try {
    await db.runTransaction(async (tx) => {
      const current = await tx.get(ref);
      if (!current.exists) throw new Error('INVITE_MISSING');
      const currentData = current.data();
      if (currentData.used === true || currentData.expiresAt.toMillis() < Date.now()) throw new Error('INVITE_EXPIRED');
      tx.update(ref, { used: true, usedAt: admin.firestore.FieldValue.serverTimestamp() });
    });
  } catch (err) {
    if (err.message === 'INVITE_EXPIRED' || err.message === 'INVITE_MISSING') {
      throw new HttpsError('failed-precondition', 'This invitation is invalid or has already been used.');
    }
    throw new HttpsError('aborted', 'This invitation is already being activated. Please try again.');
  }

  try {
    await auth.updateUser(invite.uid, {
      password,
      emailVerified: true,
      disabled: false,
      displayName: invite.name,
    });

    await db.collection('users').doc(invite.uid).set({
      invitationStatus: 'Accepted',
      status: 'Active',
      passwordSetAt: admin.firestore.FieldValue.serverTimestamp(),
      lastLogin: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    const customToken = await auth.createCustomToken(invite.uid);
    return { ok: true, customToken };
  } catch (err) {
    console.error('completeUserInvite failed', err);
    // Do not expose internal details. The invitation remains marked used so it cannot be replayed.
    throw new HttpsError('internal', 'Unable to activate the account. Please ask an Admin to send a new invitation.');
  }
});

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, '&#96;');
}
