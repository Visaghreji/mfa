'use strict';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const store = {
  get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set: (k, v) => localStorage.setItem(k, JSON.stringify(v))
};
let current = null;   // signed-in username (memory only, no tokens stored)
let pending = null;   // user mid-registration or mid-login
let selMfa = null, demoCode = '';

/* ---------- Navigation ---------- */
function show(id) {
  $$('.view').forEach(v => v.hidden = v.id !== id);
  $('#signOut').hidden = !current;
  window.scrollTo(0, 0);
}
document.addEventListener('click', e => {
  const g = e.target.closest('[data-go]');
  if (g) { e.preventDefault(); show(g.dataset.go); }
});
$('#navMissions').onclick = e => { e.preventDefault(); current ? renderDash() : show('login'); };
$('#signOut').onclick = () => { current = null; pending = null; show('login'); };

/* ---------- Crypto (demo only) ---------- */
const hasCrypto = !!(window.crypto && crypto.subtle);
if (!hasCrypto) $('#compat').hidden = false;
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function hash(pw, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256));
}
const randCode = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');

/* ---------- Registration ---------- */
function strength(p) {
  let s = 0;
  if (p.length >= 8) s++; if (p.length >= 12) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
  if (/\d/.test(p)) s++; if (/[^A-Za-z0-9]/.test(p)) s++;
  return s;
}
$('#rPass').oninput = e => {
  const s = strength(e.target.value), l = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
  const f = $('#meterFill'); f.style.width = (s * 20) + '%';
  f.style.background = s < 3 ? 'var(--bad)' : s < 4 ? '#fbbf24' : 'var(--good)';
  $('#meterText').textContent = 'Strength: ' + (e.target.value ? l[s] : 'enter a password');
};
$('#regForm').onsubmit = async e => {
  e.preventDefault();
  const u = $('#rUser').value.trim(), m = $('#rEmail').value.trim(), p = $('#rPass').value, c = $('#rConf').value, msg = $('#regMsg');
  const users = store.get('cq_users', []);
  const err = !u || !m || !p || !c ? 'Fill in every field.' :
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(m) ? 'Enter an email like name@example.com.' :
    p !== c ? 'Passwords do not match.' :
    strength(p) < 3 ? 'Choose a stronger password: add length, mixed case, digits or symbols.' :
    !$('#rAck').checked ? 'Tick the box to confirm this is an educational demo.' :
    users.some(x => x.username.toLowerCase() === u.toLowerCase()) ? 'That username is taken in this demo. Pick another.' :
    !hasCrypto ? 'Web Crypto is unavailable in this browser context.' : '';
  if (err) { msg.textContent = err; return; }
  msg.textContent = '';
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  pending = { username: u, email: m, salt, hash: await hash(p, salt), mfa: null };
  $('#regForm').reset(); $('#meterFill').style.width = 0;
  show('enroll'); $('#enrollBox').innerHTML = '';
};

/* ---------- MFA (simulated, separate from account data) ---------- */
function mfaPanel(method, onOk, box) {
  demoCode = randCode();
  if (method === 'bio') {
    box.innerHTML = '<p class="sim">Simulation: no real biometric data is used. Biometrics are an "inherence" factor: something you are.</p><div class="fp" id="fp">☝</div><button class="btn" id="fpBtn">Simulate Fingerprint Verification</button>';
    $('#fpBtn').onclick = () => { $('#fp').classList.add('scan'); setTimeout(() => { $('#fp').classList.remove('scan'); box.insertAdjacentHTML('beforeend', '<p class="ok">Fingerprint matched (simulated).</p>'); onOk(); }, 1400); };
    return;
  }
  const label = method === 'app'
    ? 'Authenticator simulation. A real app derives codes from a shared secret and the time. This is a random demo code.'
    : 'Simulated email inside the app. Nothing is sent. Message: "Your CyberQuest demo code is ' + demoCode + '".';
  box.innerHTML = `<p class="sim">${label}</p><div class="code" aria-label="Demonstration code">${demoCode}</div><label>Enter the code<input id="otpIn" inputmode="numeric" maxlength="6" autocomplete="off"></label><p class="msg" id="otpMsg" role="alert"></p><button class="btn" id="otpBtn">Verify</button>`;
  $('#otpBtn').onclick = () => {
    if ($('#otpIn').value.trim() === demoCode) { $('#otpMsg').textContent = ''; onOk(); }
    else { $('#otpMsg').textContent = 'Code does not match. Second factor rejected.'; box.classList.add('shake'); setTimeout(() => box.classList.remove('shake'), 400); }
  };
}
$$('[data-mfa]').forEach(b => b.onclick = () => {
  selMfa = b.dataset.mfa;
  $$('[data-mfa]').forEach(x => x.classList.toggle('sel', x === b));
  mfaPanel(selMfa, () => {
    pending.mfa = selMfa;
    const users = store.get('cq_users', []); users.push(pending); store.set('cq_users', users);
    current = pending.username; pending = null; renderDash();
  }, $('#enrollBox'));
});

/* ---------- Sign-in ---------- */
$('#loginForm').onsubmit = async e => {
  e.preventDefault();
  const id = $('#lUser').value.trim().toLowerCase(), pw = $('#lPass').value, msg = $('#loginMsg');
  const u = store.get('cq_users', []).find(x => x.username.toLowerCase() === id || x.email.toLowerCase() === id);
  if (!hasCrypto) { msg.textContent = 'Web Crypto is unavailable in this browser context.'; return; }
  if (!u || await hash(pw, u.salt) !== u.hash) { msg.textContent = 'Sign-in failed: username or password is incorrect.'; return; }
  msg.textContent = ''; $('#loginForm').reset();
  show('challenge');
  mfaPanel(u.mfa, () => { current = u.username; renderDash(); }, $('#challengeBox'));
};

/* ---------- Progress ---------- */
const BOARD = [['NeonFox', 520], ['ByteWarden', 410], ['PacketPixie', 330], ['CipherCat', 250]];
const prog = () => store.get('cq_prog_' + current, { xp: 0, done: {}, right: 0, total: 0, badges: [], streak: 0, last: '', log: [] });
const save = p => store.set('cq_prog_' + current, p);
function award(p, xp, correct) {
  p.total++; if (correct) { p.right++; p.xp += xp; }
  const today = new Date().toDateString();
  if (p.last !== today) { const y = new Date(Date.now() - 864e5).toDateString(); p.streak = p.last === y ? p.streak + 1 : 1; p.last = today; }
  save(p);
}
function badge(p, name) { if (!p.badges.includes(name)) { p.badges.push(name); p.log.unshift('Earned badge: ' + name); } }

/* ---------- Missions ---------- */
const Q = (q, o, a, x) => ({ q, o, a, x });
const MISSIONS = [
 { id: 1, name: 'Identity Checkpoint', topic: 'Authentication', badge: 'Gatekeeper', qs: [
  Q('A user enters a valid username with the wrong password. What happened?', ['Authentication failed', 'Authorization failed', 'Login succeeded'], 0, 'The system could not verify the claimed identity, so authentication failed. Authorization is only considered after identity is established.'),
  Q('A student logs in successfully and is shown only their own marks. This shows:', ['Identity and permission are different things', 'The password was weak', 'MFA was used'], 0, 'Authentication proved who they are. Permissions then limited what that identity could see.'),
  Q('Which is a credential?', ['A password', 'The page title', 'A browser tab'], 0, 'Credentials are secrets or proofs, like passwords, used to verify identity.')] },
 { id: 2, name: 'Permission Matrix', topic: 'Authorization / RBAC', badge: 'Least Privilege', type: 'matrix' },
 { id: 3, name: 'The Second-Factor Shield', topic: 'MFA and 2FA', badge: 'Shield Bearer', qs: [
  Q('Password + PIN: is this true multi-factor?', ['Yes, two secrets', 'No, both are something you know', 'Yes, a PIN is something you have'], 1, 'Both are knowledge factors. Two passwords are still one factor type, so one phish or leak can defeat both.'),
  Q('Password + authenticator app: valid?', ['Yes: know + have', 'No: both are digital', 'No: apps are unsafe'], 0, 'A password is something you know; the app on your device is something you have. This is 2FA, and 2FA is a form of MFA.'),
  Q('Password + hardware security key + fingerprint is best described as:', ['2FA', 'MFA with three distinct factor types', 'Single factor'], 1, 'MFA means two or more factors. 2FA is exactly two. Three types here: know, have, are.'),
  Q('A fingerprint is which factor?', ['Know', 'Have', 'Are'], 2, 'Inherence: something you are.')] },
 { id: 4, name: 'OTP Under Pressure', topic: 'One-time passwords', badge: 'Quick Draw', type: 'otp' },
 { id: 5, name: 'Spot the Attack', topic: 'Authentication attacks', badge: 'Threat Hunter', qs: [
  Q('Many logins arrive using passwords leaked from another website. This is:', ['Credential stuffing', 'Biometrics', 'File compression'], 0, 'Attackers replay leaked credentials. Defenses: unique passwords, MFA, rate limiting, breach monitoring.'),
  Q('One account gets thousands of rapid guesses. Best defense?', ['Rate limiting and lockout', 'Bigger fonts', 'Encryption at rest'], 0, 'Brute force is slowed by throttling, lockouts and strong passwords.'),
  Q('A user gets 30 unexpected approval prompts overnight and taps Approve to stop them. This is:', ['MFA fatigue', 'Session theft', 'Brute force'], 0, 'Prompt bombing. Defend with number matching, prompt limits and training users to deny unexpected prompts.'),
  Q('A fake portal asks for your password and OTP and forwards them instantly. This is:', ['Phishing', 'Rate limiting', 'RBAC'], 0, 'Phishing can relay OTPs in real time. Phishing-resistant keys (FIDO2) and checking URLs help.'),
  Q('An attacker copies a logged-in user\'s session cookie. This is:', ['Session theft', 'Credential stuffing', 'Hashing'], 0, 'Defend with HttpOnly/Secure cookies, short sessions, and re-authentication for sensitive actions.')] },
 { id: 6, name: 'The Administrator Trap', topic: 'Broken access control', badge: 'Admin Guardian', qs: [
  Q('A student hides nothing: they type /admin into the URL and the server returns the dashboard. What is the flaw?', ['Broken access control: no server-side check', 'Weak password', 'Slow network'], 0, 'Authorization must be enforced on the server for every request.'),
  Q('Developers hide the Admin button from students. Is that enough?', ['Yes', 'No: hidden UI can still be requested directly', 'Only on mobile'], 1, 'Hiding a button is cosmetic. Attackers call the URL or API directly.'),
  Q('A student changes "role":"student" to "admin" in a request and gains access. Fix?', ['Trust the client role less', 'Derive role from server-side session data and verify it', 'Rename the field'], 1, 'Never trust client-supplied roles. This is privilege escalation.'),
  Q('Which principle limits damage when an account is compromised?', ['Least privilege', 'Maximum convenience', 'Shared accounts'], 0, 'Grant only the access a role needs.')] }
];
const ACTIONS = ['View own marks', "View another student's marks", 'Update marks', 'Create student accounts', 'Manage user roles', 'Access admin dashboard'];
const ROLES = ['Student', 'Teacher', 'Admin'];
const RIGHT = [[1,1,1],[0,0,0],[0,1,1],[0,0,1],[0,0,1],[0,0,1]];

function renderDash() {
  const p = prog(), lvl = Math.floor(p.xp / 100) + 1, done = Object.keys(p.done).length;
  show('dash');
  $('#welcome').textContent = 'Welcome back, ' + current;
  const acc = p.total ? Math.round(p.right / p.total * 100) : 0;
  $('#stats').innerHTML = [['Level', lvl], ['XP', p.xp], ['Missions', done + '/6'], ['Accuracy', acc + '%'], ['Streak', p.streak + ' day' + (p.streak === 1 ? '' : 's')]]
    .map(([k, v]) => `<div class="glass stat"><b>${v}</b><small>${k}</small></div>`).join('');
  $('#lvlBar').style.width = (p.xp % 100) + '%';
  const next = MISSIONS.find(m => !p.done[m.id]) || MISSIONS[0];
  $('#daily').textContent = 'Daily challenge: finish "' + next.name + '" with no wrong answers.';
  $('#continueBtn').onclick = () => openMission(next.id);
  $('#badges').innerHTML = p.badges.length ? p.badges.map(b => `<span>${b}</span>`).join('') : '<small>No badges yet.</small>';
  $('#recent').innerHTML = p.log.slice(0, 4).map(l => `<li>${l}</li>`).join('') || '<li>Complete a mission to earn achievements.</li>';
  $('#missionCards').innerHTML = MISSIONS.map(m => `<article class="glass mc"><h3>${m.id}. ${m.name}</h3><p>${m.topic}</p>${p.done[m.id] ? '<p class="tick">Completed</p>' : ''}<button class="btn ${p.done[m.id] ? 'ghost' : ''}" data-m="${m.id}">${p.done[m.id] ? 'Replay' : 'Start'}</button></article>`).join('');
  $$('[data-m]').forEach(b => b.onclick = () => openMission(+b.dataset.m));
  const rows = BOARD.concat([[current, p.xp]]).sort((a, b) => b[1] - a[1]);
  $('#board').innerHTML = rows.map(r => `<li>${r[0]}: ${r[1]} XP</li>`).join('');
}
$('#backDash').onclick = renderDash;
$('#resetBtn').onclick = () => { $('#dlgText').textContent = 'Reset all XP, badges and mission progress for this demo account?'; $('#dlg').showModal(); };
$('#dlgNo').onclick = () => $('#dlg').close();
$('#dlgYes').onclick = () => { localStorage.removeItem('cq_prog_' + current); $('#dlg').close(); renderDash(); };

let timer = null;
function openMission(id) {
  clearInterval(timer);
  const m = MISSIONS.find(x => x.id === id), box = $('#missionBox');
  show('mission');
  const finish = (wrong) => {
    const p = prog(); p.done[id] = true; badge(p, m.badge);
    if (!wrong) { p.xp += 20; p.log.unshift('Perfect run: ' + m.name + ' (+20 XP bonus)'); } else p.log.unshift('Completed: ' + m.name);
    save(p);
    box.innerHTML = `<h2>${m.name} complete</h2><p class="ok">Badge earned: ${m.badge}${wrong ? '' : ' | Perfect run: +20 XP'}</p><button class="btn" id="fin">Back to dashboard</button>`;
    $('#fin').onclick = renderDash;
  };
  if (m.type === 'matrix') return matrixMission(m, box, finish);
  if (m.type === 'otp') return otpMission(m, box, finish);
  let i = 0, wrong = 0;
  const step = () => {
    const q = m.qs[i];
    box.innerHTML = `<h2>${m.name}</h2><small>Question ${i + 1} of ${m.qs.length}</small><p>${q.q}</p><div class="opts">${q.o.map((o, k) => `<button class="opt" data-k="${k}">${o}</button>`).join('')}</div><div id="fb"></div>`;
    $$('#missionBox .opt').forEach(b => b.onclick = () => {
      const k = +b.dataset.k, ok = k === q.a;
      $$('#missionBox .opt').forEach(x => { x.disabled = true; if (+x.dataset.k === q.a) x.classList.add('right'); });
      if (!ok) { b.classList.add('wrong'); wrong++; }
      award(prog(), 10, ok);
      $('#fb').innerHTML = `<div class="explain"><b>${ok ? 'Correct, +10 XP.' : 'Not quite.'}</b> ${q.x}</div><button class="btn" id="nx">${i + 1 < m.qs.length ? 'Next' : 'Finish mission'}</button>`;
      $('#nx').onclick = () => { i++; i < m.qs.length ? step() : finish(wrong); };
    });
  };
  step();
}

function matrixMission(m, box, finish) {
  const grid = ACTIONS.map(() => [0, 0, 0]);
  box.innerHTML = `<h2>${m.name}</h2><p>Click a cell to toggle Allow / Deny. Apply least privilege: grant only what each role needs. (Teachers update marks only for assigned students.)</p><table class="matrix"><tr><th>Action</th>${ROLES.map(r => `<th>${r}</th>`).join('')}</tr>${ACTIONS.map((a, r) => `<tr><td>${a}</td>${ROLES.map((_, c) => `<td><button class="cell deny" data-r="${r}" data-c="${c}">Deny</button></td>`).join('')}</tr>`).join('')}</table><p class="msg" id="mm"></p><button class="btn" id="chk">Check matrix</button>`;
  $$('.cell').forEach(b => b.onclick = () => { const r = b.dataset.r, c = b.dataset.c; grid[r][c] ^= 1; b.className = 'cell ' + (grid[r][c] ? 'allow' : 'deny'); b.textContent = grid[r][c] ? 'Allow' : 'Deny'; });
  $('#chk').onclick = () => {
    let bad = 0, over = [];
    ACTIONS.forEach((a, r) => ROLES.forEach((_, c) => { if (grid[r][c] !== RIGHT[r][c]) { bad++; if (grid[r][c]) over.push(ROLES[c] + ' → ' + a); } }));
    const p = prog(); const good = ACTIONS.length * 3 - bad; p.total += 18; p.right += good; p.xp += Math.round(good * 1.5); save(p);
    if (bad) { $('#mm').innerHTML = `${bad} cell(s) are wrong. ` + (over.length ? 'Security warning, excess privilege: ' + over.join('; ') + '. ' : '') + 'Authentication alone does not grant every permission. Try again.'; return; }
    $('#mm').className = 'msg ok'; $('#mm').textContent = 'Perfect. Every role has only the access it needs.'; setTimeout(() => finish(0), 900);
  };
}

function otpMission(m, box, finish) {
  let t = 30, code = randCode(), wrong = 0;
  const draw = () => {
    box.innerHTML = `<h2>${m.name}</h2><p class="sim">Simulation: this code and timer are not connected to any real account.</p><div class="code">${code}</div><p>Time left: <b id="tm">${t}</b>s</p><div class="otp">${[0,1,2,3,4,5].map(i => `<input maxlength="1" inputmode="numeric" data-i="${i}" aria-label="Digit ${i + 1}">`).join('')}</div><p class="msg" id="om"></p><div class="row"><button class="btn" id="os">Submit</button><button class="btn ghost" id="og">Regenerate code</button></div><div class="explain">OTPs expire quickly so a stolen code is useless later. Never share one with anyone. Phishing sites can still relay an OTP in real time.</div>`;
    const ins = $$('.otp input'); ins[0].focus();
    ins.forEach((el, i) => el.oninput = () => { if (el.value && ins[i + 1]) ins[i + 1].focus(); });
    $('#og').onclick = () => { code = randCode(); t = 30; draw(); };
    $('#os').onclick = () => {
      const v = ins.map(x => x.value).join('');
      if (t <= 0) return;
      if (v === code) { clearInterval(timer); award(prog(), 15, true); $('#om').className = 'msg ok'; $('#om').textContent = 'Code accepted, +15 XP.'; setTimeout(() => finish(wrong), 900); }
      else { wrong++; award(prog(), 0, false); $('#om').textContent = 'Wrong code.'; box.classList.add('shake'); setTimeout(() => box.classList.remove('shake'), 400); }
    };
    clearInterval(timer);
    timer = setInterval(() => { t--; const el = $('#tm'); if (el) el.textContent = t; if (t <= 0) { clearInterval(timer); const o = $('#om'); if (o) o.textContent = 'Code expired. Regenerate to try again.'; } }, 1000);
  };
  draw();
}

/* ---------- Background (motion-safe) ---------- */
(function () {
  const c = $('#bg'), x = c.getContext('2d');
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  let w, h, cols;
  const size = () => { w = c.width = innerWidth; h = c.height = innerHeight; cols = Array.from({ length: Math.floor(w / 28) }, () => Math.random() * h); };
  size(); addEventListener('resize', size);
  setInterval(() => {
    x.fillStyle = 'rgba(5,9,20,.12)'; x.fillRect(0, 0, w, h); x.fillStyle = '#22d3ee33'; x.font = '14px monospace';
    cols.forEach((y, i) => { x.fillText(Math.random() < .5 ? '0' : '1', i * 28, y); cols[i] = y > h + Math.random() * 3000 ? 0 : y + 14; });
  }, 90);
})();
show('landing');
