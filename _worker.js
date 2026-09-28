// _worker.js
//
// Vaveyla Wiki — tek dosyalık Cloudflare Worker.
// Statik dosyalar (public/ klasörü) env.ASSETS binding'i ile otomatik sunulur.
// /api/* ile başlayan istekler aşağıdaki router tarafından karşılanır.
// Veritabanı: Cloudflare Workers KV (binding adı: VAVEYLA_KV — dashboard'dan bağlanmalı).

/* ================= ORTAK YARDIMCI FONKSİYONLAR ================= */

function json(obj, status, extraHeaders){
  var headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  if (extraHeaders) { for (var k in extraHeaders) headers[k] = extraHeaders[k]; }
  return new Response(JSON.stringify(obj), { status: status || 200, headers: headers });
}

function bytesToHex(bytes){
  return Array.from(bytes).map(function(b){ return b.toString(16).padStart(2, '0'); }).join('');
}
function hexToBytes(hex){
  var arr = new Uint8Array(hex.length / 2);
  for (var i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}

async function hashPassword(password, saltHex){
  var enc = new TextEncoder();
  var salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: 100000 },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

async function createSession(env, userId){
  var token = crypto.randomUUID() + crypto.randomUUID();
  await env.VAVEYLA_KV.put('session:' + token, JSON.stringify({ userId: userId }), {
    expirationTtl: 60 * 60 * 24 * 30, // 30 gün
  });
  return token;
}

function getBearerToken(request){
  var auth = request.headers.get('Authorization') || '';
  var m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function getUserFromRequest(request, env){
  var token = getBearerToken(request);
  if (!token) return null;
  var sessRaw = await env.VAVEYLA_KV.get('session:' + token);
  if (!sessRaw) return null;
  var sess = JSON.parse(sessRaw);
  var userRaw = await env.VAVEYLA_KV.get('user:' + sess.userId);
  if (!userRaw) return null;
  return JSON.parse(userRaw);
}

function isAdmin(user){
  return !!(user && Array.isArray(user.roles) && user.roles.indexOf('admin') !== -1);
}

function publicUser(user){
  return {
    sub: user.id,
    email: user.email,
    user_metadata: { full_name: user.fullName },
    app_metadata: { roles: user.roles || [] },
  };
}

async function readJsonBody(request){
  try { return await request.json(); } catch (e) { return null; }
}

function requireKv(env){
  if (!env.VAVEYLA_KV) {
    return json({ error: 'Sunucu yapılandırma hatası: VAVEYLA_KV bağlantısı bulunamadı. Cloudflare dashboard > Settings > Bindings kısmından KV namespace bağlayın.' }, 500);
  }
  return null;
}

/* ================= AUTH: KAYIT / GİRİŞ / ÇIKIŞ / ME ================= */

async function handleRegister(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);

  var email = (body.email || '').trim().toLowerCase();
  var password = body.password || '';
  var fullName = (body.fullName || '').trim().slice(0, 32);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Geçerli bir e-posta adresi girin.' }, 400);
  if (password.length < 8) return json({ error: 'Şifre en az 8 karakter olmalı.' }, 400);
  if (!fullName) return json({ error: 'Kullanıcı adı girin.' }, 400);
  if (fullName.length < 3) return json({ error: 'Kullanıcı adı en az 3 karakter olmalı.' }, 400);
  if (!/^[a-zA-Z0-9_şŞıİçÇöÖüÜğĞ .-]+$/.test(fullName)) return json({ error: 'Kullanıcı adı geçersiz karakter içeriyor.' }, 400);

  try {
    var idxKey = 'useridx:' + email;
    var existing = await env.VAVEYLA_KV.get(idxKey);
    if (existing) return json({ error: 'Bu e-posta ile zaten bir hesap var.' }, 400);

    var existingUsers = await env.VAVEYLA_KV.list({ prefix: 'user:', limit: 1 });
    var isFirstUser = existingUsers.keys.length === 0;

    var hashed = await hashPassword(password);
    var id = crypto.randomUUID();
    var user = {
      id: id, email: email, passwordHash: hashed.hash, salt: hashed.salt, fullName: fullName,
      roles: isFirstUser ? ['admin'] : [],
      createdAt: Date.now(), lastLogin: Date.now(), confirmed: true,
    };

    await env.VAVEYLA_KV.put('user:' + id, JSON.stringify(user));
    await env.VAVEYLA_KV.put(idxKey, id);

    var token = await createSession(env, id);
    return json({ ok: true, token: token, user: publicUser(user) });
  } catch (err) {
    return json({ error: 'Kayıt sırasında hata oluştu.', detail: String(err) }, 500);
  }
}

async function handleLogin(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);

  var email = (body.email || '').trim().toLowerCase();
  var password = body.password || '';
  if (!email || !password) return json({ error: 'E-posta ve şifre gerekli.' }, 400);

  try {
    var id = await env.VAVEYLA_KV.get('useridx:' + email);
    if (!id) return json({ error: 'E-posta veya şifre hatalı.' }, 401);

    var userRaw = await env.VAVEYLA_KV.get('user:' + id);
    if (!userRaw) return json({ error: 'E-posta veya şifre hatalı.' }, 401);
    var user = JSON.parse(userRaw);

    var hashed = await hashPassword(password, user.salt);
    if (hashed.hash !== user.passwordHash) return json({ error: 'E-posta veya şifre hatalı.' }, 401);

    user.lastLogin = Date.now();
    await env.VAVEYLA_KV.put('user:' + id, JSON.stringify(user));

    var token = await createSession(env, id);
    return json({ ok: true, token: token, user: publicUser(user) });
  } catch (err) {
    return json({ error: 'Giriş sırasında hata oluştu.', detail: String(err) }, 500);
  }
}

async function handleLogout(request, env){
  try {
    var token = getBearerToken(request);
    if (token && env.VAVEYLA_KV) await env.VAVEYLA_KV.delete('session:' + token);
    return json({ ok: true });
  } catch (err) {
    return json({ ok: true });
  }
}

async function handleMe(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  try {
    var user = await getUserFromRequest(request, env);
    if (!user) return json({ error: 'Oturum bulunamadı.' }, 401);
    return json({ user: publicUser(user) });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

/* ================= PROJECT VAVEYLA: KATKILAR ================= */

var KATEGORILER = ['Özel SCP', 'Lore Katkısı', 'Departmanlar', 'Çıkar Grupları', 'Diğer'];
var MAX_BASLIK = 150;
var MAX_ICERIK = 20000;
var MAX_GORSEL_BYTES = 4.5 * 1024 * 1024;

async function handleKatkilarList(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  try {
    var user = await getUserFromRequest(request, env);

    var items = [];
    var cursor;
    do {
      var list = await env.VAVEYLA_KV.list({ prefix: 'katki:', cursor: cursor });
      for (var i = 0; i < list.keys.length; i++) {
        var raw = await env.VAVEYLA_KV.get(list.keys[i].name);
        if (!raw) continue;
        var data = JSON.parse(raw);
        var oySayisi = Array.isArray(data.oylar) ? data.oylar.length : 0;
        var oyVerdiMi = !!(user && Array.isArray(data.oylar) && data.oylar.indexOf(user.id) !== -1);
        items.push({
          id: data.id, kategori: data.kategori, baslik: data.baslik, icerik: data.icerik,
          gorsel: data.gorsel || null, yazarAdi: data.yazarAdi, yazarId: data.yazarId,
          tarih: data.tarih, oySayisi: oySayisi, oyVerdiMi: oyVerdiMi,
          onayli: !!data.onayli, onaylayan: data.onaylayan || null,
        });
      }
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);

    items.sort(function(a, b){ return (b.tarih || 0) - (a.tarih || 0); });
    return json({ katkilar: items });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleKatkilarCreate(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!user) return json({ error: 'Katkı göndermek için giriş yapmalısınız.' }, 401);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);

  var kategori = (body.kategori || '').trim();
  var baslik = (body.baslik || '').trim();
  var icerik = (body.icerik || '').trim();
  var gorsel = body.gorsel || null;

  if (KATEGORILER.indexOf(kategori) === -1) return json({ error: 'Geçersiz konu seçildi.' }, 400);
  if (!baslik || baslik.length > MAX_BASLIK) return json({ error: 'Başlık gerekli (en fazla ' + MAX_BASLIK + ' karakter).' }, 400);
  if (!icerik || icerik.length > MAX_ICERIK) return json({ error: 'Metin gerekli (en fazla ' + MAX_ICERIK + ' karakter).' }, 400);
  if (gorsel) {
    if (typeof gorsel !== 'string' || !/^data:image\/(png|jpe?g|webp|gif);base64,/.test(gorsel)) {
      return json({ error: 'Geçersiz görsel formatı.' }, 400);
    }
    if (gorsel.length > MAX_GORSEL_BYTES) return json({ error: 'Görsel çok büyük. Lütfen daha küçük bir görsel seçin.' }, 400);
  }

  var id = crypto.randomUUID();
  var item = {
    id: id, kategori: kategori, baslik: baslik, icerik: icerik, gorsel: gorsel,
    yazarId: user.id, yazarAdi: user.fullName || user.email || 'İsimsiz Kullanıcı',
    tarih: Date.now(), oylar: [], onayli: false, onaylayan: null,
  };

  try {
    await env.VAVEYLA_KV.put('katki:' + id, JSON.stringify(item));
    return json({ ok: true, id: id });
  } catch (err) {
    return json({ error: 'Kaydedilirken hata oluştu', detail: String(err) }, 500);
  }
}

async function handleKatkilarVote(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!user) return json({ error: 'Oy vermek için giriş yapmalısınız.' }, 401);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var id = body.id;
  if (!id) return json({ error: 'id gerekli.' }, 400);

  try {
    var raw = await env.VAVEYLA_KV.get('katki:' + id);
    if (!raw) return json({ error: 'Katkı bulunamadı.' }, 404);
    var item = JSON.parse(raw);

    item.oylar = Array.isArray(item.oylar) ? item.oylar : [];
    var uid = user.id;
    var idx = item.oylar.indexOf(uid);
    var oyVerdiMi;
    if (idx === -1) { item.oylar.push(uid); oyVerdiMi = true; }
    else { item.oylar.splice(idx, 1); oyVerdiMi = false; }

    await env.VAVEYLA_KV.put('katki:' + id, JSON.stringify(item));
    return json({ ok: true, oySayisi: item.oylar.length, oyVerdiMi: oyVerdiMi });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleKatkilarOnayla(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!isAdmin(user)) return json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var id = body.id;
  var onayli = !!body.onayli;
  if (!id) return json({ error: 'id gerekli.' }, 400);

  try {
    var raw = await env.VAVEYLA_KV.get('katki:' + id);
    if (!raw) return json({ error: 'Katkı bulunamadı.' }, 404);
    var item = JSON.parse(raw);
    item.onayli = onayli;
    item.onaylayan = onayli ? (user.fullName || user.email) : null;
    await env.VAVEYLA_KV.put('katki:' + id, JSON.stringify(item));
    return json({ ok: true });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleKatkilarSil(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!isAdmin(user)) return json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var id = body.id;
  if (!id) return json({ error: 'id gerekli.' }, 400);

  try {
    await env.VAVEYLA_KV.delete('katki:' + id);
    return json({ ok: true });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

/* ================= GALERİ (SADECE ADMIN YÜKLER / SİLER, HERKES GÖRÜR) ================= */

var MAX_GALERI_BYTES = 6 * 1024 * 1024;

async function handleGaleriList(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  try {
    var items = [];
    var cursor;
    do {
      var list = await env.VAVEYLA_KV.list({ prefix: 'galeri:', cursor: cursor });
      for (var i = 0; i < list.keys.length; i++) {
        var raw = await env.VAVEYLA_KV.get(list.keys[i].name);
        if (!raw) continue;
        var data = JSON.parse(raw);
        items.push({
          id: data.id, baslik: data.baslik || '', gorsel: data.gorsel,
          yukleyenAdi: data.yukleyenAdi, yukleyenId: data.yukleyenId, tarih: data.tarih,
        });
      }
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);

    items.sort(function(a, b){ return (b.tarih || 0) - (a.tarih || 0); });
    return json({ galeri: items });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleGaleriCreate(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!isAdmin(user)) return json({ error: 'Galeriye görsel eklemek için admin yetkisi gerekiyor.' }, 403);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);

  var baslik = (body.baslik || '').trim().slice(0, 150);
  var gorsel = body.gorsel || null;

  if (!gorsel || typeof gorsel !== 'string' || !/^data:image\/(png|jpe?g|webp|gif);base64,/.test(gorsel)) {
    return json({ error: 'Geçerli bir görsel gerekli.' }, 400);
  }
  if (gorsel.length > MAX_GALERI_BYTES) return json({ error: 'Görsel çok büyük. Lütfen daha küçük bir görsel seçin.' }, 400);

  var id = crypto.randomUUID();
  var item = {
    id: id, baslik: baslik, gorsel: gorsel,
    yukleyenId: user.id, yukleyenAdi: user.fullName || user.email || 'İsimsiz Kullanıcı',
    tarih: Date.now(),
  };

  try {
    await env.VAVEYLA_KV.put('galeri:' + id, JSON.stringify(item));
    return json({ ok: true, id: id, item: item });
  } catch (err) {
    return json({ error: 'Kaydedilirken hata oluştu', detail: String(err) }, 500);
  }
}

async function handleGaleriSil(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!isAdmin(user)) return json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var id = body.id;
  if (!id) return json({ error: 'id gerekli.' }, 400);

  try {
    await env.VAVEYLA_KV.delete('galeri:' + id);
    return json({ ok: true });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

/* ================= İÇERİK YÖNETİMİ (SAYFA DÜZENLEME / YENİ SAYFA) + DUYURULAR + GÖRSEL ================= */
/* Tek anahtar mantığı: KV "list" işlemi kotası düşük olduğundan (ücretsiz planda günde 1000),
   içerik ve duyurular tek bir anahtarda tutulur; okuma = 1 KV get. Her kayıt monoton artan bir
   "v" (sürüm) numarası taşır; istemci eski (gecikmeli) bir sürümü otomatik yok sayar. */

var RESERVED_PAGE_IDS = ['home', 'project-vaveyla', 'galeri', 'admin-panel', 'admin-studio', 'yetkili-kadrosu'];
var KATEGORI_PREFIX = { taraflar: 'f-', departmanlar: 'd-', karakterler: 'c-', savaslar: 'w-', makaleler: 'm-' };
var MAX_HTML_LEN = 600 * 1024;
var MAX_IMG_BYTES = 4 * 1024 * 1024;

async function readKeyJson(env, key, fallback){
  var raw = await env.VAVEYLA_KV.get(key);
  if (!raw) return fallback;
  try { return JSON.parse(raw); } catch (e) { return fallback; }
}
function nextVersion(prev){
  return Math.max((prev || 0) + 1, Date.now());
}
function slugify(str){
  var map = { 'ç':'c','Ç':'c','ğ':'g','Ğ':'g','ı':'i','İ':'i','ö':'o','Ö':'o','ş':'s','Ş':'s','ü':'u','Ü':'u' };
  var out = String(str || '').replace(/[çÇğĞıİöÖşŞüÜ]/g, function(ch){ return map[ch] || ch; }).toLowerCase();
  out = out.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return out || 'sayfa';
}
function htmlLooksUnsafe(html){
  return /<\s*(script|iframe|object|embed|link|meta|style|form|base)\b/i.test(html) || /javascript\s*:/i.test(html);
}
function validateHtml(html){
  if (typeof html !== 'string' || !html.trim()) return 'İçerik boş olamaz.';
  if (html.length > MAX_HTML_LEN) return 'İçerik çok büyük. Görselleri yükleyerek küçültün.';
  if (htmlLooksUnsafe(html)) return 'İçerik güvenli olmayan öğeler içeriyor.';
  return null;
}

async function requireAdminUser(request, env){
  var user = await getUserFromRequest(request, env);
  if (!isAdmin(user)) return { error: json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403) };
  return { user: user };
}

/* --- Ortak senkron: içerik + duyurular (istemci sürüm numaralarını gönderir) --- */
async function handleSenkron(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var url = new URL(request.url);
  var iv = parseInt(url.searchParams.get('iv') || '0', 10) || 0;
  var dv = parseInt(url.searchParams.get('dv') || '0', 10) || 0;
  var results = await Promise.all([
    readKeyJson(env, 'icerik', { v: 0, pages: {}, custom: {} }),
    readKeyJson(env, 'duyurular', { v: 0, items: [] }),
  ]);
  var icerik = results[0], duyurular = results[1];
  var out = { iv: icerik.v || 0, dv: duyurular.v || 0 };
  if (out.iv !== iv) { out.icerik = { pages: icerik.pages || {}, custom: icerik.custom || {} }; }
  if (out.dv !== dv) { out.duyurular = duyurular.items || []; }
  return json(out);
}

/* --- Var olan (statik) sayfa VEYA özel sayfa içeriğini kaydet --- */
async function handleIcerikKaydet(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);

  var id = String(body.id || '');
  if (!/^[a-z0-9_-]{2,80}$/.test(id) || RESERVED_PAGE_IDS.indexOf(id) !== -1) return json({ error: 'Bu sayfa düzenlenemez.' }, 400);
  var hErr = validateHtml(body.html); if (hErr) return json({ error: hErr }, 400);

  var data = await readKeyJson(env, 'icerik', { v: 0, pages: {}, custom: {} });
  data.pages = data.pages || {}; data.custom = data.custom || {};
  var now = Date.now();
  var who = a.user.fullName || a.user.email || 'Admin';

  if (data.custom[id]) {
    data.custom[id].html = body.html;
    data.custom[id].updatedAt = now;
    data.custom[id].updatedBy = who;
    if (typeof body.baslik === 'string' && body.baslik.trim()) data.custom[id].baslik = body.baslik.trim().slice(0, 80);
  } else {
    data.pages[id] = { html: body.html, updatedAt: now, updatedBy: who };
  }
  data.v = nextVersion(data.v);
  await env.VAVEYLA_KV.put('icerik', JSON.stringify(data));
  return json({ ok: true, v: data.v, page: data.custom[id] ? { custom: data.custom[id] } : { override: data.pages[id] } });
}

/* --- Düzenlenmiş statik sayfayı orijinal (varsayılan) haline döndür --- */
async function handleIcerikSifirla(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  if (!body || !body.id) return json({ error: 'id gerekli.' }, 400);
  var data = await readKeyJson(env, 'icerik', { v: 0, pages: {}, custom: {} });
  data.pages = data.pages || {};
  delete data.pages[String(body.id)];
  data.v = nextVersion(data.v);
  await env.VAVEYLA_KV.put('icerik', JSON.stringify(data));
  return json({ ok: true, v: data.v });
}

/* --- Yeni sayfa oluştur (kategori + şablondan üretilmiş HTML) --- */
async function handleSayfaOlustur(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);

  var kategori = String(body.kategori || '');
  if (!KATEGORI_PREFIX[kategori]) return json({ error: 'Geçersiz kategori.' }, 400);
  var baslik = String(body.baslik || '').trim().slice(0, 80);
  if (baslik.length < 2) return json({ error: 'Başlık en az 2 karakter olmalı.' }, 400);
  var renk = ['v', 'k', 'g', 'vita', 'n'].indexOf(body.renk) !== -1 ? body.renk : 'n';
  var hErr = validateHtml(body.html); if (hErr) return json({ error: hErr }, 400);

  var data = await readKeyJson(env, 'icerik', { v: 0, pages: {}, custom: {} });
  data.pages = data.pages || {}; data.custom = data.custom || {};
  var id = KATEGORI_PREFIX[kategori] + slugify(baslik) + '-' + crypto.randomUUID().slice(0, 4);
  var now = Date.now();
  data.custom[id] = {
    id: id, kategori: kategori, baslik: baslik, renk: renk, html: body.html,
    createdAt: now, updatedAt: now,
    createdBy: a.user.fullName || a.user.email || 'Admin', updatedBy: a.user.fullName || a.user.email || 'Admin',
  };
  data.v = nextVersion(data.v);
  await env.VAVEYLA_KV.put('icerik', JSON.stringify(data));
  return json({ ok: true, v: data.v, page: data.custom[id] });
}

async function handleSayfaSil(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  if (!body || !body.id) return json({ error: 'id gerekli.' }, 400);
  var data = await readKeyJson(env, 'icerik', { v: 0, pages: {}, custom: {} });
  data.custom = data.custom || {}; data.pages = data.pages || {};
  var id = String(body.id);
  if (!data.custom[id]) return json({ error: 'Yalnızca sonradan oluşturulan sayfalar silinebilir.' }, 400);
  delete data.custom[id];
  delete data.pages[id];
  data.v = nextVersion(data.v);
  await env.VAVEYLA_KV.put('icerik', JSON.stringify(data));
  return json({ ok: true, v: data.v });
}

/* --- Duyurular --- */
async function handleDuyuruOlustur(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var metin = String(body.metin || '').trim().slice(0, 700);
  var baslik = String(body.baslik || '').trim().slice(0, 100);
  if (metin.length < 2) return json({ error: 'Duyuru metni çok kısa.' }, 400);

  var data = await readKeyJson(env, 'duyurular', { v: 0, items: [] });
  data.items = data.items || [];
  var item = {
    id: crypto.randomUUID(), baslik: baslik, metin: metin,
    yazarId: a.user.id, yazarAdi: a.user.fullName || a.user.email || 'Admin', tarih: Date.now(),
  };
  data.items = [item].concat(data.items).slice(0, 30);
  data.v = nextVersion(data.v);
  await env.VAVEYLA_KV.put('duyurular', JSON.stringify(data));
  return json({ ok: true, v: data.v, item: item });
}

async function handleDuyuruSil(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  if (!body || !body.id) return json({ error: 'id gerekli.' }, 400);
  var data = await readKeyJson(env, 'duyurular', { v: 0, items: [] });
  data.items = (data.items || []).filter(function(d){ return d.id !== body.id; });
  data.v = nextVersion(data.v);
  await env.VAVEYLA_KV.put('duyurular', JSON.stringify(data));
  return json({ ok: true, v: data.v });
}

/* --- Görsel yükleme (admin) ve sunma (herkes). Görseller ikili veri olarak saklanır,
       HTML içinde sadece kısa bir /api/gorsel?id=... adresi durur. --- */
async function handleGorselYukle(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var a = await requireAdminUser(request, env); if (a.error) return a.error;
  var body = await readJsonBody(request);
  var dataUrl = body && body.data;
  var m = typeof dataUrl === 'string' && dataUrl.match(/^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+\/=]+)$/);
  if (!m) return json({ error: 'Geçerli bir görsel gerekli (png, jpg, webp, gif).' }, 400);

  var bin = atob(m[2]);
  if (bin.length > MAX_IMG_BYTES) return json({ error: 'Görsel çok büyük (en fazla 4 MB).' }, 400);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);

  var id = crypto.randomUUID().replace(/-/g, '');
  await env.VAVEYLA_KV.put('img:' + id, bytes.buffer, { metadata: { type: m[1] } });
  return json({ ok: true, id: id, url: '/api/gorsel?id=' + id });
}

async function handleGorselGetir(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var id = new URL(request.url).searchParams.get('id') || '';
  if (!/^[a-f0-9]{32}$/.test(id)) return json({ error: 'Geçersiz görsel.' }, 400);
  var res = await env.VAVEYLA_KV.getWithMetadata('img:' + id, { type: 'arrayBuffer' });
  if (!res || !res.value) return json({ error: 'Görsel bulunamadı.' }, 404);
  var type = (res.metadata && res.metadata.type) || 'image/jpeg';
  return new Response(res.value, {
    status: 200,
    headers: {
      'Content-Type': type,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/* ================= KULLANICI YÖNETİMİ (ADMIN) ================= */

async function handleKullanicilarListesi(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var user = await getUserFromRequest(request, env);
  if (!isAdmin(user)) return json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403);

  try {
    var kullanicilar = [];
    var cursor;
    do {
      var list = await env.VAVEYLA_KV.list({ prefix: 'user:', cursor: cursor });
      for (var i = 0; i < list.keys.length; i++) {
        var raw = await env.VAVEYLA_KV.get(list.keys[i].name);
        if (!raw) continue;
        var u = JSON.parse(raw);
        kullanicilar.push({
          id: u.id, email: u.email, isim: u.fullName || '',
          roller: u.roles || [], olusturulma: u.createdAt, sonGiris: u.lastLogin || null,
          onaylandi: !!u.confirmed,
        });
      }
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);

    kullanicilar.sort(function(a, b){ return (b.olusturulma || 0) - (a.olusturulma || 0); });
    return json({ kullanicilar: kullanicilar });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleKullaniciSil(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var admin = await getUserFromRequest(request, env);
  if (!isAdmin(admin)) return json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var id = body.id;
  if (!id) return json({ error: 'Kullanıcı id gerekli.' }, 400);
  if (id === admin.id) return json({ error: 'Kendi hesabınızı buradan silemezsiniz.' }, 400);

  try {
    var raw = await env.VAVEYLA_KV.get('user:' + id);
    if (raw) {
      var u = JSON.parse(raw);
      await env.VAVEYLA_KV.delete('useridx:' + u.email);
    }
    await env.VAVEYLA_KV.delete('user:' + id);
    return json({ ok: true });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleKullaniciRol(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  var admin = await getUserFromRequest(request, env);
  if (!isAdmin(admin)) return json({ error: 'Bu işlem için admin yetkisi gerekiyor.' }, 403);

  var body = await readJsonBody(request);
  if (!body) return json({ error: 'Geçersiz istek gövdesi.' }, 400);
  var id = body.id;
  var role = body.role;
  var action = body.action;

  if (!id || ['admin', 'yetkili'].indexOf(role) === -1 || ['add', 'remove'].indexOf(action) === -1) {
    return json({ error: 'Geçersiz istek.' }, 400);
  }

  try {
    var raw = await env.VAVEYLA_KV.get('user:' + id);
    if (!raw) return json({ error: 'Kullanıcı bulunamadı.' }, 404);
    var u = JSON.parse(raw);
    u.roles = Array.isArray(u.roles) ? u.roles : [];
    var idx = u.roles.indexOf(role);
    if (action === 'add' && idx === -1) u.roles.push(role);
    if (action === 'remove' && idx !== -1) u.roles.splice(idx, 1);
    await env.VAVEYLA_KV.put('user:' + id, JSON.stringify(u));
    return json({ ok: true, roller: u.roles });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

async function handleYetkiliListesi(request, env){
  var kvErr = requireKv(env); if (kvErr) return kvErr;
  try {
    var yetkililer = [];
    var cursor;
    do {
      var list = await env.VAVEYLA_KV.list({ prefix: 'user:', cursor: cursor });
      for (var i = 0; i < list.keys.length; i++) {
        var raw = await env.VAVEYLA_KV.get(list.keys[i].name);
        if (!raw) continue;
        var u = JSON.parse(raw);
        var roles = u.roles || [];
        if (roles.indexOf('admin') !== -1 || roles.indexOf('yetkili') !== -1) {
          yetkililer.push({
            name: u.fullName || u.email || 'İsimsiz Kullanıcı',
            role: roles.indexOf('admin') !== -1 ? 'Admin' : 'Yetkili',
          });
        }
      }
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);

    yetkililer.sort(function(a, b){
      if (a.role !== b.role) return a.role === 'Admin' ? -1 : 1;
      return a.name.localeCompare(b.name, 'tr');
    });

    return json({ yetkililer: yetkililer }, 200, { 'Cache-Control': 'public, max-age=60' });
  } catch (err) {
    return json({ error: 'Beklenmeyen hata', detail: String(err) }, 500);
  }
}

/* ================= ROUTER ================= */

var ROUTES = {
  'GET /api/me': handleMe,
  'POST /api/register': handleRegister,
  'POST /api/login': handleLogin,
  'POST /api/logout': handleLogout,
  'GET /api/katkilar-list': handleKatkilarList,
  'POST /api/katkilar-create': handleKatkilarCreate,
  'POST /api/katkilar-vote': handleKatkilarVote,
  'POST /api/katkilar-onayla': handleKatkilarOnayla,
  'POST /api/katkilar-sil': handleKatkilarSil,
  'GET /api/galeri-list': handleGaleriList,
  'POST /api/galeri-create': handleGaleriCreate,
  'POST /api/galeri-sil': handleGaleriSil,
  'GET /api/senkron': handleSenkron,
  'POST /api/icerik-kaydet': handleIcerikKaydet,
  'POST /api/icerik-sifirla': handleIcerikSifirla,
  'POST /api/sayfa-olustur': handleSayfaOlustur,
  'POST /api/sayfa-sil': handleSayfaSil,
  'POST /api/duyuru-olustur': handleDuyuruOlustur,
  'POST /api/duyuru-sil': handleDuyuruSil,
  'POST /api/gorsel-yukle': handleGorselYukle,
  'GET /api/gorsel': handleGorselGetir,
  'GET /api/kullanicilar-listesi': handleKullanicilarListesi,
  'POST /api/kullanici-sil': handleKullaniciSil,
  'POST /api/kullanici-rol': handleKullaniciRol,
  'GET /api/yetkili-listesi': handleYetkiliListesi,
};

export default {
  async fetch(request, env, ctx){
    var url = new URL(request.url);

    if (url.pathname.indexOf('/api/') === 0) {
      var key = request.method + ' ' + url.pathname;
      var handler = ROUTES[key];
      if (handler) {
        try {
          return await handler(request, env);
        } catch (err) {
          return json({ error: 'Beklenmeyen sunucu hatası', detail: String(err) }, 500);
        }
      }
      return json({ error: 'Bulunamadı.' }, 404);
    }

    // /api/ ile başlamayan her şey: statik dosya (public/ klasörü) olarak sunulur.
    return env.ASSETS.fetch(request);
  }
};
