// Pruebas del cliente web (se ejecutan con: node --test tests/web)
import assert from "node:assert/strict";
import { test } from "node:test";
import { FAST, P, sodium } from "./setup.mjs";

const { decodeContent, padJson } = await import("../../web/js/client.js");

// ---------------------------------------------------------------- relleno

test("padJson deja cada mensaje en un tamaño fijo", () => {
  const size = (s) => new TextEncoder().encode(s).length;
  assert.equal(size(padJson('{"t":"text","body":"ok"}')), 256);
  assert.equal(size(padJson(JSON.stringify({ t: "text", body: "x".repeat(300) }))), 1024);
  assert.equal(size(padJson(JSON.stringify({ t: "text", body: "ñ".repeat(200) }))), 1024); // cuenta bytes, no letras
  assert.equal(size(padJson(JSON.stringify({ t: "file", data: "A".repeat(70000) }))), 131072);
  assert.deepEqual(JSON.parse(padJson('{"t":"text","body":"hola"}')).body, "hola");
  assert.equal(padJson("no es json"), "no es json");
});

// --------------------------------------------------- validación del contenido

test("decodeContent descarta campos desconocidos y tipos raros", () => {
  const c = decodeContent(JSON.stringify({ t: "text", body: "hola", mid: "abcdefgh12", html: "<b>x</b>", evil: 1 }));
  assert.deepEqual(c, { t: "text", body: "hola", mid: "abcdefgh12" });
  assert.deepEqual(decodeContent("texto plano"), { t: "text", body: "texto plano" });
  assert.equal(decodeContent(JSON.stringify({ t: "image", mime: "text/html", data: "AAAA" })).t, "unsupported");
  assert.equal(decodeContent(JSON.stringify({ t: "poll", q: "¿?", opts: ["solo una"] })).t, "unsupported");
  assert.equal(decodeContent(JSON.stringify({ t: "text", body: "x".repeat(30000) })).body.length, 20000);
});

test("decodeContent acepta una vista previa de enlace válida", () => {
  const lp = { url: "https://example.com/a", title: "Ejemplo", desc: "Una página", site: "example.com", img: "QUJD" };
  assert.deepEqual(decodeContent(JSON.stringify({ t: "text", body: "mira https://example.com/a", lp })).lp, lp);
});

test("decodeContent rechaza vistas previas peligrosas", () => {
  const dec = (lp) => decodeContent(JSON.stringify({ t: "text", body: "x", lp })).lp;
  assert.equal(dec({ url: "javascript:alert(1)", title: "x" }), undefined);
  assert.equal(dec("https://example.com"), undefined);
  // La imagen solo puede ser base64 (nada de "data:..." ni comillas para salir del atributo)
  assert.equal(dec({ url: "https://e.com", title: "t", img: '" onerror="alert(1)' }).img, undefined);
  assert.equal(dec({ url: "https://e.com", title: "t".repeat(500) }).title.length, 200);
});

test("decodeContent valida respuestas y temporizadores", () => {
  const c = decodeContent(JSON.stringify({ t: "text", body: "a", exp: 123, reply: { mid: "abcdefgh12", from: "ana", text: "x".repeat(500) } }));
  assert.equal(c.exp, undefined); // solo los tiempos permitidos
  assert.equal(c.reply.text.length, 120);
  assert.equal(decodeContent(JSON.stringify({ t: "text", body: "a", exp: 86400 })).exp, 86400);
});

// ------------------------------------------------------------- identidad

test("la identidad se abre solo con su contraseña", () => {
  const seed = P.newIdentitySeed();
  const blob = P.saveIdentity(seed, "contraseña buena", ...FAST);
  assert.ok(!JSON.stringify(blob).includes("contraseña"));
  const id = P.loadIdentity(blob, "contraseña buena");
  assert.ok(P.equal(id.seed, seed));
  assert.throws(() => P.loadIdentity(blob, "contraseña mala"));
});

test("las firmas de autenticación no sirven para otro usuario ni otro reto", () => {
  const id = P.loadIdentity(P.saveIdentity(P.newIdentitySeed(), "x".repeat(8), ...FAST), "x".repeat(8));
  const nonce = sodium.randombytes_buf(32);
  const sig = P.signAuth(id, nonce, "alice");
  const msg = (n, u) => P.encodeFields(P.utf8("securechat-auth-v1"), n, P.utf8(u));
  // La firma verifica con el contexto correcto y falla si cambia el usuario o el reto
  const ok = (n, u) => sodium.crypto_sign_verify_detached(sig, msg(n, u), id.publicKey);
  assert.equal(ok(nonce, "alice"), true);
  assert.equal(ok(sodium.randombytes_buf(32), "alice"), false);
  assert.equal(ok(nonce, "mallory"), false);
});

test("el número de seguridad es el mismo visto desde los dos lados", () => {
  const a = sodium.crypto_sign_keypair().publicKey, b = sodium.crypto_sign_keypair().publicKey;
  const n1 = P.safetyNumber("ana", a, "bob", b), n2 = P.safetyNumber("bob", b, "ana", a);
  assert.equal(n1, n2);
  assert.match(n1.replace(/\s/g, ""), /^\d{60}$/);
  assert.notEqual(n1, P.safetyNumber("ana", a, "bob", sodium.crypto_sign_keypair().publicKey));
});

test("kdf separa claves por etiqueta", () => {
  const k = sodium.randombytes_buf(32);
  assert.ok(P.equal(P.kdf(k, "sc-backup"), P.kdf(k, "sc-backup")));
  assert.ok(!P.equal(P.kdf(k, "sc-backup"), P.kdf(k, "sc-history")));
});
