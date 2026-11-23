// Lo que se firma de cada actualización (lo usan la app y el script que firma).
function signedMessage(version, sha512hex) {
  return Buffer.from(`securechat-update-v1\n${version}\n${sha512hex}\n`, "utf8");
}
module.exports = { signedMessage };
