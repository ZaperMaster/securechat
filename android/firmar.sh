#!/usr/bin/env bash
# Firma la app de Android con la clave de privado/android (que no está en git).
# Uso (desde android/):  bash firmar.sh      -> salida/SecureChat-<versión>.apk y .aab
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_HOME:-$LOCALAPPDATA/Android/Sdk}"
BT="$SDK/build-tools/36.1.0"
JDK="${JAVA_HOME:-C:/Program Files/Eclipse Adoptium/jdk-17.0.20.101-hotspot}"
KS="../privado/android/securechat.keystore"
export KP="$(sed -n 's/^contraseña (almacén y clave): //p' ../privado/android/firma.txt)"
export JAVA_TOOL_OPTIONS="-Djdk.net.unixdomain.tmpdir=C:/securechat-sin-af-unix"
VER="$(sed -n 's/.*"appVersionName": "\([^"]*\)".*/\1/p' twa-manifest.json)"
mkdir -p salida

"$BT/zipalign.exe" -p -f 4 app/build/outputs/apk/release/app-release-unsigned.apk salida/alineada.apk
"$JDK/bin/java.exe" -jar "$BT/lib/apksigner.jar" sign --ks "$KS" --ks-key-alias securechat --ks-pass env:KP --key-pass env:KP   --out "salida/SecureChat-$VER.apk" salida/alineada.apk
rm -f salida/alineada.apk salida/*.idsig
cp app/build/outputs/bundle/release/app-release.aab "salida/SecureChat-$VER.aab"
"$JDK/bin/jarsigner.exe" -keystore "$KS" -storepass:env KP -keypass:env KP -sigalg SHA256withRSA -digestalg SHA-256 \
  "salida/SecureChat-$VER.aab" securechat > /dev/null
echo "firmado: salida/SecureChat-$VER.apk y .aab"
