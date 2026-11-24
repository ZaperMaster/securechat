#!/usr/bin/env bash
# Compila y firma la app de Android (Capacitor). Uso, desde movil/:  bash compilar.sh
#   -> salida/SecureChat-<versión>.apk (para instalar) y .aab (para Google Play)
# Necesita: Android SDK, JDK 21 (JAVA_HOME) y, en privado/android/, la clave de firma (firma.txt +
# securechat.keystore) y google-services.json de Firebase (sin él la app funciona pero sin avisos).
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
PRIV="$ROOT/privado/android"
SDK="${ANDROID_HOME:-$LOCALAPPDATA/Android/Sdk}"
BT="$SDK/build-tools/36.1.0"
export JAVA_HOME="${SECURECHAT_JDK21:-$LOCALAPPDATA/securechat-tools/jdk21/jdk-21.0.13.1+2}"  # Capacitor 8 necesita Java 21
export ANDROID_HOME="$SDK"
# Windows Insider (26300) rompe los sockets AF_UNIX de Java: así usa el plan B por TCP
export JAVA_TOOL_OPTIONS="-Djdk.net.unixdomain.tmpdir=C:/securechat-sin-af-unix"

if [ -f "$PRIV/google-services.json" ]; then cp "$PRIV/google-services.json" android/app/google-services.json
else echo "AVISO: falta privado/android/google-services.json: la app no recibirá avisos con la app cerrada"; fi

npm run sync
(cd android && ./gradlew --no-daemon -q -Porg.gradle.java.installations.auto-detect=false "-Porg.gradle.java.installations.paths=$(cygpath -m "$JAVA_HOME" 2>/dev/null || echo "$JAVA_HOME")" assembleRelease bundleRelease)

VER="$(sed -n 's/.*versionName "\([^"]*\)".*/\1/p' android/app/build.gradle)"
KS="$PRIV/securechat.keystore"
export KP="$(sed -n 's/^contraseña (almacén y clave): //p' "$PRIV/firma.txt")"
mkdir -p salida
"$BT/zipalign.exe" -p -f 4 android/app/build/outputs/apk/release/app-release-unsigned.apk salida/alineada.apk
"$JAVA_HOME/bin/java.exe" -jar "$BT/lib/apksigner.jar" sign --ks "$KS" --ks-key-alias securechat --ks-pass env:KP --key-pass env:KP \
  --out "salida/SecureChat-$VER.apk" salida/alineada.apk
rm -f salida/alineada.apk salida/*.idsig
cp android/app/build/outputs/bundle/release/app-release.aab "salida/SecureChat-$VER.aab"
"$JAVA_HOME/bin/jarsigner.exe" -keystore "$KS" -storepass:env KP -keypass:env KP -sigalg SHA256withRSA -digestalg SHA-256 \
  "salida/SecureChat-$VER.aab" securechat > /dev/null
"$JAVA_HOME/bin/java.exe" -jar "$BT/lib/apksigner.jar" verify --print-certs "salida/SecureChat-$VER.apk" | grep -i "SHA-256 digest"
echo "listo: movil/salida/SecureChat-$VER.apk y .aab"
