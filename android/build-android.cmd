@echo off
rem Compila la app de Android (APK y AAB sin firmar). La firma se hace aparte con apksigner.
if not defined JAVA_HOME set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot"
if not defined ANDROID_HOME set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
rem En algunas versiones de Windows los sockets AF_UNIX de Java fallan ("Invalid argument: connect").
rem Con una carpeta que no existe, Java usa TCP local en su lugar.
set "JAVA_TOOL_OPTIONS=-Djdk.net.unixdomain.tmpdir=C:\securechat-sin-af-unix"
cd /d "%~dp0"
call "%~dp0gradlew.bat" assembleRelease bundleRelease --no-daemon %*
