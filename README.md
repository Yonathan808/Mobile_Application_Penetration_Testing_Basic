Webinar: [HackemCON: Pentest de Apps Móviles en Android](https://www.youtube.com/watch?v=0KF_Ngp-XKI)
CheatSheet: [MobileHackingCheatSheet](https://github.com/randorisec/MobileHackingCheatSheet)
OWASP Mobile Application Security: [OWASP MAS Checklist](https://mas.owasp.org/checklists/MASVS-NETWORK/#)


# Pentesting de Aplicaciones Móviles Android

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

### 2. Drozer
- Requiere cliente en dispositivo móvil y PC
- Funciona como cliente-servidor
- PC actúa como servidor
- Obtiene información de la aplicación en análisis

### 3. Android Studio
- Framework estándar más utilizado
- Permite generar emuladores de diferentes versiones Android (7, 8, 9, 10)
- Evita necesidad de comprar múltiples dispositivos físicos
- Incluye emulación de diferentes tipos de dispositivos:
  - Smartphones
  - Tablets
  - Relojes inteligentes
  - Sistemas para automóviles

### 4. Herramientas de Ingeniería Inversa y Hooking
- **Frida**: Modificación en tiempo real de aplicaciones
- Se instala en el dispositivo de pruebas
- Ejecuta en segundo plano
- Permite acceso al código fuente compilado
- Útil para probar resistencia a bypass

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

### Paso 1: Obtención y Descompresión de la APK

1. Descargar la aplicación objetivo
2. Cambiar extensión de `.apk` a `.zip`
3. Descomprimir el archivo
4. Analizar estructura de carpetas resultante

### Paso 2: Análisis de Permisos

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
