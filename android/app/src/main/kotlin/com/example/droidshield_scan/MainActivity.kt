package com.example.droidshield_scan

import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Bundle
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.zip.ZipFile
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "droidshield/apk_picker")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "listInstalledApps" -> listInstalledApps(result)
                    "readInstalledAnalysis" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName == null) {
                            result.error("missing_package", "Package name is required.", null)
                        } else {
                            readInstalledAnalysis(packageName, result)
                        }
                    }
                    else -> result.notImplemented()
                }
            }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "mysecure/preferences")
            .setMethodCallHandler { call, result ->
                val preferences = getSharedPreferences("mysecure_preferences", MODE_PRIVATE)
                val key = call.argument<String>("key")
                if (key == null) {
                    result.error("missing_key", "Preference key is required.", null)
                    return@setMethodCallHandler
                }
                when (call.method) {
                    "getString" -> result.success(preferences.getString(key, null))
                    "setString" -> {
                        val value = call.argument<String>("value") ?: ""
                        preferences.edit().putString(key, value).apply()
                        result.success(null)
                    }
                    "remove" -> {
                        preferences.edit().remove(key).apply()
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun listInstalledApps(result: MethodChannel.Result) {
        try {
            val apps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { packageManager.getLaunchIntentForPackage(it.packageName) != null }
                .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 || it.packageName == packageName }
                .map {
                    val packageInfo = packageManager.getPackageInfo(it.packageName, 0)
                    mapOf(
                        "label" to packageManager.getApplicationLabel(it).toString(),
                        "packageName" to it.packageName,
                        "versionName" to (packageInfo.versionName ?: ""),
                        "targetSdk" to it.targetSdkVersion,
                        "iconPng" to iconPngBytes(packageManager.getApplicationIcon(it))
                    )
                }
                .filter {
                    isGovernmentApp(
                        it["label"] as String,
                        it["packageName"] as String
                    )
                }
                .sortedBy { it["label"] as String }

            result.success(apps)
        } catch (error: Exception) {
            result.error("list_failed", error.message ?: "Could not list installed apps.", null)
        }
    }

    private fun isGovernmentApp(label: String, packageName: String): Boolean {
        val text = "$label $packageName".lowercase()
        return governmentAppSignals.any { signal -> text.contains(signal) }
    }

    private fun iconPngBytes(drawable: Drawable): ByteArray {
        val size = 96
        val bitmap = if (drawable is BitmapDrawable && drawable.bitmap != null) {
            Bitmap.createScaledBitmap(drawable.bitmap, size, size, true)
        } else {
            Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888).also { bitmap ->
                val canvas = Canvas(bitmap)
                drawable.setBounds(0, 0, canvas.width, canvas.height)
                drawable.draw(canvas)
            }
        }
        return ByteArrayOutputStream().use { output ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)
            output.toByteArray()
        }
    }

    private fun readInstalledAnalysis(packageName: String, result: MethodChannel.Result) {
        try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            val packageInfo = packageManager.getPackageInfo(packageName, 0)
            val apk = File(appInfo.sourceDir)
            if (!apk.exists()) {
                result.error("apk_missing", "The selected app APK could not be found.", null)
                return
            }

            val evidence = mapOf(
                "evidenceSource" to "installed_app",
                "apkSha256" to sha256File(apk),
                "apkSizeBytes" to apk.length(),
                "sourcePath" to appInfo.sourceDir,
                "installerPackage" to (packageManager.getInstallerPackageName(packageName) ?: ""),
                "firstInstallTime" to Instant.ofEpochMilli(packageInfo.firstInstallTime).toString(),
                "lastUpdateTime" to Instant.ofEpochMilli(packageInfo.lastUpdateTime).toString(),
                "splitApkCount" to (appInfo.splitSourceDirs?.size ?: 0)
            )
            result.success(analyzeZipFile(apk, evidence))
        } catch (error: Exception) {
            result.error("read_failed", error.message ?: "Could not read the selected installed app.", null)
        }
    }

    private fun analyzeZipFile(apk: File, evidence: Map<String, Any> = emptyMap()): Map<String, Any> {
        val scan = ApkStaticScan()
        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val name = entry.name
                scan.inspectName(name)

                if (name == "AndroidManifest.xml") {
                    scan.manifestBytes = zip.getInputStream(entry).use { it.readBytes() }
                } else if (scan.shouldScanContent(name) && entry.size in 1..MAX_ENTRY_SCAN_BYTES) {
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    scan.inspectContent(name, bytes)
                }
            }
        }
        return scan.toMap() + evidence
    }

    private fun sha256File(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) {
                    break
                }
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val MAX_ENTRY_SCAN_BYTES = 2_000_000L
        private val governmentAppSignals = listOf(
            "gov",
            "kerajaan",
            "malaysia",
            "mygov",
            "myjpj",
            "jpj",
            "jpn",
            "lhdn",
            "hasil",
            "mytax",
            "kwsp",
            "epf",
            "perkeso",
            "socso",
            "mysejahtera",
            "moh",
            "kkm",
            "moe",
            "mohe",
            "pdrm",
            "rmp",
            "sprm",
            "imigresen",
            "immigration",
            "mybayar",
            "mydigital",
            "myidentity",
            "dosm",
            "nadma",
            "jkm",
            "mampu",
            "egov",
            "myeg"
        )
    }
}

private class ApkStaticScan {
    var manifestBytes: ByteArray? = null
    private var dexCount = 0
    private val nativeLibraries = linkedSetOf<String>()
    private val httpUrls = linkedSetOf<String>()
    private val secretSignals = linkedSetOf<String>()
    private val trackerSignals = linkedSetOf<String>()
    private val networkConfigFiles = linkedSetOf<String>()
    private val backupRuleFiles = linkedSetOf<String>()
    private val signingFiles = linkedSetOf<String>()
    private val piiSignals = linkedSetOf<String>()
    private val cryptoSignals = linkedSetOf<String>()
    private val readableIdentifierSignals = linkedSetOf<String>()

    fun inspectName(name: String) {
        val lower = name.lowercase()
        if (Regex("""classes\d*\.dex""").matches(name.substringAfterLast('/'))) {
            dexCount += 1
        }
        if (lower.startsWith("lib/") && lower.endsWith(".so")) {
            nativeLibraries.add(name.substringAfterLast('/'))
        }
        if (lower.startsWith("meta-inf/") && (lower.endsWith(".rsa") || lower.endsWith(".dsa") || lower.endsWith(".ec") || lower.endsWith(".sf"))) {
            signingFiles.add(name)
        }
        if (lower.contains("network_security") || lower.contains("network-security")) {
            networkConfigFiles.add(name)
        }
        if (lower.contains("backup_rules") || lower.contains("data_extraction_rules")) {
            backupRuleFiles.add(name)
        }
        inspectTrackerText(name.replace('/', '.'))
    }

    fun shouldScanContent(name: String): Boolean {
        val lower = name.lowercase()
        return lower.endsWith(".dex") ||
            lower.endsWith(".xml") ||
            lower.endsWith(".json") ||
            lower.endsWith(".properties") ||
            lower.endsWith(".txt") ||
            lower.endsWith(".html") ||
            lower.endsWith(".js")
    }

    fun inspectContent(name: String, bytes: ByteArray) {
        if (bytes.isEmpty()) {
            return
        }
        val text = bytes.toString(Charsets.ISO_8859_1)
        httpUrlRegex.findAll(text).take(MAX_SIGNALS).forEach {
            httpUrls.add(it.value.take(120))
        }
        secretRegexes.forEach { regex ->
            regex.findAll(text).take(2).forEach {
                secretSignals.add("${name.substringAfterLast('/')}: ${it.value.take(42)}")
            }
        }
        piiRegexes.forEach { regex ->
            regex.findAll(text).take(2).forEach {
                piiSignals.add("${name.substringAfterLast('/')}: ${it.value.take(42)}")
            }
        }
        cryptoRegexes.forEach { regex ->
            regex.findAll(text).take(2).forEach {
                cryptoSignals.add("${name.substringAfterLast('/')}: ${it.value.take(42)}")
            }
        }
        readableIdentifierRegex.findAll(text).take(4).forEach {
            readableIdentifierSignals.add("${name.substringAfterLast('/')}: ${it.value.take(42)}")
        }
        inspectTrackerText(text)
    }

    private fun inspectTrackerText(text: String) {
        val normalized = text.lowercase().replace('/', '.')
        trackerPackages.forEach { tracker ->
            if (normalized.contains(tracker)) {
                trackerSignals.add(tracker)
            }
        }
    }

    fun toMap(): Map<String, Any> {
        val manifest = manifestBytes ?: throw IllegalStateException("AndroidManifest.xml was not found in this APK.")
        return mapOf(
            "manifestBytes" to manifest,
            "dexCount" to dexCount,
            "nativeLibCount" to nativeLibraries.size,
            "nativeLibraries" to nativeLibraries.take(MAX_SIGNALS),
            "httpUrls" to httpUrls.take(MAX_SIGNALS),
            "secretSignals" to secretSignals.take(MAX_SIGNALS),
            "trackerSignals" to trackerSignals.take(MAX_SIGNALS),
            "networkConfigFiles" to networkConfigFiles.take(MAX_SIGNALS),
            "backupRuleFiles" to backupRuleFiles.take(MAX_SIGNALS),
            "signingFiles" to signingFiles.take(MAX_SIGNALS),
            "piiSignals" to piiSignals.take(MAX_SIGNALS),
            "cryptoSignals" to cryptoSignals.take(MAX_SIGNALS),
            "readableIdentifierSignals" to readableIdentifierSignals.take(MAX_SIGNALS)
        )
    }

    companion object {
        private const val MAX_SIGNALS = 12
        private val httpUrlRegex = Regex("""http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
        private val secretRegexes = listOf(
            Regex("""AIza[0-9A-Za-z_-]{20,}"""),
            Regex("""AKIA[0-9A-Z]{16}"""),
            Regex("""sk_live_[0-9A-Za-z]{16,}"""),
            Regex("""(?i)(api[_-]?key|secret|token|password)["'=:\s]{1,8}[A-Za-z0-9_.\-]{8,}""")
        )
        private val piiRegexes = listOf(
            Regex("""\b\d{6}[- ]?\d{2}[- ]?\d{4}\b"""),
            Regex("""(?i)\b(no[_-]?ic|nric|mykad|passport[_-]?(num|number)?|phone[_-]?(no|number)?|alamat|address|dob|date[_-]?of[_-]?birth)\b""")
        )
        private val cryptoRegexes = listOf(
            Regex("""(?i)\b(MD5|SHA-?1|DES|3DES|Blowfish|RC4|AES/ECB|ECB/PKCS5Padding)\b""")
        )
        private val readableIdentifierRegex = Regex(
            """(?i)\b(processPayment|loginUser|verifyPassword|decryptData|encryptData|uploadDocument|customerData|userProfile|identityCard|passportNumber|phoneNumber|homeAddress)\b"""
        )
        private val trackerPackages = listOf(
            "com.google.firebase",
            "com.google.android.gms.ads",
            "com.facebook",
            "com.appsflyer",
            "com.adjust.sdk",
            "com.flurry",
            "com.onesignal",
            "com.crashlytics",
            "com.amplitude",
            "com.segment.analytics"
        )
    }
}
