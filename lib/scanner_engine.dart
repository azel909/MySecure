enum Severity { critical, high, medium, low }

class ScanFinding {
  const ScanFinding({
    required this.id,
    required this.severity,
    required this.score,
    required this.title,
    required this.advice,
    this.category = 'Manifest Security',
    this.macLevel = 'Level 1',
  });

  final String id;
  final Severity severity;
  final int score;
  final String title;
  final String advice;
  final String category;
  final String macLevel;

  Map<String, Object> toJson() => {
    'category': category,
    'severity': severity.name,
    'title': title,
    'advice': advice,
    'macLevel': macLevel,
  };
}

class ApkArtifact {
  const ApkArtifact({
    this.evidenceSource = 'unknown',
    this.apkSha256 = '',
    this.apkSizeBytes = 0,
    this.sourcePath = '',
    this.installerPackage = '',
    this.firstInstallTime = '',
    this.lastUpdateTime = '',
    this.splitApkCount = 0,
    this.dexCount = 0,
    this.nativeLibCount = 0,
    this.nativeLibraries = const <String>[],
    this.httpUrls = const <String>[],
    this.secretSignals = const <String>[],
    this.trackerSignals = const <String>[],
    this.networkConfigFiles = const <String>[],
    this.backupRuleFiles = const <String>[],
    this.signingFiles = const <String>[],
    this.piiSignals = const <String>[],
    this.cryptoSignals = const <String>[],
    this.readableIdentifierSignals = const <String>[],
  });

  final String evidenceSource;
  final String apkSha256;
  final int apkSizeBytes;
  final String sourcePath;
  final String installerPackage;
  final String firstInstallTime;
  final String lastUpdateTime;
  final int splitApkCount;
  final int dexCount;
  final int nativeLibCount;
  final List<String> nativeLibraries;
  final List<String> httpUrls;
  final List<String> secretSignals;
  final List<String> trackerSignals;
  final List<String> networkConfigFiles;
  final List<String> backupRuleFiles;
  final List<String> signingFiles;
  final List<String> piiSignals;
  final List<String> cryptoSignals;
  final List<String> readableIdentifierSignals;

  Map<String, Object> toJson() => {
    'evidenceSource': evidenceSource,
    'apkSha256': apkSha256,
    'apkSizeBytes': apkSizeBytes,
    'sourcePath': sourcePath,
    'installerPackage': installerPackage,
    'firstInstallTime': firstInstallTime,
    'lastUpdateTime': lastUpdateTime,
    'splitApkCount': splitApkCount,
    'dexCount': dexCount,
    'nativeLibCount': nativeLibCount,
    'nativeLibraries': nativeLibraries,
    'httpUrls': httpUrls,
    'secretSignals': secretSignals,
    'trackerSignals': trackerSignals,
    'networkConfigFiles': networkConfigFiles,
    'backupRuleFiles': backupRuleFiles,
    'signingFiles': signingFiles,
    'piiSignals': piiSignals,
    'cryptoSignals': cryptoSignals,
    'readableIdentifierSignals': readableIdentifierSignals,
  };
}

class ScanProfile {
  const ScanProfile({
    required this.appName,
    required this.packageName,
    required this.version,
    required this.targetSdk,
    required this.manifest,
    this.completedControls = const <String>{},
    this.artifact,
  });

  final String appName;
  final String packageName;
  final String version;
  final int targetSdk;
  final String manifest;
  final Set<String> completedControls;
  final ApkArtifact? artifact;
}

class ScannerEngine {
  static List<ScanFinding> scan(ScanProfile profile) {
    final manifest = profile.manifest;
    final findings = <ScanFinding>[];

    void addWhen(bool condition, ScanFinding finding) {
      if (condition) {
        findings.add(finding);
      }
    }

    addWhen(
      RegExp(
        r'android:debuggable\s*=\s*"true"',
        caseSensitive: false,
      ).hasMatch(manifest),
      const ScanFinding(
        id: 'debuggable',
        severity: Severity.critical,
        score: 22,
        title: 'Debuggable build is enabled',
        advice:
            'Disable android:debuggable for release builds to reduce runtime inspection and tampering risk.',
        category: 'Binary Hardening',
        macLevel: 'Level 3',
      ),
    );

    addWhen(
      RegExp(
        r'android:allowBackup\s*=\s*"true"',
        caseSensitive: false,
      ).hasMatch(manifest),
      const ScanFinding(
        id: 'backup',
        severity: Severity.high,
        score: 16,
        title: 'Application backup is allowed',
        advice:
            'Set allowBackup to false or define strict backup rules for sensitive application data.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 3',
      ),
    );

    addWhen(
      RegExp(
        r'android:usesCleartextTraffic\s*=\s*"true"',
        caseSensitive: false,
      ).hasMatch(manifest),
      const ScanFinding(
        id: 'cleartext',
        severity: Severity.high,
        score: 18,
        title: 'Cleartext network traffic is permitted',
        advice:
            'Require HTTPS traffic and configure a network security policy for trusted domains.',
        category: 'Communication and APIs',
        macLevel: 'Level 2',
      ),
    );

    final usesNetwork =
        _usesPermission(manifest, 'INTERNET') ||
        _usesPermission(manifest, 'ACCESS_NETWORK_STATE') ||
        _has(manifest, r'android:usesCleartextTraffic\s*=\s*"true"');

    addWhen(
      usesNetwork && !_has(manifest, r'android:networkSecurityConfig\s*='),
      const ScanFinding(
        id: 'missing-network-security-config',
        severity: Severity.low,
        score: 2,
        title: 'Network security config not declared',
        advice:
            'Define a network security config to control cleartext traffic, trusted CAs, certificate pinning, and debug overrides.',
        category: 'Communication and APIs',
        macLevel: 'Level 1',
      ),
    );

    addWhen(
      RegExp(
        r'<activity\b[^>]*android:exported\s*=\s*"true"',
        caseSensitive: false,
      ).hasMatch(manifest),
      const ScanFinding(
        id: 'exported-activity',
        severity: Severity.high,
        score: 15,
        title: 'Exported activity detected',
        advice:
            'Export only public entry points and protect sensitive activities with permissions.',
        category: 'Code Quality and Logic',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      RegExp(
        r'<provider\b[^>]*android:exported\s*=\s*"true"',
        caseSensitive: false,
      ).hasMatch(manifest),
      const ScanFinding(
        id: 'exported-provider',
        severity: Severity.critical,
        score: 24,
        title: 'Exported content provider detected',
        advice:
            'Avoid exported providers unless necessary and enforce strong read/write permissions.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 3',
      ),
    );

    addWhen(
      _has(manifest, r'<service\b[^>]*android:exported\s*=\s*"true"'),
      const ScanFinding(
        id: 'exported-service',
        severity: Severity.high,
        score: 15,
        title: 'Exported service detected',
        advice:
            'Restrict exported services and require signature-level permissions for sensitive background operations.',
        category: 'Code Quality and Logic',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _has(manifest, r'<receiver\b[^>]*android:exported\s*=\s*"true"'),
      const ScanFinding(
        id: 'exported-receiver',
        severity: Severity.high,
        score: 14,
        title: 'Exported broadcast receiver detected',
        advice:
            'Avoid public receivers for sensitive actions and validate every inbound intent.',
        category: 'Code Quality and Logic',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      RegExp(
        'READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE',
        caseSensitive: false,
      ).hasMatch(manifest),
      const ScanFinding(
        id: 'external-storage',
        severity: Severity.medium,
        score: 8,
        title: 'External storage permission requested',
        advice:
            'Use scoped storage and avoid placing sensitive data in shared external locations.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _usesPermission(manifest, 'MANAGE_EXTERNAL_STORAGE'),
      const ScanFinding(
        id: 'manage-external-storage',
        severity: Severity.high,
        score: 14,
        title: 'All files access permission requested',
        advice:
            'Avoid MANAGE_EXTERNAL_STORAGE unless the app genuinely needs broad file-manager style access.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _has(manifest, r'android:requestLegacyExternalStorage\s*=\s*"true"'),
      const ScanFinding(
        id: 'legacy-external-storage',
        severity: Severity.medium,
        score: 9,
        title: 'Legacy external storage mode requested',
        advice:
            'Remove requestLegacyExternalStorage and migrate sensitive file handling to scoped storage.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _usesAnyPermission(manifest, const [
        'READ_SMS',
        'SEND_SMS',
        'RECEIVE_SMS',
      ]),
      const ScanFinding(
        id: 'sms-permissions',
        severity: Severity.high,
        score: 15,
        title: 'SMS permission requested',
        advice:
            'SMS permissions are high-risk and should be justified by a core feature with strict runtime consent.',
        category: 'Permissions and Runtime Environment',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _usesAnyPermission(manifest, const [
        'READ_CONTACTS',
        'WRITE_CONTACTS',
        'GET_ACCOUNTS',
      ]),
      const ScanFinding(
        id: 'contacts-permissions',
        severity: Severity.medium,
        score: 10,
        title: 'Contacts or account permission requested',
        advice:
            'Limit contact/account access and avoid collecting personal data unless strictly required.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _usesAnyPermission(manifest, const [
        'ACCESS_FINE_LOCATION',
        'ACCESS_COARSE_LOCATION',
        'ACCESS_BACKGROUND_LOCATION',
      ]),
      const ScanFinding(
        id: 'location-permissions',
        severity: Severity.medium,
        score: 10,
        title: 'Location permission requested',
        advice:
            'Request location only in context, avoid background location unless essential, and document retention clearly.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _usesPermission(manifest, 'RECORD_AUDIO'),
      const ScanFinding(
        id: 'microphone-permission',
        severity: Severity.medium,
        score: 9,
        title: 'Microphone permission requested',
        advice:
            'Ensure microphone capture is user-initiated and never retained or logged without clear consent.',
        category: 'Data Storage and Privacy',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _usesPermission(manifest, 'SYSTEM_ALERT_WINDOW'),
      const ScanFinding(
        id: 'overlay-permission',
        severity: Severity.high,
        score: 15,
        title: 'Overlay permission requested',
        advice:
            'Overlay access can support phishing or tapjacking abuse; require strong justification and safeguards.',
        category: 'Malware and Integrity Check',
        macLevel: 'Level 3',
      ),
    );

    addWhen(
      _usesPermission(manifest, 'REQUEST_INSTALL_PACKAGES'),
      const ScanFinding(
        id: 'install-packages-permission',
        severity: Severity.high,
        score: 13,
        title: 'Package installation permission requested',
        advice:
            'Avoid requesting package installation unless the app is a trusted installer or enterprise updater.',
        category: 'Malware and Integrity Check',
        macLevel: 'Level 3',
      ),
    );

    addWhen(
      _usesPermission(manifest, 'QUERY_ALL_PACKAGES'),
      const ScanFinding(
        id: 'query-all-packages',
        severity: Severity.medium,
        score: 8,
        title: 'Broad installed-app visibility requested',
        advice:
            'Limit package visibility with targeted queries where possible to reduce privacy exposure.',
        category: 'Permissions and Runtime Environment',
        macLevel: 'Level 1',
      ),
    );

    addWhen(
      _has(manifest, r'android\.permission\.BIND_ACCESSIBILITY_SERVICE'),
      const ScanFinding(
        id: 'accessibility-service',
        severity: Severity.high,
        score: 18,
        title: 'Accessibility service declared',
        advice:
            'Accessibility services can observe and control user interactions; verify the feature cannot be abused.',
        category: 'Malware and Integrity Check',
        macLevel: 'Level 3',
      ),
    );

    addWhen(
      _usesPermission(manifest, 'RECEIVE_BOOT_COMPLETED'),
      const ScanFinding(
        id: 'boot-persistence',
        severity: Severity.medium,
        score: 8,
        title: 'Starts after device boot',
        advice:
            'Review boot receivers for persistence abuse and ensure background work is transparent to users.',
        category: 'Malware and Integrity Check',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _has(manifest, r'android:testOnly\s*=\s*"true"'),
      const ScanFinding(
        id: 'test-only',
        severity: Severity.high,
        score: 13,
        title: 'Test-only build flag is enabled',
        advice:
            'Do not distribute testOnly builds because they bypass normal install expectations and indicate a non-release artifact.',
        category: 'Binary Hardening',
        macLevel: 'Level 2',
      ),
    );

    addWhen(
      _has(manifest, r'android:extractNativeLibs\s*=\s*"true"'),
      const ScanFinding(
        id: 'extract-native-libs',
        severity: Severity.low,
        score: 5,
        title: 'Native libraries are extracted at install time',
        advice:
            'Review native library hardening and only extract native libs when required by compatibility needs.',
        category: 'Binary Hardening',
        macLevel: 'Level 1',
      ),
    );

    addWhen(
      profile.targetSdk < 31,
      const ScanFinding(
        id: 'old-target-sdk',
        severity: Severity.low,
        score: 4,
        title: 'Target SDK is outdated',
        advice:
            'Raise targetSdkVersion to inherit current Android platform protections and behavior changes.',
        category: 'Binary Hardening',
        macLevel: 'Level 1',
      ),
    );

    final artifact = profile.artifact;
    if (artifact != null) {
      addWhen(
        artifact.httpUrls.isNotEmpty,
        ScanFinding(
          id: 'hardcoded-http-url',
          severity: Severity.high,
          score: 16,
          title: 'Hardcoded insecure HTTP endpoint found',
          advice:
              'Replace plain HTTP endpoints with HTTPS and review these URLs: ${artifact.httpUrls.take(3).join(', ')}.',
          category: 'Communication and APIs',
          macLevel: 'Level 2',
        ),
      );

      addWhen(
        artifact.secretSignals.isNotEmpty,
        ScanFinding(
          id: 'hardcoded-secret-signal',
          severity: Severity.critical,
          score: 24,
          title: 'Possible hardcoded secret or API key found',
          advice:
              'Review APK strings/resources for exposed credentials. Signals: ${artifact.secretSignals.take(4).join(', ')}.',
          category: 'Code Quality and Logic',
          macLevel: 'Level 2',
        ),
      );

      addWhen(
        artifact.piiSignals.isNotEmpty,
        ScanFinding(
          id: 'pdpa-pii-signal',
          severity: Severity.high,
          score: 18,
          title: 'Possible Malaysian PII or PDPA keyword found',
          advice:
              'Review code and asset files for unencrypted NRIC, passport, phone, address, or personal-data fields. Signals: ${artifact.piiSignals.take(4).join(', ')}.',
          category: 'Government PDPA Privacy Exposure',
          macLevel: 'Level 3',
        ),
      );

      addWhen(
        artifact.cryptoSignals.isNotEmpty,
        ScanFinding(
          id: 'legacy-crypto-signal',
          severity: Severity.high,
          score: 15,
          title: 'Weak or legacy cryptography keyword found',
          advice:
              'Replace legacy algorithms or modes with modern approved cryptography. Signals: ${artifact.cryptoSignals.take(4).join(', ')}.',
          category: 'Government Cryptography Audit',
          macLevel: 'Level 3',
        ),
      );

      addWhen(
        artifact.readableIdentifierSignals.length >= 4,
        ScanFinding(
          id: 'readable-identifier-signal',
          severity: Severity.medium,
          score: 8,
          title: 'Readable business identifiers detected',
          advice:
              'Review obfuscation and release build hardening. Readable identifiers can make reverse engineering easier. Signals: ${artifact.readableIdentifierSignals.take(4).join(', ')}.',
          category: 'Government MAC Scheme Hardening',
          macLevel: 'Level 3',
        ),
      );

      addWhen(
        artifact.nativeLibCount > 0,
        ScanFinding(
          id: 'native-code-present',
          severity: Severity.low,
          score: 0,
          title: 'Native libraries are present',
          advice:
              'Native code should be reviewed for memory-safety flaws and compiled with hardening flags. Libraries: ${artifact.nativeLibraries.take(3).join(', ')}.',
          category: 'Binary Code Security',
          macLevel: 'Level 3',
        ),
      );

      addWhen(
        artifact.dexCount > 1,
        const ScanFinding(
          id: 'multidex-app',
          severity: Severity.low,
          score: 0,
          title: 'Multiple DEX files detected',
          advice:
              'Multiple DEX files are normal in large apps, but all classes should be included in static review and secret scanning.',
          category: 'SAST Coverage',
          macLevel: 'Level 1',
        ),
      );

      addWhen(
        artifact.trackerSignals.isNotEmpty,
        ScanFinding(
          id: 'third-party-sdk-signal',
          severity: Severity.medium,
          score: 7,
          title: 'Third-party SDK or tracking package signal found',
          advice:
              'Review third-party SDK purpose, privacy disclosures, data sharing, and update status. Signals: ${artifact.trackerSignals.take(4).join(', ')}.',
          category: 'Open-Source and Third-Party Dependencies',
          macLevel: 'Level 2',
        ),
      );

      addWhen(
        usesNetwork &&
            artifact.networkConfigFiles.isEmpty &&
            !_has(manifest, r'android:networkSecurityConfig\s*='),
        const ScanFinding(
          id: 'network-policy-file-missing',
          severity: Severity.low,
          score: 2,
          title: 'No network policy file found in APK',
          advice:
              'Add a network security config to define cleartext, CA trust, certificate pinning, and debug certificate behavior.',
          category: 'Communication and APIs',
          macLevel: 'Level 1',
        ),
      );

      addWhen(
        artifact.backupRuleFiles.isEmpty &&
            _has(manifest, r'android:allowBackup\s*=\s*"true"'),
        const ScanFinding(
          id: 'backup-rules-missing',
          severity: Severity.medium,
          score: 8,
          title: 'Backup enabled without visible backup rules',
          advice:
              'Define backup rules to exclude tokens, local databases, private keys, and other sensitive files.',
          category: 'Data Storage and Privacy',
          macLevel: 'Level 3',
        ),
      );

      addWhen(
        artifact.signingFiles.isEmpty,
        const ScanFinding(
          id: 'legacy-signature-files-not-visible',
          severity: Severity.low,
          score: 0,
          title: 'Legacy META-INF signature files not visible',
          advice:
              'Modern APK signing may not expose legacy signature files, but release builds should still be verified with apksigner.',
          category: 'Binary Code Security',
          macLevel: 'Level 1',
        ),
      );
    }

    return findings;
  }

  static bool _has(String manifest, String pattern) {
    return RegExp(pattern, caseSensitive: false).hasMatch(manifest);
  }

  static bool _usesPermission(String manifest, String permission) {
    return RegExp(
      'android\\.permission\\.${RegExp.escape(permission)}',
      caseSensitive: false,
    ).hasMatch(manifest);
  }

  static bool _usesAnyPermission(String manifest, List<String> permissions) {
    return permissions.any(
      (permission) => _usesPermission(manifest, permission),
    );
  }

  static int riskScore(
    List<ScanFinding> findings,
    Set<String> completedControls,
  ) {
    const controlCredits = <String, int>{
      'obfuscation': 8,
      'pinning': 10,
      'secrets': 7,
      'abuseControls': 6,
      'encryptedStorage': 8,
      'httpsOnly': 6,
    };

    final baseScore = findings.fold<int>(
      0,
      (total, finding) => total + finding.score,
    );
    final credits = completedControls.fold<int>(
      0,
      (total, control) => total + (controlCredits[control] ?? 0),
    );

    return (baseScore - credits).clamp(0, 100);
  }

  static String riskLevel(int score) {
    if (score >= 76) {
      return 'Critical';
    }
    if (score >= 51) {
      return 'High';
    }
    if (score >= 26) {
      return 'Medium';
    }
    return 'Low';
  }
}
