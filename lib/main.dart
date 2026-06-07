import 'dart:convert';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'apk_manifest_reader.dart';
import 'screens/auth_screen.dart';
import 'screens/report_history_screen.dart';
import 'services/backend_api.dart';
import 'scanner_engine.dart';

void main() {
  runApp(const MySecureApp());
}

const _gold = Color(0xFFF5B323);
const _goldDeep = Color(0xFFC47A00);
const _navyDeep = Color(0xFF071845);
const _blueGlow = Color(0xFF1FA7FF);
const _ink = Color(0xFF06122E);
const _panel = Color(0xFF0D2355);
const _panelSoft = Color(0xFF14316F);
const _line = Color(0xFF31558E);
const _muted = Color(0xFFB7C7E7);

class MySecureApp extends StatelessWidget {
  const MySecureApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MySecure',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: _blueGlow,
          brightness: Brightness.dark,
        ),
        scaffoldBackgroundColor: _ink,
        fontFamily: 'Roboto',
        useMaterial3: true,
      ),
      home: const AuthGate(),
    );
  }
}

class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  static const _prefs = MethodChannel('mysecure/preferences');

  AuthSession? session;
  bool restoringSession = true;

  @override
  void initState() {
    super.initState();
    _restoreSession();
  }

  Future<void> _restoreSession() async {
    try {
      final saved = await _prefs.invokeMethod<String>('getString', {
        'key': 'auth_session',
      });
      if (saved == null || saved.isEmpty) {
        return;
      }
      final restored = AuthSession.fromJson(
        jsonDecode(saved) as Map<String, dynamic>,
      );
      final user = await BackendApi(restored.baseUrl).me(restored.accessToken);
      if (mounted) {
        setState(() {
          session = AuthSession(
            baseUrl: restored.baseUrl,
            accessToken: restored.accessToken,
            user: user,
          );
        });
      }
    } catch (_) {
      await _prefs.invokeMethod<void>('remove', {'key': 'auth_session'});
    } finally {
      if (mounted) {
        setState(() => restoringSession = false);
      }
    }
  }

  Future<void> _saveSession(AuthSession value) async {
    await _prefs.invokeMethod<void>('setString', {
      'key': 'backend_url',
      'value': value.baseUrl,
    });
    await _prefs.invokeMethod<void>('setString', {
      'key': 'auth_session',
      'value': jsonEncode(value.toJson()),
    });
  }

  Future<void> _clearSession() async {
    await _prefs.invokeMethod<void>('remove', {'key': 'auth_session'});
  }

  @override
  Widget build(BuildContext context) {
    if (restoringSession) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator(color: _gold)),
      );
    }

    final currentSession = session;
    if (currentSession == null) {
      return AuthScreen(
        onAuthenticated: (value) async {
          await _saveSession(value);
          if (mounted) {
            setState(() => session = value);
          }
        },
      );
    }

    return ScannerScreen(
      session: currentSession,
      onLogout: () async {
        try {
          await BackendApi(
            currentSession.baseUrl,
          ).logout(currentSession.accessToken);
        } finally {
          await _clearSession();
          if (mounted) {
            setState(() => session = null);
          }
        }
      },
    );
  }
}

class ScannerScreen extends StatefulWidget {
  const ScannerScreen({
    required this.session,
    required this.onLogout,
    super.key,
  });

  final AuthSession session;
  final VoidCallback onLogout;

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  static const _apkPicker = MethodChannel('droidshield/apk_picker');

  final appNameController = TextEditingController(text: 'Sample Android App');
  final packageController = TextEditingController(text: 'com.example.app');
  final versionController = TextEditingController(text: '1.0.0');
  final targetSdkController = TextEditingController(text: '28');
  final manifestController = TextEditingController(text: sampleManifest);
  final completedControls = <String>{};

  ApkArtifact? currentArtifact;
  late List<ScanFinding> findings = _scanProfile();
  bool scanningInstalledApp = false;
  int tabIndex = 0;

  @override
  void dispose() {
    appNameController.dispose();
    packageController.dispose();
    versionController.dispose();
    targetSdkController.dispose();
    manifestController.dispose();
    super.dispose();
  }

  int get targetSdk => int.tryParse(targetSdkController.text) ?? 1;

  ScanProfile get profile => ScanProfile(
    appName: appNameController.text.trim(),
    packageName: packageController.text.trim(),
    version: versionController.text.trim(),
    targetSdk: targetSdk,
    manifest: manifestController.text,
    completedControls: completedControls,
    artifact: currentArtifact,
  );

  List<ScanFinding> _scanProfile() => ScannerEngine.scan(profile);

  int get score => ScannerEngine.riskScore(findings, completedControls);
  String get level => ScannerEngine.riskLevel(score);

  void runScan() {
    setState(() {
      findings = _scanProfile();
      tabIndex = 1;
    });
  }

  void updateControl(String control, bool selected) {
    setState(() {
      if (selected) {
        completedControls.add(control);
      } else {
        completedControls.remove(control);
      }
    });
  }

  Future<void> scanInstalledApp() async {
    setState(() {
      scanningInstalledApp = true;
    });

    try {
      final apps = await _apkPicker.invokeMethod<List<dynamic>>(
        'listInstalledApps',
      );
      if (!mounted) {
        return;
      }

      final selected = await showModalBottomSheet<Map<String, Object?>>(
        context: context,
        backgroundColor: _panel,
        showDragHandle: true,
        builder: (context) => _InstalledAppsSheet(apps: apps ?? const []),
      );

      if (selected == null) {
        return;
      }

      final analysis = await _apkPicker.invokeMethod<Map<dynamic, dynamic>>(
        'readInstalledAnalysis',
        {'packageName': selected['packageName']},
      );
      if (analysis == null) {
        return;
      }

      final decoded = _decodeAnalysis(analysis);
      final manifest = decoded.manifest;
      setState(() {
        appNameController.text =
            '${selected['label'] ?? appNameController.text}';
        packageController.text =
            manifest.packageName ??
            '${selected['packageName'] ?? packageController.text}';
        versionController.text =
            manifest.versionName ??
            '${selected['versionName'] ?? versionController.text}';
        targetSdkController.text =
            '${manifest.targetSdk ?? selected['targetSdk'] ?? targetSdk}';
        manifestController.text = manifest.xml;
        currentArtifact = decoded.artifact;
        findings = _scanProfile();
        tabIndex = 1;
      });

      if (mounted) {
        _toast('Installed app scanned');
      }
    } on PlatformException catch (error) {
      if (mounted) {
        _toast(error.message ?? 'Could not scan installed app');
      }
    } on FormatException catch (error) {
      if (mounted) {
        _toast(error.message);
      }
    } catch (error) {
      if (mounted) {
        _toast('Could not scan this installed app: $error');
      }
    } finally {
      if (mounted) {
        setState(() {
          scanningInstalledApp = false;
        });
      }
    }
  }

  Future<void> copyReport() async {
    final report = _buildReport();

    await Clipboard.setData(
      ClipboardData(text: const JsonEncoder.withIndent('  ').convert(report)),
    );

    if (mounted) {
      _toast('Security report copied as JSON');
    }
  }

  Future<void> uploadReport() async {
    try {
      final reportId = await BackendApi(
        widget.session.baseUrl,
      ).createReport(token: widget.session.accessToken, report: _buildReport());
      if (mounted) {
        _toast('Report uploaded to backend as #$reportId');
        setState(() => tabIndex = 3);
      }
    } catch (error) {
      if (mounted) {
        _toast('Could not upload report: $error');
      }
    }
  }

  Map<String, Object?> _buildReport() {
    return {
      'appName': profile.appName,
      'packageName': profile.packageName,
      'version': profile.version,
      'targetSdk': profile.targetSdk,
      'riskScore': score,
      'riskLevel': level,
      'forensicEvidence': currentArtifact?.toJson(),
      'findings': findings.map((finding) => finding.toJson()).toList(),
      'generatedAt': DateTime.now().toIso8601String(),
      'examinerName': widget.session.user.name,
    };
  }

  void _toast(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
        backgroundColor: _panelSoft,
      ),
    );
  }

  _DecodedApkAnalysis _decodeAnalysis(Map<dynamic, dynamic> analysis) {
    final manifestBytes = analysis['manifestBytes'];
    if (manifestBytes is! Uint8List) {
      throw const FormatException('APK manifest could not be extracted.');
    }

    return _DecodedApkAnalysis(
      manifest: ApkManifestReader.readManifestBytes(manifestBytes),
      artifact: ApkArtifact(
        evidenceSource: _stringValue(analysis['evidenceSource']),
        apkSha256: _stringValue(analysis['apkSha256']),
        apkSizeBytes: _intValue(analysis['apkSizeBytes']),
        sourcePath: _stringValue(analysis['sourcePath']),
        installerPackage: _stringValue(analysis['installerPackage']),
        firstInstallTime: _stringValue(analysis['firstInstallTime']),
        lastUpdateTime: _stringValue(analysis['lastUpdateTime']),
        splitApkCount: _intValue(analysis['splitApkCount']),
        dexCount: _intValue(analysis['dexCount']),
        nativeLibCount: _intValue(analysis['nativeLibCount']),
        nativeLibraries: _stringList(analysis['nativeLibraries']),
        httpUrls: _stringList(analysis['httpUrls']),
        secretSignals: _stringList(analysis['secretSignals']),
        trackerSignals: _stringList(analysis['trackerSignals']),
        networkConfigFiles: _stringList(analysis['networkConfigFiles']),
        backupRuleFiles: _stringList(analysis['backupRuleFiles']),
        signingFiles: _stringList(analysis['signingFiles']),
        piiSignals: _stringList(analysis['piiSignals']),
        cryptoSignals: _stringList(analysis['cryptoSignals']),
        readableIdentifierSignals: _stringList(
          analysis['readableIdentifierSignals'],
        ),
      ),
    );
  }

  int _intValue(Object? value) {
    return value is int ? value : int.tryParse('$value') ?? 0;
  }

  String _stringValue(Object? value) {
    final text = '${value ?? ''}';
    return text == 'null' ? '' : text;
  }

  List<String> _stringList(Object? value) {
    if (value is List) {
      return value
          .map((item) => '$item')
          .where((item) => item.isNotEmpty)
          .toList();
    }
    return const <String>[];
  }

  @override
  Widget build(BuildContext context) {
    final pages = [
      _HomePage(state: this),
      _ResultsPage(state: this),
      _ChecklistPage(state: this),
      ReportHistoryScreen(session: widget.session, key: ValueKey(tabIndex)),
    ];

    return Scaffold(
      body: Stack(
        children: [
          const _CyberBackground(),
          SafeArea(
            child: Column(
              children: [
                _TopChrome(
                  userName: widget.session.user.name,
                  onLogout: widget.onLogout,
                ),
                Expanded(
                  child: AnimatedSwitcher(
                    duration: const Duration(milliseconds: 220),
                    child: pages[tabIndex],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      bottomNavigationBar: _BottomTabs(
        currentIndex: tabIndex,
        onChanged: (index) => setState(() => tabIndex = index),
      ),
    );
  }
}

class _DecodedApkAnalysis {
  const _DecodedApkAnalysis({required this.manifest, required this.artifact});

  final ApkManifest manifest;
  final ApkArtifact artifact;
}

class _CyberBackground extends StatefulWidget {
  const _CyberBackground();

  @override
  State<_CyberBackground> createState() => _CyberBackgroundState();
}

class _CyberBackgroundState extends State<_CyberBackground>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 10),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        return Container(
          decoration: const BoxDecoration(
            gradient: RadialGradient(
              center: Alignment.topCenter,
              radius: 1,
              colors: [Color(0xFF164B9A), _navyDeep, _ink],
              stops: [0, 0.55, 1],
            ),
          ),
          child: CustomPaint(
            painter: _CircuitPainter(progress: _controller.value),
            size: Size.infinite,
          ),
        );
      },
    );
  }
}

class _TopChrome extends StatelessWidget {
  const _TopChrome({required this.userName, required this.onLogout});

  final String userName;
  final VoidCallback onLogout;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 10, 18, 6),
      child: Row(
        children: [
          const CircleAvatar(
            radius: 18,
            backgroundColor: _panelSoft,
            child: Padding(
              padding: EdgeInsets.all(4),
              child: Image(
                image: AssetImage('assets/branding/secure_logo.png'),
                fit: BoxFit.contain,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'MySecure',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w900,
                  ),
                ),
                Text(
                  'Signed in: $userName',
                  style: const TextStyle(color: _muted, fontSize: 12),
                ),
              ],
            ),
          ),
          IconButton(
            tooltip: 'Logout',
            onPressed: onLogout,
            icon: const Icon(Icons.logout_rounded, color: _gold),
          ),
        ],
      ),
    );
  }
}

class _HomePage extends StatelessWidget {
  const _HomePage({required this.state});

  final _ScannerScreenState state;

  @override
  Widget build(BuildContext context) {
    return ListView(
      key: const ValueKey('home'),
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 22),
      children: [
        const SizedBox(height: 8),
        const Center(child: _ShieldHero(size: 210)),
        const SizedBox(height: 18),
        const Text(
          'MySecure\nGovernment Mobile\nAudit Shield',
          style: TextStyle(
            color: Colors.white,
            fontSize: 28,
            height: 1.05,
            fontWeight: FontWeight.w900,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Audit government Android apps for PDPA exposure, MAC hardening gaps, and forensic evidence readiness.',
          style: TextStyle(color: _muted, height: 1.4),
        ),
        const SizedBox(height: 22),
        _GoldButton(
          label: state.scanningInstalledApp
              ? 'Loading Government Apps'
              : 'Scan Government App',
          icon: state.scanningInstalledApp
              ? Icons.hourglass_top_rounded
              : Icons.apps_rounded,
          onPressed: state.scanningInstalledApp ? null : state.scanInstalledApp,
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: state.runScan,
          icon: const Icon(Icons.play_arrow_rounded),
          label: const Text('Scan pasted manifest'),
          style: OutlinedButton.styleFrom(
            foregroundColor: _gold,
            side: const BorderSide(color: _goldDeep),
            minimumSize: const Size.fromHeight(48),
          ),
        ),
        const SizedBox(height: 18),
        _DarkPanel(
          title: 'Government Application Details',
          child: Column(
            children: [
              _ProfileField(
                label: 'App name',
                controller: state.appNameController,
              ),
              _ProfileField(
                label: 'Package name',
                controller: state.packageController,
              ),
              Row(
                children: [
                  Expanded(
                    child: _ProfileField(
                      label: 'Version',
                      controller: state.versionController,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: _ProfileField(
                      label: 'Target SDK',
                      controller: state.targetSdkController,
                      keyboardType: TextInputType.number,
                      onChanged: (_) => state.runScan(),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        _DarkPanel(
          title: 'Manifest Input',
          action: IconButton(
            tooltip: 'Run scan',
            onPressed: state.runScan,
            icon: const Icon(Icons.radar_rounded, color: _gold),
          ),
          child: TextField(
            controller: state.manifestController,
            minLines: 8,
            maxLines: 14,
            spellCheckConfiguration: const SpellCheckConfiguration.disabled(),
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 12,
              color: Color(0xFFEAF3FF),
            ),
            decoration: const InputDecoration(
              hintText: 'Paste AndroidManifest.xml here',
              hintStyle: TextStyle(color: _muted),
              border: OutlineInputBorder(borderSide: BorderSide(color: _line)),
              enabledBorder: OutlineInputBorder(
                borderSide: BorderSide(color: _line),
              ),
              focusedBorder: OutlineInputBorder(
                borderSide: BorderSide(color: _gold),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _ResultsPage extends StatelessWidget {
  const _ResultsPage({required this.state});

  final _ScannerScreenState state;

  @override
  Widget build(BuildContext context) {
    final critical = state.findings
        .where((finding) => finding.severity == Severity.critical)
        .length;
    final high = state.findings
        .where((finding) => finding.severity == Severity.high)
        .length;
    final medium = state.findings
        .where((finding) => finding.severity == Severity.medium)
        .length;

    return ListView(
      key: const ValueKey('results'),
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 22),
      children: [
        _ScanMeter(score: state.score, level: state.level),
        const SizedBox(height: 16),
        const _RiskClassificationPanel(),
        const SizedBox(height: 16),
        _ComplianceDashboard(findings: state.findings, score: state.score),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: _MetricCard(
                label: 'Critical',
                value: '$critical',
                icon: Icons.dangerous_outlined,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _MetricCard(
                label: 'High',
                value: '$high',
                icon: Icons.warning_amber_outlined,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _MetricCard(
                label: 'Medium',
                value: '$medium',
                icon: Icons.report_outlined,
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        _ForensicSnapshot(artifact: state.currentArtifact),
        const SizedBox(height: 16),
        _DarkPanel(
          title: 'Government Audit Findings',
          action: Wrap(
            spacing: 4,
            children: [
              IconButton(
                tooltip: 'Upload report',
                onPressed: state.uploadReport,
                icon: const Icon(Icons.cloud_upload_outlined, color: _gold),
              ),
              IconButton(
                tooltip: 'Copy report',
                onPressed: state.copyReport,
                icon: const Icon(Icons.copy_all_outlined, color: _gold),
              ),
            ],
          ),
          child: Column(
            children: state.findings.isEmpty
                ? const [_PassFinding()]
                : state.findings
                      .map((finding) => _FindingTile(finding: finding))
                      .toList(),
          ),
        ),
      ],
    );
  }
}

class _ComplianceDashboard extends StatelessWidget {
  const _ComplianceDashboard({required this.findings, required this.score});

  final List<ScanFinding> findings;
  final int score;

  @override
  Widget build(BuildContext context) {
    final pdpaFindings = findings
        .where((finding) => finding.category.contains('PDPA'))
        .length;
    final cryptoFindings = findings
        .where((finding) => finding.category.contains('Cryptography'))
        .length;
    final hardeningFindings = findings
        .where(
          (finding) =>
              finding.category.contains('Hardening') ||
              finding.category.contains('Binary Code') ||
              finding.category.contains('MAC Scheme'),
        )
        .length;
    final macLevel = _highestMacLevel(findings);
    final topCategory = _topCategory(findings);
    final complianceScore = (100 - score).clamp(0, 100);

    return _DarkPanel(
      title: 'Government Compliance Dashboard',
      action: const Icon(Icons.dashboard_customize_outlined, color: _gold),
      child: Column(
        children: [
          Row(
            children: [
              Expanded(
                child: _StatusBlock(
                  label: 'Compliance',
                  value: '$complianceScore%',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _StatusBlock(label: 'MAC Map', value: macLevel),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _StatusBlock(
                  label: 'PDPA Exposure',
                  value: pdpaFindings == 0 ? 'None' : '$pdpaFindings flags',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _StatusBlock(
                  label: 'Weak Crypto',
                  value: cryptoFindings == 0 ? 'None' : '$cryptoFindings flags',
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _StatusBlock(
                  label: 'Hardening',
                  value: hardeningFindings == 0
                      ? 'No flags'
                      : '$hardeningFindings flags',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _StatusBlock(label: 'Top Area', value: topCategory),
              ),
            ],
          ),
        ],
      ),
    );
  }

  static String _highestMacLevel(List<ScanFinding> findings) {
    if (findings.any((finding) => finding.macLevel == 'Level 3')) {
      return 'Level 3';
    }
    if (findings.any((finding) => finding.macLevel == 'Level 2')) {
      return 'Level 2';
    }
    return 'Level 1';
  }

  static String _topCategory(List<ScanFinding> findings) {
    if (findings.isEmpty) {
      return 'Clear';
    }
    final counts = <String, int>{};
    for (final finding in findings) {
      counts[finding.category] = (counts[finding.category] ?? 0) + 1;
    }
    final sorted = counts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    return sorted.first.key;
  }
}

class _ForensicSnapshot extends StatelessWidget {
  const _ForensicSnapshot({required this.artifact});

  final ApkArtifact? artifact;

  @override
  Widget build(BuildContext context) {
    if (artifact == null) {
      return const _DarkPanel(
        title: 'Government Forensic Snapshot',
        child: Text(
          'Import a government APK or scan an installed government app to generate hashes and evidence metadata.',
          style: TextStyle(color: _muted, height: 1.35),
        ),
      );
    }

    final evidence = artifact!;
    return _DarkPanel(
      title: 'Government Forensic Snapshot',
      action: const Icon(Icons.fingerprint_rounded, color: _gold),
      child: Column(
        children: [
          _EvidenceRow(label: 'Source', value: evidence.evidenceSource),
          _EvidenceRow(label: 'SHA-256', value: evidence.apkSha256),
          _EvidenceRow(
            label: 'APK size',
            value: _formatBytes(evidence.apkSizeBytes),
          ),
          _EvidenceRow(
            label: 'First install',
            value: evidence.firstInstallTime,
          ),
          _EvidenceRow(label: 'Last update', value: evidence.lastUpdateTime),
          _EvidenceRow(label: 'Installer', value: evidence.installerPackage),
          _EvidenceRow(label: 'Source path', value: evidence.sourcePath),
          _EvidenceRow(label: 'Split APKs', value: '${evidence.splitApkCount}'),
        ],
      ),
    );
  }

  static String _formatBytes(int bytes) {
    if (bytes <= 0) {
      return 'Unknown';
    }
    final mb = bytes / (1024 * 1024);
    return '${mb.toStringAsFixed(2)} MB';
  }
}

class _EvidenceRow extends StatelessWidget {
  const _EvidenceRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    if (value.isEmpty || value == '0') {
      return const SizedBox.shrink();
    }

    return Padding(
      padding: const EdgeInsets.only(bottom: 9),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 92,
            child: Text(
              label,
              style: const TextStyle(color: _muted, fontSize: 12),
            ),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(
                color: Color(0xFFF4EAD0),
                fontSize: 12,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ChecklistPage extends StatelessWidget {
  const _ChecklistPage({required this.state});

  final _ScannerScreenState state;

  static const controls = <String, String>{
    'obfuscation': 'Code obfuscation enabled',
    'pinning': 'Certificate pinning implemented',
    'secrets': 'Secrets removed from source and resources',
    'abuseControls': 'Root and emulator abuse controls reviewed',
    'encryptedStorage': 'Sensitive data encrypted at rest',
    'httpsOnly': 'Network calls restricted to HTTPS',
  };

  @override
  Widget build(BuildContext context) {
    return ListView(
      key: const ValueKey('checklist'),
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 22),
      children: [
        const _ShieldHero(size: 150),
        const SizedBox(height: 12),
        _DarkPanel(
          title: 'Government Protection Controls',
          action: Text(
            'Risk ${state.score}/100',
            style: const TextStyle(color: _gold, fontWeight: FontWeight.w900),
          ),
          child: Column(
            children: controls.entries.map((entry) {
              final checked = state.completedControls.contains(entry.key);
              return Container(
                margin: const EdgeInsets.only(bottom: 10),
                decoration: BoxDecoration(
                  color: checked ? const Color(0xFF2E2815) : _panelSoft,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: checked ? _goldDeep : _line),
                ),
                child: CheckboxListTile(
                  value: checked,
                  activeColor: _gold,
                  checkColor: Colors.black,
                  onChanged: (value) =>
                      state.updateControl(entry.key, value ?? false),
                  title: Text(
                    entry.value,
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  controlAffinity: ListTileControlAffinity.leading,
                ),
              );
            }).toList(),
          ),
        ),
        const SizedBox(height: 14),
        Row(
          children: [
            Expanded(
              child: _GoldButton(
                label: 'Copy Report',
                icon: Icons.description_outlined,
                onPressed: state.copyReport,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _GoldButton(
                label: 'Upload',
                icon: Icons.cloud_upload_outlined,
                onPressed: state.uploadReport,
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _InstalledAppsSheet extends StatelessWidget {
  const _InstalledAppsSheet({required this.apps});

  final List<dynamic> apps;

  @override
  Widget build(BuildContext context) {
    final mappedApps = apps
        .whereType<Map>()
        .map((app) => app.cast<String, Object?>())
        .toList();

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        child: Column(
          children: [
            const Text(
              'Choose Government App',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: mappedApps.isEmpty
                  ? const Center(
                      child: Text(
                        'No government apps were found on this phone.',
                        style: TextStyle(color: _muted),
                      ),
                    )
                  : ListView.separated(
                      itemCount: mappedApps.length,
                      separatorBuilder: (context, index) =>
                          const Divider(color: _line, height: 1),
                      itemBuilder: (context, index) {
                        final app = mappedApps[index];
                        final iconBytes = app['iconPng'] is Uint8List
                            ? app['iconPng'] as Uint8List
                            : null;
                        return ListTile(
                          leading: CircleAvatar(
                            backgroundColor: _panelSoft,
                            child: iconBytes == null
                                ? const Icon(Icons.apps_rounded, color: _gold)
                                : ClipOval(
                                    child: Image.memory(
                                      iconBytes,
                                      width: 34,
                                      height: 34,
                                      fit: BoxFit.cover,
                                      filterQuality: FilterQuality.high,
                                    ),
                                  ),
                          ),
                          title: Text(
                            '${app['label'] ?? 'Unknown app'}',
                            style: const TextStyle(fontWeight: FontWeight.w800),
                          ),
                          subtitle: Text(
                            '${app['packageName'] ?? ''}',
                            style: const TextStyle(color: _muted),
                          ),
                          trailing: const Icon(
                            Icons.chevron_right_rounded,
                            color: _gold,
                          ),
                          onTap: () => Navigator.of(context).pop(app),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ScanMeter extends StatelessWidget {
  const _ScanMeter({required this.score, required this.level});

  final int score;
  final String level;

  @override
  Widget build(BuildContext context) {
    return _DarkPanel(
      title: 'Scan Result',
      action: _RiskPill(level: level),
      child: Column(
        children: [
          SizedBox(
            height: 190,
            child: CustomPaint(
              painter: _MeterPainter(score),
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      '$score',
                      style: const TextStyle(
                        fontSize: 38,
                        color: _gold,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                    const Text('Risk Score', style: TextStyle(color: _muted)),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _StatusBlock(label: 'Risk Class', value: level),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _StatusBlock(label: 'Scan Status', value: level),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _RiskClassificationPanel extends StatelessWidget {
  const _RiskClassificationPanel();

  @override
  Widget build(BuildContext context) {
    return const _DarkPanel(
      title: 'Risk Classification',
      child: Row(
        children: [
          Expanded(
            child: _RiskRangeBlock(
              label: 'LOW',
              range: '0 - 25',
              color: Color(0xFF28B463),
            ),
          ),
          SizedBox(width: 8),
          Expanded(
            child: _RiskRangeBlock(
              label: 'MEDIUM',
              range: '26 - 50',
              color: _gold,
            ),
          ),
          SizedBox(width: 8),
          Expanded(
            child: _RiskRangeBlock(
              label: 'HIGH',
              range: '51 - 75',
              color: Color(0xFFFF7A1A),
            ),
          ),
          SizedBox(width: 8),
          Expanded(
            child: _RiskRangeBlock(
              label: 'CRITICAL',
              range: '76 - 100',
              color: Color(0xFFE22D3D),
            ),
          ),
        ],
      ),
    );
  }
}

class _RiskRangeBlock extends StatelessWidget {
  const _RiskRangeBlock({
    required this.label,
    required this.range,
    required this.color,
  });

  final String label;
  final String range;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(minHeight: 58),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.85)),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            label,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: color,
              fontSize: 11,
              fontWeight: FontWeight.w900,
            ),
          ),
          const SizedBox(height: 3),
          Text(
            range,
            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w800),
          ),
        ],
      ),
    );
  }
}

class _DarkPanel extends StatelessWidget {
  const _DarkPanel({required this.title, required this.child, this.action});

  final String title;
  final Widget child;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: _panel.withValues(alpha: 0.92),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: _line),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.32),
            blurRadius: 24,
            offset: const Offset(0, 12),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  title,
                  style: const TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
              ?action,
            ],
          ),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _GoldButton extends StatelessWidget {
  const _GoldButton({
    required this.label,
    required this.icon,
    required this.onPressed,
  });

  final String label;
  final IconData icon;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    return FilledButton.icon(
      onPressed: onPressed,
      icon: Icon(icon),
      label: Text(label),
      style: FilledButton.styleFrom(
        backgroundColor: _gold,
        foregroundColor: Colors.black,
        disabledBackgroundColor: _line,
        disabledForegroundColor: _muted,
        minimumSize: const Size.fromHeight(50),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(28),
          side: const BorderSide(color: Color(0xFFFFE07A), width: 1.2),
        ),
        textStyle: const TextStyle(fontWeight: FontWeight.w900),
      ),
    );
  }
}

class _ProfileField extends StatelessWidget {
  const _ProfileField({
    required this.label,
    required this.controller,
    this.keyboardType,
    this.onChanged,
  });

  final String label;
  final TextEditingController controller;
  final TextInputType? keyboardType;
  final ValueChanged<String>? onChanged;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: TextField(
        controller: controller,
        keyboardType: keyboardType,
        onChanged: onChanged,
        style: const TextStyle(
          color: Color(0xFFEAF3FF),
          fontWeight: FontWeight.w700,
        ),
        decoration: InputDecoration(
          labelText: label,
          labelStyle: const TextStyle(color: _muted),
          filled: true,
          fillColor: _panelSoft,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _line),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _line),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _gold),
          ),
        ),
      ),
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.label,
    required this.value,
    required this.icon,
  });

  final String label;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _panel,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: _line),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: _gold, size: 20),
          const SizedBox(height: 10),
          Text(
            value,
            style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w900),
          ),
          Text(label, style: const TextStyle(color: _muted, fontSize: 12)),
        ],
      ),
    );
  }
}

class _StatusBlock extends StatelessWidget {
  const _StatusBlock({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _panelSoft,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: _line),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(color: _muted, fontSize: 12)),
          const SizedBox(height: 4),
          Text(
            value,
            style: const TextStyle(color: _gold, fontWeight: FontWeight.w900),
          ),
        ],
      ),
    );
  }
}

class _FindingTile extends StatelessWidget {
  const _FindingTile({required this.finding});

  final ScanFinding finding;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _panelSoft,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: _line),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SeverityDot(severity: finding.severity),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  finding.title,
                  style: const TextStyle(fontWeight: FontWeight.w900),
                ),
                const SizedBox(height: 3),
                Text(
                  '${finding.category} | ${finding.macLevel}',
                  style: const TextStyle(
                    color: _gold,
                    fontSize: 11,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  finding.advice,
                  style: const TextStyle(
                    color: _muted,
                    height: 1.35,
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _PassFinding extends StatelessWidget {
  const _PassFinding();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: _panelSoft,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: _line),
      ),
      child: const Row(
        children: [
          Icon(Icons.verified_user_outlined, color: _gold),
          SizedBox(width: 12),
          Expanded(
            child: Text(
              'No risky manifest patterns found. Continue with dependency scanning, code review, and dynamic testing.',
              style: TextStyle(color: _muted),
            ),
          ),
        ],
      ),
    );
  }
}

class _SeverityDot extends StatelessWidget {
  const _SeverityDot({required this.severity});

  final Severity severity;

  @override
  Widget build(BuildContext context) {
    final color = switch (severity) {
      Severity.critical => const Color(0xFFFF4D4D),
      Severity.high => const Color(0xFFFF9E2C),
      Severity.medium => _gold,
      Severity.low => const Color(0xFF35D38B),
    };
    return Container(
      width: 42,
      height: 42,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color.withValues(alpha: 0.16),
      ),
      child: Icon(Icons.bolt_rounded, color: color, size: 22),
    );
  }
}

class _RiskPill extends StatelessWidget {
  const _RiskPill({required this.level});

  final String level;

  @override
  Widget build(BuildContext context) {
    final color = switch (level) {
      'Critical' => const Color(0xFFE22D3D),
      'High' => const Color(0xFFFF7A1A),
      'Medium' => _gold,
      _ => const Color(0xFF35D38B),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 7),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.6)),
      ),
      child: Text(
        level,
        style: TextStyle(
          color: color,
          fontSize: 12,
          fontWeight: FontWeight.w900,
        ),
      ),
    );
  }
}

class _BottomTabs extends StatelessWidget {
  const _BottomTabs({required this.currentIndex, required this.onChanged});

  final int currentIndex;
  final ValueChanged<int> onChanged;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: _navyDeep,
        border: Border(top: BorderSide(color: _line)),
      ),
      child: SafeArea(
        top: false,
        child: NavigationBar(
          selectedIndex: currentIndex,
          onDestinationSelected: onChanged,
          backgroundColor: Colors.transparent,
          indicatorColor: _blueGlow.withValues(alpha: 0.22),
          labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
          destinations: const [
            NavigationDestination(
              icon: Icon(Icons.shield_outlined),
              selectedIcon: Icon(Icons.shield),
              label: 'Home',
            ),
            NavigationDestination(
              icon: Icon(Icons.radar_outlined),
              selectedIcon: Icon(Icons.radar),
              label: 'Scan',
            ),
            NavigationDestination(
              icon: Icon(Icons.lock_outline),
              selectedIcon: Icon(Icons.lock),
              label: 'Controls',
            ),
            NavigationDestination(
              icon: Icon(Icons.history_outlined),
              selectedIcon: Icon(Icons.history),
              label: 'History',
            ),
          ],
        ),
      ),
    );
  }
}

class _ShieldHero extends StatelessWidget {
  const _ShieldHero({required this.size});

  final double size;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: DecoratedBox(
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          boxShadow: [
            BoxShadow(
              color: _blueGlow.withValues(alpha: 0.24),
              blurRadius: 32,
              spreadRadius: 4,
            ),
          ],
        ),
        child: Image.asset(
          'assets/branding/secure_logo.png',
          fit: BoxFit.contain,
          filterQuality: FilterQuality.high,
        ),
      ),
    );
  }
}

class _MeterPainter extends CustomPainter {
  const _MeterPainter(this.score);

  final int score;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height * 0.76);
    final radius = size.width * 0.35;
    const segments = 28;
    final lit = (segments * (score / 100)).round();

    for (var i = 0; i < segments; i++) {
      final angle = math.pi + (math.pi * i / (segments - 1));
      final paint = Paint()
        ..color = i < lit ? _gold : const Color(0xFF274472)
        ..strokeWidth = 8
        ..strokeCap = StrokeCap.round;
      final inner = Offset(
        center.dx + math.cos(angle) * (radius - 22),
        center.dy + math.sin(angle) * (radius - 22),
      );
      final outer = Offset(
        center.dx + math.cos(angle) * radius,
        center.dy + math.sin(angle) * radius,
      );
      canvas.drawLine(inner, outer, paint);
    }
  }

  @override
  bool shouldRepaint(covariant _MeterPainter oldDelegate) =>
      oldDelegate.score != score;
}

class _CircuitPainter extends CustomPainter {
  const _CircuitPainter({required this.progress});

  final double progress;

  @override
  void paint(Canvas canvas, Size size) {
    final linePaint = Paint()
      ..color = _blueGlow.withValues(alpha: 0.16)
      ..strokeWidth = 1;
    final pulsePaint = Paint()
      ..color = _gold.withValues(alpha: 0.18)
      ..strokeWidth = 2
      ..strokeCap = StrokeCap.round;
    final glowPaint = Paint()
      ..shader =
          RadialGradient(
            colors: [_blueGlow.withValues(alpha: 0.16), Colors.transparent],
          ).createShader(
            Rect.fromCircle(
              center: Offset(size.width * (0.25 + progress * 0.5), 120),
              radius: size.width * 0.45,
            ),
          );

    canvas.drawCircle(
      Offset(size.width * (0.25 + progress * 0.5), 120),
      size.width * 0.45,
      glowPaint,
    );

    for (var i = 0; i < 9; i++) {
      final y = 48.0 + (i * 78) + (progress * 42);
      final wrappedY = y % (size.height + 120);
      canvas.drawLine(
        Offset(-20, wrappedY),
        Offset(size.width * 0.34, wrappedY + 38),
        linePaint,
      );
      canvas.drawLine(
        Offset(size.width + 20, wrappedY + 24),
        Offset(size.width * 0.66, wrappedY + 66),
        linePaint,
      );

      if (i.isEven) {
        final pulseX = size.width * ((progress + i * 0.17) % 1);
        canvas.drawLine(
          Offset(pulseX - 30, wrappedY + 12),
          Offset(pulseX + 30, wrappedY + 20),
          pulsePaint,
        );
      }
    }
  }

  @override
  bool shouldRepaint(covariant _CircuitPainter oldDelegate) =>
      oldDelegate.progress != progress;
}

const sampleManifest =
    '''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
  <application
    android:allowBackup="true"
    android:debuggable="true"
    android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true" />
    <provider android:name=".FileProvider" android:exported="true" />
  </application>
</manifest>''';
