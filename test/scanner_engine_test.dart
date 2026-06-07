import 'package:flutter_test/flutter_test.dart';
import 'package:droidshield_scan/scanner_engine.dart';

void main() {
  test('scanner detects risky Android manifest settings', () {
    const profile = ScanProfile(
      appName: 'Risky',
      packageName: 'com.example.risky',
      version: '1.0.0',
      targetSdk: 28,
      manifest: '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
  <application android:allowBackup="true" android:debuggable="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true" />
    <provider android:name=".FileProvider" android:exported="true" />
  </application>
</manifest>
''',
    );

    final findings = ScannerEngine.scan(profile);
    expect(
      findings.map((finding) => finding.id),
      containsAll(<String>[
        'debuggable',
        'backup',
        'cleartext',
        'exported-activity',
        'exported-provider',
        'external-storage',
        'old-target-sdk',
      ]),
    );
    expect(
      ScannerEngine.riskLevel(
        ScannerEngine.riskScore(findings, const <String>{}),
      ),
      'Critical',
    );
  });

  test('completed controls lower but never invert the risk score', () {
    const finding = ScanFinding(
      id: 'debuggable',
      severity: Severity.critical,
      score: 22,
      title: 'Debuggable build is enabled',
      advice: 'Disable debuggable builds.',
    );

    final score = ScannerEngine.riskScore(
      const <ScanFinding>[finding],
      const <String>{'obfuscation', 'pinning', 'secrets', 'abuseControls'},
    );

    expect(score, 0);
  });
}
