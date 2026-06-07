import 'dart:convert';
import 'dart:async';

import 'package:http/http.dart' as http;

class AuthSession {
  const AuthSession({
    required this.baseUrl,
    required this.accessToken,
    required this.user,
  });

  final String baseUrl;
  final String accessToken;
  final BackendUser user;

  Map<String, Object> toJson() => {
    'baseUrl': baseUrl,
    'accessToken': accessToken,
    'user': user.toJson(),
  };

  factory AuthSession.fromJson(Map<String, dynamic> json) {
    return AuthSession(
      baseUrl: '${json['baseUrl']}',
      accessToken: '${json['accessToken']}',
      user: BackendUser.fromJson(
        Map<String, dynamic>.from(json['user'] as Map),
      ),
    );
  }
}

class BackendUser {
  const BackendUser({
    required this.id,
    required this.name,
    required this.email,
    required this.role,
  });

  final int id;
  final String name;
  final String email;
  final String role;

  Map<String, Object> toJson() => {
    'id': id,
    'name': name,
    'email': email,
    'role': role,
  };

  factory BackendUser.fromJson(Map<String, dynamic> json) {
    return BackendUser(
      id: json['id'] as int,
      name: '${json['name']}',
      email: '${json['email']}',
      role: '${json['role']}',
    );
  }
}

class ReportSummary {
  const ReportSummary({
    required this.id,
    required this.appName,
    required this.packageName,
    required this.riskScore,
    required this.riskLevel,
    required this.findingCount,
    required this.createdAt,
    this.version,
    this.apkSha256,
    this.examinerName,
  });

  final int id;
  final String appName;
  final String packageName;
  final String? version;
  final int riskScore;
  final String riskLevel;
  final String? apkSha256;
  final int findingCount;
  final String? examinerName;
  final String createdAt;

  factory ReportSummary.fromJson(Map<String, dynamic> json) {
    return ReportSummary(
      id: json['id'] as int,
      appName: '${json['appName']}',
      packageName: '${json['packageName']}',
      version: json['version'] as String?,
      riskScore: json['riskScore'] as int,
      riskLevel: '${json['riskLevel']}',
      apkSha256: json['apkSha256'] as String?,
      findingCount: json['findingCount'] as int,
      examinerName: json['examinerName'] as String?,
      createdAt: '${json['createdAt']}',
    );
  }
}

class ReportDetail extends ReportSummary {
  const ReportDetail({
    required super.id,
    required super.appName,
    required super.packageName,
    required super.riskScore,
    required super.riskLevel,
    required super.findingCount,
    required super.createdAt,
    super.version,
    super.apkSha256,
    super.examinerName,
    this.targetSdk,
    this.findings = const <Map<String, dynamic>>[],
    this.generatedAt,
    this.caseReference,
    this.notes,
  });

  final int? targetSdk;
  final List<Map<String, dynamic>> findings;
  final String? generatedAt;
  final String? caseReference;
  final String? notes;

  factory ReportDetail.fromJson(Map<String, dynamic> json) {
    return ReportDetail(
      id: json['id'] as int,
      appName: '${json['appName']}',
      packageName: '${json['packageName']}',
      version: json['version'] as String?,
      riskScore: json['riskScore'] as int,
      riskLevel: '${json['riskLevel']}',
      apkSha256: json['apkSha256'] as String?,
      findingCount: json['findingCount'] as int,
      examinerName: json['examinerName'] as String?,
      createdAt: '${json['createdAt']}',
      targetSdk: json['targetSdk'] as int?,
      findings: (json['findings'] as List<dynamic>? ?? const [])
          .whereType<Map>()
          .map((item) => Map<String, dynamic>.from(item))
          .toList(),
      generatedAt: json['generatedAt'] as String?,
      caseReference: json['caseReference'] as String?,
      notes: json['notes'] as String?,
    );
  }
}

class BackendApi {
  BackendApi(this.baseUrl);

  static const _timeout = Duration(seconds: 10);

  final String baseUrl;

  Uri _uri(String path) =>
      Uri.parse('${baseUrl.replaceAll(RegExp(r'/+$'), '')}$path');

  Future<AuthSession> register({
    required String name,
    required String email,
    required String password,
  }) async {
    final response = await _send(
      () => http.post(
        _uri('/auth/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'name': name, 'email': email, 'password': password}),
      ),
    );
    return _authSession(response);
  }

  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    final response = await _send(
      () => http.post(
        _uri('/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'email': email, 'password': password}),
      ),
    );
    return _authSession(response);
  }

  Future<void> logout(String token) async {
    await _send(
      () => http.post(_uri('/auth/logout'), headers: _authHeaders(token)),
    );
  }

  Future<BackendUser> me(String token) async {
    final response = await _send(
      () => http.get(_uri('/auth/me'), headers: _authHeaders(token)),
    );
    return BackendUser.fromJson(_json(response));
  }

  Future<int> createReport({
    required String token,
    required Map<String, Object?> report,
  }) async {
    final response = await _send(
      () => http.post(
        _uri('/reports'),
        headers: _authHeaders(token),
        body: jsonEncode(report),
      ),
    );
    final json = _json(response);
    return json['id'] as int;
  }

  Future<List<ReportSummary>> listReports({required String token}) async {
    final response = await _send(
      () => http.get(_uri('/reports'), headers: _authHeaders(token)),
    );
    final json = _jsonList(response);
    return json
        .map((item) => ReportSummary.fromJson(Map<String, dynamic>.from(item)))
        .toList();
  }

  Future<ReportDetail> getReport({
    required String token,
    required int reportId,
  }) async {
    final response = await _send(
      () => http.get(_uri('/reports/$reportId'), headers: _authHeaders(token)),
    );
    return ReportDetail.fromJson(_json(response));
  }

  Future<ReportDetail> updateReport({
    required String token,
    required int reportId,
    String? caseReference,
    String? notes,
    String? examinerName,
  }) async {
    final response = await _send(
      () => http.patch(
        _uri('/reports/$reportId'),
        headers: _authHeaders(token),
        body: jsonEncode({
          'caseReference': caseReference,
          'notes': notes,
          'examinerName': examinerName,
        }),
      ),
    );
    return ReportDetail.fromJson(_json(response));
  }

  Future<void> deleteReport({
    required String token,
    required int reportId,
  }) async {
    await _send(
      () =>
          http.delete(_uri('/reports/$reportId'), headers: _authHeaders(token)),
    );
  }

  Map<String, String> _authHeaders(String token) => {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer $token',
  };

  Future<http.Response> _send(Future<http.Response> Function() request) async {
    try {
      return await request().timeout(_timeout);
    } on TimeoutException {
      throw const BackendApiException(
        'Backend connection timed out. Check the backend URL and Wi-Fi connection.',
      );
    } catch (error) {
      throw BackendApiException(
        'Cannot reach backend. Use your computer IP address, not localhost, on a real phone. Details: $error',
      );
    }
  }

  AuthSession _authSession(http.Response response) {
    final json = _json(response);
    return AuthSession(
      baseUrl: baseUrl,
      accessToken: '${json['accessToken']}',
      user: BackendUser.fromJson(
        Map<String, dynamic>.from(json['user'] as Map),
      ),
    );
  }

  Map<String, dynamic> _json(http.Response response) {
    final body = _jsonMap(response.body);
    if (response.statusCode >= 400) {
      throw BackendApiException('${body['detail'] ?? 'Request failed'}');
    }
    return body;
  }

  List<dynamic> _jsonList(http.Response response) {
    if (response.statusCode >= 400) {
      final body = _jsonMap(response.body);
      throw BackendApiException('${body['detail'] ?? 'Request failed'}');
    }
    return response.body.isEmpty
        ? <dynamic>[]
        : jsonDecode(response.body) as List<dynamic>;
  }

  Map<String, dynamic> _jsonMap(String responseBody) {
    if (responseBody.isEmpty) {
      return <String, dynamic>{};
    }
    try {
      return jsonDecode(responseBody) as Map<String, dynamic>;
    } on FormatException {
      return <String, dynamic>{'detail': responseBody};
    }
  }
}

class BackendApiException implements Exception {
  const BackendApiException(this.message);

  final String message;

  @override
  String toString() => message;
}
