import 'package:flutter/material.dart';

import '../services/backend_api.dart';

const _gold = Color(0xFFF5B323);
const _panel = Color(0xFF0D2355);
const _panelSoft = Color(0xFF14316F);
const _line = Color(0xFF31558E);
const _muted = Color(0xFFB7C7E7);

class ReportHistoryScreen extends StatefulWidget {
  const ReportHistoryScreen({required this.session, super.key});

  final AuthSession session;

  @override
  State<ReportHistoryScreen> createState() => _ReportHistoryScreenState();
}

class _ReportHistoryScreenState extends State<ReportHistoryScreen> {
  late Future<List<ReportSummary>> reportsFuture = _loadReports();

  Future<List<ReportSummary>> _loadReports() {
    return BackendApi(
      widget.session.baseUrl,
    ).listReports(token: widget.session.accessToken);
  }

  Future<void> refresh() async {
    setState(() {
      reportsFuture = _loadReports();
    });
    await reportsFuture;
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: refresh,
      color: _gold,
      child: FutureBuilder<List<ReportSummary>>(
        future: reportsFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator(color: _gold));
          }

          if (snapshot.hasError) {
            return ListView(
              padding: const EdgeInsets.all(18),
              children: [
                _HistoryPanel(
                  child: Column(
                    children: [
                      const Icon(
                        Icons.cloud_off_outlined,
                        color: _gold,
                        size: 42,
                      ),
                      const SizedBox(height: 12),
                      const Text(
                        'Could not load report history',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w900,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        '${snapshot.error}',
                        textAlign: TextAlign.center,
                        style: const TextStyle(color: _muted),
                      ),
                      const SizedBox(height: 12),
                      FilledButton.icon(
                        onPressed: refresh,
                        icon: const Icon(Icons.refresh),
                        label: const Text('Retry'),
                      ),
                    ],
                  ),
                ),
              ],
            );
          }

          final reports = snapshot.data ?? const <ReportSummary>[];
          if (reports.isEmpty) {
            return ListView(
              padding: const EdgeInsets.all(18),
              children: const [
                _HistoryPanel(
                  child: Column(
                    children: [
                      Icon(Icons.history_rounded, color: _gold, size: 44),
                      SizedBox(height: 12),
                      Text(
                        'No reports saved yet',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w900,
                        ),
                      ),
                      SizedBox(height: 8),
                      Text(
                        'Scan an app, tap Upload, then saved reports will appear here.',
                        textAlign: TextAlign.center,
                        style: TextStyle(color: _muted),
                      ),
                    ],
                  ),
                ),
              ],
            );
          }

          return ListView.separated(
            padding: const EdgeInsets.fromLTRB(18, 16, 18, 22),
            itemCount: reports.length + 1,
            separatorBuilder: (context, index) => const SizedBox(height: 12),
            itemBuilder: (context, index) {
              if (index == 0) {
                return _HistoryHeader(
                  count: reports.length,
                  userRole: widget.session.user.role,
                  onRefresh: refresh,
                );
              }
              return _ReportTile(
                report: reports[index - 1],
                session: widget.session,
                onChanged: refresh,
              );
            },
          );
        },
      ),
    );
  }
}

class _HistoryHeader extends StatelessWidget {
  const _HistoryHeader({
    required this.count,
    required this.userRole,
    required this.onRefresh,
  });

  final int count;
  final String userRole;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    return _HistoryPanel(
      child: Row(
        children: [
          const Icon(Icons.folder_copy_outlined, color: _gold, size: 36),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Report History',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.w900),
                ),
                Text(
                  '$count saved reports • $userRole access',
                  style: const TextStyle(color: _muted),
                ),
              ],
            ),
          ),
          IconButton(
            tooltip: 'Refresh',
            onPressed: onRefresh,
            icon: const Icon(Icons.refresh, color: _gold),
          ),
        ],
      ),
    );
  }
}

class _ReportTile extends StatelessWidget {
  const _ReportTile({
    required this.report,
    required this.session,
    required this.onChanged,
  });

  final ReportSummary report;
  final AuthSession session;
  final VoidCallback onChanged;

  @override
  Widget build(BuildContext context) {
    return _HistoryPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  report.appName,
                  style: const TextStyle(
                    fontSize: 17,
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
              _RiskBadge(level: report.riskLevel, score: report.riskScore),
            ],
          ),
          const SizedBox(height: 5),
          Text(report.packageName, style: const TextStyle(color: _muted)),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _MetaChip(icon: Icons.tag, label: '#${report.id}'),
              _MetaChip(
                icon: Icons.warning_amber_rounded,
                label: '${report.findingCount} findings',
              ),
              if (report.examinerName?.isNotEmpty ?? false)
                _MetaChip(
                  icon: Icons.person_outline,
                  label: report.examinerName!,
                ),
              if (report.version?.isNotEmpty ?? false)
                _MetaChip(
                  icon: Icons.android_outlined,
                  label: 'v${report.version}',
                ),
            ],
          ),
          if (report.apkSha256?.isNotEmpty ?? false) ...[
            const SizedBox(height: 10),
            SelectableText(
              'SHA-256: ${report.apkSha256}',
              style: const TextStyle(color: _muted, fontSize: 12),
            ),
          ],
          const SizedBox(height: 8),
          Text(
            report.createdAt,
            style: const TextStyle(color: _muted, fontSize: 12),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _showReportDetail(context),
                  icon: const Icon(Icons.visibility_outlined),
                  label: const Text('View'),
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                tooltip: 'Edit report',
                onPressed: () => _editReport(context),
                icon: const Icon(Icons.edit_note_rounded, color: _gold),
              ),
              IconButton(
                tooltip: 'Delete report',
                onPressed: () => _deleteReport(context),
                icon: const Icon(
                  Icons.delete_outline_rounded,
                  color: Color(0xFFE22D3D),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _showReportDetail(BuildContext context) async {
    try {
      final detail = await BackendApi(
        session.baseUrl,
      ).getReport(token: session.accessToken, reportId: report.id);
      if (!context.mounted) return;
      await showModalBottomSheet<void>(
        context: context,
        backgroundColor: _panel,
        showDragHandle: true,
        isScrollControlled: true,
        builder: (context) => _ReportDetailSheet(detail: detail),
      );
    } catch (error) {
      if (context.mounted) _toast(context, '$error');
    }
  }

  Future<void> _editReport(BuildContext context) async {
    ReportDetail detail;
    try {
      detail = await BackendApi(
        session.baseUrl,
      ).getReport(token: session.accessToken, reportId: report.id);
    } catch (error) {
      if (context.mounted) _toast(context, '$error');
      return;
    }
    if (!context.mounted) return;

    final caseController = TextEditingController(
      text: detail.caseReference ?? '',
    );
    final notesController = TextEditingController(text: detail.notes ?? '');
    final saved = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: _panel,
        title: const Text('Edit Report'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: caseController,
              decoration: const InputDecoration(labelText: 'Case reference'),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: notesController,
              minLines: 3,
              maxLines: 5,
              decoration: const InputDecoration(labelText: 'Notes'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (saved != true || !context.mounted) return;

    try {
      await BackendApi(session.baseUrl).updateReport(
        token: session.accessToken,
        reportId: report.id,
        caseReference: caseController.text.trim().isEmpty
            ? null
            : caseController.text.trim(),
        notes: notesController.text.trim().isEmpty
            ? null
            : notesController.text.trim(),
        examinerName: session.user.name,
      );
      onChanged();
      if (context.mounted) _toast(context, 'Report updated');
    } catch (error) {
      if (context.mounted) _toast(context, '$error');
    }
  }

  Future<void> _deleteReport(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: _panel,
        title: const Text('Delete Report?'),
        content: Text('Delete report #${report.id} for ${report.appName}?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      await BackendApi(
        session.baseUrl,
      ).deleteReport(token: session.accessToken, reportId: report.id);
      onChanged();
      if (context.mounted) _toast(context, 'Report deleted');
    } catch (error) {
      if (context.mounted) _toast(context, '$error');
    }
  }

  void _toast(BuildContext context, String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: _panelSoft),
    );
  }
}

class _ReportDetailSheet extends StatelessWidget {
  const _ReportDetailSheet({required this.detail});

  final ReportDetail detail;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.fromLTRB(18, 8, 18, 24),
        children: [
          Text(
            detail.appName,
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w900),
          ),
          const SizedBox(height: 4),
          Text(detail.packageName, style: const TextStyle(color: _muted)),
          const SizedBox(height: 14),
          _DetailRow(
            label: 'Risk',
            value: '${detail.riskLevel} ${detail.riskScore}/100',
          ),
          _DetailRow(label: 'Version', value: detail.version ?? ''),
          _DetailRow(label: 'Target SDK', value: '${detail.targetSdk ?? ''}'),
          _DetailRow(label: 'Case', value: detail.caseReference ?? ''),
          _DetailRow(label: 'Notes', value: detail.notes ?? ''),
          _DetailRow(label: 'SHA-256', value: detail.apkSha256 ?? ''),
          const SizedBox(height: 14),
          const Text('Findings', style: TextStyle(fontWeight: FontWeight.w900)),
          const SizedBox(height: 8),
          ...detail.findings.map(
            (finding) => _HistoryPanel(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${finding['title'] ?? 'Finding'}',
                    style: const TextStyle(fontWeight: FontWeight.w900),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${finding['category'] ?? ''}',
                    style: const TextStyle(color: _gold, fontSize: 12),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${finding['advice'] ?? ''}',
                    style: const TextStyle(color: _muted, height: 1.35),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  const _DetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    if (value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 88,
            child: Text(label, style: const TextStyle(color: _muted)),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(fontWeight: FontWeight.w700),
            ),
          ),
        ],
      ),
    );
  }
}

class _HistoryPanel extends StatelessWidget {
  const _HistoryPanel({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: _panel.withValues(alpha: 0.92),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: _line),
      ),
      child: child,
    );
  }
}

class _RiskBadge extends StatelessWidget {
  const _RiskBadge({required this.level, required this.score});

  final String level;
  final int score;

  @override
  Widget build(BuildContext context) {
    final color = switch (level) {
      'Critical' => const Color(0xFFE22D3D),
      'High' => const Color(0xFFFF7A1A),
      'Medium' => _gold,
      _ => const Color(0xFF35D38B),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.65)),
      ),
      child: Text(
        '$level $score',
        style: TextStyle(color: color, fontWeight: FontWeight.w900),
      ),
    );
  }
}

class _MetaChip extends StatelessWidget {
  const _MetaChip({required this.icon, required this.label});

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 6),
      decoration: BoxDecoration(
        color: _panelSoft,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: _line),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: _gold, size: 14),
          const SizedBox(width: 5),
          Text(label, style: const TextStyle(fontSize: 12)),
        ],
      ),
    );
  }
}
