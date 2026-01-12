import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:rcspy/src/services/supabase_service.dart';
import 'package:share_plus/share_plus.dart';

enum SupabaseViewMode { list, table, json }

class SupabaseResultsPage extends StatefulWidget {
  const SupabaseResultsPage({
    super.key,
    required this.appName,
    required this.result,
  });

  final String appName;
  final SupabaseSecurityResult result;

  @override
  State<SupabaseResultsPage> createState() => _SupabaseResultsPageState();
}

class _SupabaseResultsPageState extends State<SupabaseResultsPage> {
  SupabaseViewMode _viewMode = SupabaseViewMode.list;

  int get _totalIssues =>
      widget.result.publicBuckets.length +
      widget.result.exposedTables.length +
      widget.result.exposedStorageObjects.length;

  List<_FindingItem> get _findings {
    final items = <_FindingItem>[];

    // Add project URL as first item
    if (widget.result.workingProjectUrl != null) {
      items.add(_FindingItem(
        type: _FindingType.info,
        title: 'Project URL',
        value: widget.result.workingProjectUrl!,
        icon: Icons.link,
        color: Colors.teal,
      ));
    }

    // Add API key
    if (widget.result.workingAnonKey != null) {
      items.add(_FindingItem(
        type: _FindingType.info,
        title: 'Anon Key',
        value: widget.result.workingAnonKey!,
        icon: Icons.key,
        color: Colors.indigo,
      ));
    }

    // Add exposed tables
    for (final table in widget.result.exposedTables) {
      items.add(_FindingItem(
        type: _FindingType.table,
        title: table.tableName,
        value: table.sampleData.isNotEmpty
            ? const JsonEncoder.withIndent('  ').convert(table.sampleData)
            : 'Columns: ${table.columns.join(', ')}',
        icon: Icons.table_chart,
        color: Colors.purple,
        metadata: {
          'columns': table.columns,
          'rowCount': table.rowCount,
          'sampleData': table.sampleData,
        },
      ));
    }

    // Add public buckets
    for (final bucket in widget.result.publicBuckets) {
      items.add(_FindingItem(
        type: _FindingType.bucket,
        title: bucket.name,
        value: bucket.isPublic ? 'Public Access Enabled' : 'Private',
        icon: Icons.folder_open,
        color: Colors.orange,
        metadata: {
          'id': bucket.id,
          'isPublic': bucket.isPublic,
          'exposedFiles': bucket.exposedFiles,
        },
      ));
    }

    // Add exposed storage objects
    for (final object in widget.result.exposedStorageObjects) {
      items.add(_FindingItem(
        type: _FindingType.file,
        title: object.split('/').last,
        value: object,
        icon: Icons.insert_drive_file,
        color: Colors.blue,
      ));
    }

    return items;
  }

  Map<String, dynamic> get _jsonData => {
        'projectUrl': widget.result.workingProjectUrl,
        'anonKey': widget.result.workingAnonKey,
        'isVulnerable': widget.result.isVulnerable,
        'summary': {
          'publicBuckets': widget.result.publicBuckets.length,
          'exposedTables': widget.result.exposedTables.length,
          'exposedStorageObjects': widget.result.exposedStorageObjects.length,
        },
        'publicBuckets':
            widget.result.publicBuckets.map((b) => b.toMap()).toList(),
        'exposedTables':
            widget.result.exposedTables.map((t) => t.toMap()).toList(),
        'exposedStorageObjects': widget.result.exposedStorageObjects,
      };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.appName,
              style: const TextStyle(fontSize: 16),
            ),
            Text(
              '$_totalIssues security issues found',
              style: TextStyle(
                fontSize: 12,
                color: _totalIssues > 0 ? Colors.red[400] : Colors.green[400],
                fontWeight: FontWeight.normal,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.share),
            tooltip: 'Share for analysis',
            onPressed: () => _shareForAnalysis(context),
          ),
          IconButton(
            icon: const Icon(Icons.copy_all),
            tooltip: 'Copy all as JSON',
            onPressed: () => _copyAllAsJson(context),
          ),
        ],
      ),
      body: _totalIssues == 0
          ? const _EmptyState()
          : Column(
              children: [
                _ViewModeSwitcher(
                  currentMode: _viewMode,
                  onModeChanged: (mode) => setState(() => _viewMode = mode),
                ),
                Expanded(child: _buildContent()),
              ],
            ),
    );
  }

  Widget _buildContent() {
    switch (_viewMode) {
      case SupabaseViewMode.list:
        return _ListView(findings: _findings);
      case SupabaseViewMode.table:
        return _TableView(findings: _findings);
      case SupabaseViewMode.json:
        return _JsonView(jsonData: _jsonData);
    }
  }

  void _copyAllAsJson(BuildContext context) {
    final jsonString = const JsonEncoder.withIndent('  ').convert(_jsonData);
    Clipboard.setData(ClipboardData(text: jsonString));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Copied all results to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  void _shareForAnalysis(BuildContext context) {
    final bucketNames =
        widget.result.publicBuckets.map((b) => b.name).join(', ');
    final tableNames =
        widget.result.exposedTables.map((t) => t.tableName).join(', ');

    final jsonString = const JsonEncoder.withIndent('  ').convert(_jsonData);

    final shareText = '''
Supabase Security Analysis Report
==================================
App: ${widget.appName}
Project URL: ${widget.result.workingProjectUrl ?? 'Unknown'}
Anon Key: ${widget.result.workingAnonKey ?? 'Unknown'}

**Security Issues Found:**
- Public Storage Buckets: ${widget.result.publicBuckets.length}${bucketNames.isNotEmpty ? ' ($bucketNames)' : ''}
- Exposed Database Tables: ${widget.result.exposedTables.length}${tableNames.isNotEmpty ? ' ($tableNames)' : ''}
- Exposed Storage Files: ${widget.result.exposedStorageObjects.length}

**Full Details:**
$jsonString

**Analysis Request:**
Please analyze these Supabase security findings and identify:
1. What sensitive data might be exposed through these misconfigurations
2. Potential attack vectors using the exposed endpoints
3. Security risks from public storage buckets and database tables
4. Row Level Security (RLS) recommendations
5. Steps the developer should take to secure this backend

---
Generated by RC Spy - Security Research Tool
''';

    Share.share(shareText, subject: 'RC Spy: ${widget.appName} Supabase Analysis');
  }
}

enum _FindingType { info, table, bucket, file }

class _FindingItem {
  final _FindingType type;
  final String title;
  final String value;
  final IconData icon;
  final Color color;
  final Map<String, dynamic>? metadata;

  _FindingItem({
    required this.type,
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
    this.metadata,
  });

  String get typeLabel {
    switch (type) {
      case _FindingType.info:
        return 'INFO';
      case _FindingType.table:
        return 'TABLE';
      case _FindingType.bucket:
        return 'BUCKET';
      case _FindingType.file:
        return 'FILE';
    }
  }
}

class _ViewModeSwitcher extends StatelessWidget {
  const _ViewModeSwitcher({
    required this.currentMode,
    required this.onModeChanged,
  });

  final SupabaseViewMode currentMode;
  final ValueChanged<SupabaseViewMode> onModeChanged;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      child: SegmentedButton<SupabaseViewMode>(
        segments: const [
          ButtonSegment(
            value: SupabaseViewMode.list,
            icon: Icon(Icons.view_list, size: 18),
            label: Text('List'),
          ),
          ButtonSegment(
            value: SupabaseViewMode.table,
            icon: Icon(Icons.table_chart, size: 18),
            label: Text('Table'),
          ),
          ButtonSegment(
            value: SupabaseViewMode.json,
            icon: Icon(Icons.data_object, size: 18),
            label: Text('JSON'),
          ),
        ],
        selected: {currentMode},
        onSelectionChanged: (selected) => onModeChanged(selected.first),
        showSelectedIcon: false,
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.check_circle, size: 64, color: Colors.green),
          SizedBox(height: 16),
          Text(
            'No vulnerabilities detected\nin Supabase configuration',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 16, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}

class _ListView extends StatelessWidget {
  const _ListView({required this.findings});

  final List<_FindingItem> findings;

  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
      itemCount: findings.length,
      itemBuilder: (context, index) {
        final finding = findings[index];
        return _FindingCard(finding: finding);
      },
    );
  }
}

class _TableView extends StatelessWidget {
  const _TableView({required this.findings});

  final List<_FindingItem> findings;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Card(
          elevation: 0,
          clipBehavior: Clip.antiAlias,
          child: Table(
            defaultColumnWidth: const IntrinsicColumnWidth(),
            columnWidths: const {
              0: FixedColumnWidth(80),
              1: FixedColumnWidth(150),
              2: FixedColumnWidth(400),
            },
            border: TableBorder(
              horizontalInside: BorderSide(color: Colors.grey.shade200),
            ),
            children: [
              TableRow(
                decoration: BoxDecoration(color: Colors.grey.shade100),
                children: const [
                  _TableHeader('Type'),
                  _TableHeader('Name'),
                  _TableHeader('Details'),
                ],
              ),
              ...findings.map((finding) => _buildTableRow(context, finding)),
            ],
          ),
        ),
      ),
    );
  }

  TableRow _buildTableRow(BuildContext context, _FindingItem finding) {
    final isLong = finding.value.length > 50 || finding.value.contains('\n');

    return TableRow(
      children: [
        _TableCell(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: finding.color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              finding.typeLabel,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: finding.color,
              ),
            ),
          ),
        ),
        _TableCell(
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(finding.icon, size: 16, color: finding.color),
              const SizedBox(width: 8),
              Text(
                finding.title,
                style: TextStyle(
                  fontWeight: FontWeight.w500,
                  fontSize: 13,
                  color: finding.color,
                ),
              ),
            ],
          ),
          onTap: () => _copyToClipboard(context, finding.title, 'Name'),
        ),
        _TableCell(
          child: Text(
            isLong
                ? '${finding.value.substring(0, 50.clamp(0, finding.value.length))}...'
                : finding.value,
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 12,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          onTap: () => _showValueDialog(context, finding),
        ),
      ],
    );
  }

  void _copyToClipboard(BuildContext context, String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copied to clipboard'),
        duration: const Duration(seconds: 1),
      ),
    );
  }

  void _showValueDialog(BuildContext context, _FindingItem finding) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        minChildSize: 0.3,
        maxChildSize: 0.95,
        expand: false,
        builder: (context, scrollController) => Container(
          decoration: const BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              Center(
                child: Container(
                  margin: const EdgeInsets.only(top: 12),
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Colors.grey[300],
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              Container(
                margin: const EdgeInsets.all(16),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: finding.color.withOpacity(0.05),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: finding.color.withOpacity(0.1)),
                ),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: finding.color.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(
                        finding.icon,
                        size: 20,
                        color: finding.color,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            finding.title,
                            style: TextStyle(
                              fontWeight: FontWeight.w600,
                              fontSize: 16,
                              color: Colors.grey.shade800,
                            ),
                          ),
                          Text(
                            finding.typeLabel,
                            style: TextStyle(
                              fontSize: 12,
                              color: finding.color,
                            ),
                          ),
                        ],
                      ),
                    ),
                    Material(
                      color: finding.color.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      child: InkWell(
                        onTap: () {
                          Clipboard.setData(ClipboardData(text: finding.value));
                          Navigator.pop(context);
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Copied to clipboard'),
                              duration: Duration(seconds: 1),
                            ),
                          );
                        },
                        borderRadius: BorderRadius.circular(8),
                        child: Padding(
                          padding: const EdgeInsets.all(8),
                          child: Icon(
                            Icons.copy_rounded,
                            size: 20,
                            color: finding.color,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: SingleChildScrollView(
                  controller: scrollController,
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                  child: Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF8F9FA),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.grey.shade200),
                    ),
                    child: SelectableText(
                      finding.value,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                        color: Colors.grey.shade800,
                        height: 1.5,
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _TableHeader extends StatelessWidget {
  const _TableHeader(this.text);
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Text(
        text,
        style: const TextStyle(
          fontWeight: FontWeight.bold,
          fontSize: 13,
        ),
      ),
    );
  }
}

class _TableCell extends StatelessWidget {
  const _TableCell({required this.child, this.onTap});
  final Widget child;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: child,
      ),
    );
  }
}

class _JsonView extends StatelessWidget {
  const _JsonView({required this.jsonData});

  final Map<String, dynamic> jsonData;

  String get _jsonString => const JsonEncoder.withIndent('  ').convert(jsonData);

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 80),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              borderRadius: BorderRadius.circular(12),
            ),
            child: SelectableText(
              _jsonString,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: Color(0xFFD4D4D4),
                height: 1.5,
              ),
            ),
          ),
        ),
        Positioned(
          right: 20,
          bottom: 20,
          child: FloatingActionButton.small(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _jsonString));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('JSON copied to clipboard'),
                  duration: Duration(seconds: 1),
                ),
              );
            },
            child: const Icon(Icons.copy),
          ),
        ),
      ],
    );
  }
}

class _FindingCard extends StatefulWidget {
  const _FindingCard({required this.finding});

  final _FindingItem finding;

  @override
  State<_FindingCard> createState() => _FindingCardState();
}

class _FindingCardState extends State<_FindingCard> {
  bool _isExpanded = false;

  static const int _maxShortValueLength = 100;
  static const int _maxShortValueLines = 3;

  bool get _isLargeValue {
    final valueStr = widget.finding.value;
    final lineCount = '\n'.allMatches(valueStr).length + 1;
    return valueStr.length > _maxShortValueLength ||
        lineCount > _maxShortValueLines;
  }

  String get _previewValue {
    final valueStr = widget.finding.value;
    final lines = valueStr.split('\n');

    if (lines.length > _maxShortValueLines) {
      return '${lines.take(_maxShortValueLines).join('\n')}...';
    }

    if (valueStr.length > _maxShortValueLength) {
      return '${valueStr.substring(0, _maxShortValueLength)}...';
    }

    return valueStr;
  }

  @override
  Widget build(BuildContext context) {
    final finding = widget.finding;

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.grey.shade200),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          InkWell(
            onTap: () => _copyValue(context),
            onLongPress: () => _showFullValue(context),
            borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: finding.color.withOpacity(0.05),
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(12),
                ),
                border: Border(
                  bottom: BorderSide(color: finding.color.withOpacity(0.1)),
                ),
              ),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: finding.color.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Icon(
                      finding.icon,
                      size: 14,
                      color: finding.color,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          finding.title,
                          style: TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                            color: Colors.grey.shade800,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          finding.typeLabel,
                          style: TextStyle(
                            fontSize: 11,
                            color: finding.color,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (finding.type != _FindingType.info)
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.red.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: const Text(
                        'EXPOSED',
                        style: TextStyle(
                          color: Colors.red,
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
          if (_isLargeValue) _buildExpandableValue() else _buildSimpleValue(),
        ],
      ),
    );
  }

  Widget _buildSimpleValue() {
    return InkWell(
      onTap: () => _copyValue(context),
      borderRadius: const BorderRadius.vertical(bottom: Radius.circular(12)),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFFF8F9FA),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey.shade200),
          ),
          child: SelectableText(
            widget.finding.value,
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 13,
              color: Colors.grey.shade800,
              height: 1.4,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildExpandableValue() {
    final finding = widget.finding;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 14, 14, 0),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFFF8F9FA),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.grey.shade200),
            ),
            constraints: BoxConstraints(maxHeight: _isExpanded ? 350 : 100),
            child: SingleChildScrollView(
              physics: _isExpanded
                  ? const AlwaysScrollableScrollPhysics()
                  : const NeverScrollableScrollPhysics(),
              child: SelectableText(
                _isExpanded ? finding.value : _previewValue,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 13,
                  color: Colors.grey.shade800,
                  height: 1.4,
                ),
              ),
            ),
          ),
        ),
        InkWell(
          onTap: () => setState(() => _isExpanded = !_isExpanded),
          borderRadius: const BorderRadius.vertical(
            bottom: Radius.circular(12),
          ),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 6,
                  ),
                  decoration: BoxDecoration(
                    color: finding.color.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _isExpanded ? Icons.unfold_less : Icons.unfold_more,
                        size: 16,
                        color: finding.color,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        _isExpanded ? 'Collapse' : 'Expand',
                        style: TextStyle(
                          color: finding.color,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  void _copyValue(BuildContext context) {
    Clipboard.setData(ClipboardData(text: widget.finding.value));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Copied "${widget.finding.title}" to clipboard'),
        duration: const Duration(seconds: 1),
      ),
    );
  }

  void _showFullValue(BuildContext context) {
    final finding = widget.finding;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.7,
        minChildSize: 0.4,
        maxChildSize: 0.95,
        expand: false,
        builder: (context, scrollController) => Container(
          decoration: const BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              Center(
                child: Container(
                  margin: const EdgeInsets.only(top: 12),
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Colors.grey[300],
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              Container(
                margin: const EdgeInsets.all(16),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: finding.color.withOpacity(0.05),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: finding.color.withOpacity(0.1)),
                ),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: finding.color.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(
                        finding.icon,
                        size: 20,
                        color: finding.color,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            finding.title,
                            style: TextStyle(
                              fontWeight: FontWeight.w600,
                              fontSize: 16,
                              color: Colors.grey.shade800,
                            ),
                          ),
                          Text(
                            finding.typeLabel,
                            style: TextStyle(
                              fontSize: 12,
                              color: finding.color,
                            ),
                          ),
                        ],
                      ),
                    ),
                    Material(
                      color: finding.color.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      child: InkWell(
                        onTap: () {
                          Clipboard.setData(ClipboardData(text: finding.value));
                          Navigator.pop(context);
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Copied to clipboard'),
                              duration: Duration(seconds: 1),
                            ),
                          );
                        },
                        borderRadius: BorderRadius.circular(8),
                        child: Padding(
                          padding: const EdgeInsets.all(8),
                          child: Icon(
                            Icons.copy_rounded,
                            size: 20,
                            color: finding.color,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: SingleChildScrollView(
                  controller: scrollController,
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                  child: Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF8F9FA),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.grey.shade200),
                    ),
                    child: SelectableText(
                      finding.value,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                        color: Colors.grey.shade800,
                        height: 1.5,
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
