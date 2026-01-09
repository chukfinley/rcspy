import 'dart:io';
import 'dart:isolate';

import 'package:archive/archive.dart';

class FirebaseAnalysisResult {
  final bool hasFirebase;
  final List<String> googleAppIds;
  final List<String> googleApiKeys;
  final String? error;

  FirebaseAnalysisResult({
    required this.hasFirebase,
    this.googleAppIds = const [],
    this.googleApiKeys = const [],
    this.error,
  });

  factory FirebaseAnalysisResult.error(String message) {
    return FirebaseAnalysisResult(
      hasFirebase: false,
      googleAppIds: [],
      googleApiKeys: [],
      error: message,
    );
  }

  Map<String, dynamic> toMap() => {
        'hasFirebase': hasFirebase,
        'googleAppIds': googleAppIds,
        'googleApiKeys': googleApiKeys,
        'error': error,
      };

  factory FirebaseAnalysisResult.fromMap(Map<String, dynamic> map) {
    return FirebaseAnalysisResult(
      hasFirebase: map['hasFirebase'] as bool,
      googleAppIds: List<String>.from(map['googleAppIds'] ?? []),
      googleApiKeys: List<String>.from(map['googleApiKeys'] ?? []),
      error: map['error'] as String?,
    );
  }
}

Future<Map<String, dynamic>> _analyzeApkInIsolate(String apkPath) async {
  try {
    final file = File(apkPath);

    if (!await file.exists()) {
      return FirebaseAnalysisResult.error('APK file not found').toMap();
    }

    final bytes = await file.readAsBytes();

    final archive = ZipDecoder().decodeBytes(bytes);

    final Set<String> foundAppIds = {};
    final Set<String> foundApiKeys = {};

    final googleAppIdPattern = RegExp(
      r'\d+:\d+:android:[a-f0-9]+',
      caseSensitive: false,
    );
    final googleApiKeyPattern = RegExp(
      r'AIza[0-9A-Za-z_-]{35}',
    );

    for (final archiveFile in archive) {
      if (archiveFile.isFile) {
        final fileName = archiveFile.name.toLowerCase();

        if (_shouldAnalyzeFileStatic(fileName)) {
          final content = archiveFile.content as List<int>;
          final extractedData = _extractGoogleCredentialsStatic(
            content,
            googleAppIdPattern,
            googleApiKeyPattern,
          );
          foundAppIds.addAll(extractedData.$1);
          foundApiKeys.addAll(extractedData.$2);
        }
      }
    }

    final hasFirebase = foundAppIds.isNotEmpty || foundApiKeys.isNotEmpty;

    return FirebaseAnalysisResult(
      hasFirebase: hasFirebase,
      googleAppIds: foundAppIds.toList(),
      googleApiKeys: foundApiKeys.toList(),
    ).toMap();
  } catch (e) {
    return FirebaseAnalysisResult.error('Failed to analyze APK: $e').toMap();
  }
}

bool _shouldAnalyzeFileStatic(String fileName) {
  return fileName.endsWith('.arsc') ||
      fileName.endsWith('.xml') ||
      fileName.endsWith('.json') ||
      fileName.endsWith('.dex') ||
      fileName.contains('google-services') ||
      fileName.contains('firebase');
}

(Set<String>, Set<String>) _extractGoogleCredentialsStatic(
  List<int> content,
  RegExp appIdPattern,
  RegExp apiKeyPattern,
) {
  final Set<String> foundAppIds = {};
  final Set<String> foundApiKeys = {};

  try {
    final stringContent = _extractStringsFromBytesStatic(content);

    final appIdMatches = appIdPattern.allMatches(stringContent);
    for (final match in appIdMatches) {
      foundAppIds.add(match.group(0)!);
    }

    final apiKeyMatches = apiKeyPattern.allMatches(stringContent);
    for (final match in apiKeyMatches) {
      foundApiKeys.add(match.group(0)!);
    }
  } catch (e) {
  }

  return (foundAppIds, foundApiKeys);
}

String _extractStringsFromBytesStatic(List<int> bytes) {
  final buffer = StringBuffer();
  final currentString = StringBuffer();

  for (final byte in bytes) {
    if (byte >= 32 && byte <= 126) {
      currentString.writeCharCode(byte);
    } else {
      if (currentString.length >= 4) {
        buffer.write(currentString.toString());
        buffer.write(' ');
      }
      currentString.clear();
    }
  }

  if (currentString.length >= 4) {
    buffer.write(currentString.toString());
  }

  return buffer.toString();
}

class ApkAnalyzer {
  static Future<FirebaseAnalysisResult> analyzeApk(String apkPath) async {
    try {
      final resultMap = await Isolate.run(() => _analyzeApkInIsolate(apkPath));
      return FirebaseAnalysisResult.fromMap(resultMap);
    } catch (e) {
      return FirebaseAnalysisResult.error('Isolate error: $e');
    }
  }
}
