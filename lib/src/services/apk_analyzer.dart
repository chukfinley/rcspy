import 'dart:io';
import 'dart:isolate';

import 'package:archive/archive.dart';

/// Result of APK analysis for Firebase detection
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

  /// Convert to Map for isolate communication
  Map<String, dynamic> toMap() => {
        'hasFirebase': hasFirebase,
        'googleAppIds': googleAppIds,
        'googleApiKeys': googleApiKeys,
        'error': error,
      };

  /// Create from Map for isolate communication
  factory FirebaseAnalysisResult.fromMap(Map<String, dynamic> map) {
    return FirebaseAnalysisResult(
      hasFirebase: map['hasFirebase'] as bool,
      googleAppIds: List<String>.from(map['googleAppIds'] ?? []),
      googleApiKeys: List<String>.from(map['googleApiKeys'] ?? []),
      error: map['error'] as String?,
    );
  }
}

/// Top-level function to run APK analysis in isolate
/// Must be top-level for Isolate.run to work
Future<Map<String, dynamic>> _analyzeApkInIsolate(String apkPath) async {
  try {
    final file = File(apkPath);

    if (!await file.exists()) {
      return FirebaseAnalysisResult.error('APK file not found').toMap();
    }

    // Read APK file bytes
    final bytes = await file.readAsBytes();

    // Decode the APK as a ZIP archive
    final archive = ZipDecoder().decodeBytes(bytes);

    final Set<String> foundAppIds = {};
    final Set<String> foundApiKeys = {};

    // Regular expressions
    final googleAppIdPattern = RegExp(
      r'\d+:\d+:android:[a-f0-9]+',
      caseSensitive: false,
    );
    final googleApiKeyPattern = RegExp(
      r'AIza[0-9A-Za-z_-]{35}',
    );

    // Search through all files in the archive
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

/// Static version for isolate - determines if a file should be analyzed
bool _shouldAnalyzeFileStatic(String fileName) {
  return fileName.endsWith('.arsc') ||
      fileName.endsWith('.xml') ||
      fileName.endsWith('.json') ||
      fileName.endsWith('.dex') ||
      fileName.contains('google-services') ||
      fileName.contains('firebase');
}

/// Static version for isolate - extracts credentials
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
    // Ignore parsing errors
  }

  return (foundAppIds, foundApiKeys);
}

/// Static version for isolate - extracts strings from bytes
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

/// Service to analyze APK files for Firebase usage
class ApkAnalyzer {
  /// Analyzes an APK file to detect Firebase usage
  /// Runs in a separate isolate to avoid blocking the main thread
  ///
  /// [apkPath] - Path to the APK file
  /// Returns [FirebaseAnalysisResult] with detection results
  static Future<FirebaseAnalysisResult> analyzeApk(String apkPath) async {
    try {
      // Run the heavy analysis in a separate isolate
      final resultMap = await Isolate.run(() => _analyzeApkInIsolate(apkPath));
      return FirebaseAnalysisResult.fromMap(resultMap);
    } catch (e) {
      return FirebaseAnalysisResult.error('Isolate error: $e');
    }
  }
}
