import 'dart:convert';

import 'package:http/http.dart' as http;

/// Result of Remote Config check
class RemoteConfigResult {
  final bool isAccessible;
  final Map<String, dynamic>? configValues;
  final String? error;

  RemoteConfigResult({
    required this.isAccessible,
    this.configValues,
    this.error,
  });

  factory RemoteConfigResult.accessible(Map<String, dynamic> values) {
    return RemoteConfigResult(
      isAccessible: true,
      configValues: values,
    );
  }

  factory RemoteConfigResult.secure() {
    return RemoteConfigResult(
      isAccessible: false,
    );
  }

  factory RemoteConfigResult.error(String message) {
    return RemoteConfigResult(
      isAccessible: false,
      error: message,
    );
  }
}

/// Service to check Firebase Remote Config accessibility
class RemoteConfigService {
  /// Checks if Firebase Remote Config is publicly accessible
  ///
  /// [googleAppId] - The Google App ID (e.g., "1:1092279052737:android:565c2d34e2a4e73a")
  /// [apiKey] - The Google API Key (e.g., "AIzaSyAIc2gqTbZ88gKFoClbn8y0FYcAI2G1_Zo")
  static Future<RemoteConfigResult> checkRemoteConfig({
    required String googleAppId,
    required String apiKey,
  }) async {
    try {
      // Extract project number from app ID (format: 1:PROJECT_NUMBER:android:hash)
      final parts = googleAppId.split(':');
      if (parts.length < 2) {
        return RemoteConfigResult.error('Invalid app ID format');
      }
      final projectNumber = parts[1];

      final url = Uri.parse(
        'https://firebaseremoteconfig.googleapis.com/v1/projects/$projectNumber/namespaces/firebase:fetch?key=$apiKey',
      );

      final response = await http.post(
        url,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'appId': googleAppId,
          'appInstanceId': 'required_but_unused_value',
        }),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;

        // Parse the entries from the response
        final entries = <String, dynamic>{};

        if (data.containsKey('entries')) {
          final rawEntries = data['entries'] as Map<String, dynamic>?;
          if (rawEntries != null) {
            for (final entry in rawEntries.entries) {
              // Try to parse JSON values, otherwise keep as string
              try {
                entries[entry.key] = jsonDecode(entry.value as String);
              } catch (_) {
                entries[entry.key] = entry.value;
              }
            }
          }
        }

        return RemoteConfigResult.accessible(entries);
      } else if (response.statusCode == 403 || response.statusCode == 401) {
        // Access denied - Remote Config is properly secured
        return RemoteConfigResult.secure();
      } else {
        return RemoteConfigResult.error(
          'HTTP ${response.statusCode}: ${response.reasonPhrase}',
        );
      }
    } catch (e) {
      return RemoteConfigResult.error('Failed to check Remote Config: $e');
    }
  }

  /// Checks multiple combinations of app IDs and API keys
  /// Returns the first successful result or secure if none work
  static Future<RemoteConfigResult> checkMultipleCombinations({
    required List<String> googleAppIds,
    required List<String> apiKeys,
  }) async {
    for (final appId in googleAppIds) {
      for (final apiKey in apiKeys) {
        final result = await checkRemoteConfig(
          googleAppId: appId,
          apiKey: apiKey,
        );

        if (result.isAccessible) {
          return result;
        }
      }
    }

    return RemoteConfigResult.secure();
  }
}
