import 'package:device_packages/device_packages.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rcspy/src/pages/remote_config_page.dart';
import 'package:rcspy/src/providers/analysis_provider.dart';
import 'package:rcspy/src/services/apk_analyzer.dart';

class AppTile extends StatelessWidget {
  const AppTile({super.key, required this.package});

  final PackageInfo package;

  String get _packageId => package.id ?? package.name ?? '';

  @override
  Widget build(BuildContext context) {
    // Use Selector to only rebuild when THIS app's state changes
    return Selector<AnalysisProvider, AppAnalysisState?>(
      selector: (_, provider) => provider.getState(_packageId),
      builder: (context, state, _) {
        return ListTile(
          title: Text(package.name ?? 'Unknown App'),
          subtitle: _buildSubtitle(state),
          leading: package.icon != null
              ? Image.memory(package.icon!, width: 40, height: 40)
              : const Icon(Icons.android, size: 40),
          trailing: _buildTrailingWidget(context, state),
          onTap: () => _handleTap(context, state),
          onLongPress: () => _showOptionsMenu(context, state),
          contentPadding: const EdgeInsets.only(
            left: 16,
            right: 4,
            top: 4,
            bottom: 8,
          ),
        );
      },
    );
  }

  void _showOptionsMenu(BuildContext context, AppAnalysisState? state) {
    final isLoading =
        state == null || state.isAnalyzingApk || state.isCheckingRc;

    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 40,
              height: 4,
              margin: const EdgeInsets.symmetric(vertical: 12),
              decoration: BoxDecoration(
                color: Colors.grey[300],
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            ListTile(
              leading: const Icon(Icons.refresh),
              title: const Text('Re-analyze this app'),
              subtitle: const Text('Clear cache and analyze again'),
              enabled: !isLoading,
              onTap: isLoading
                  ? null
                  : () {
                      Navigator.pop(context);
                      context.read<AnalysisProvider>().reanalyzePackage(
                        package,
                      );
                    },
            ),
            if (state?.apkResult?.hasFirebase == true)
              ListTile(
                leading: const Icon(Icons.info_outline),
                title: const Text('View Firebase details'),
                onTap: () {
                  Navigator.pop(context);
                  _showFirebaseDetails(context, state!.apkResult!);
                },
              ),
            if (state?.rcResult?.isAccessible == true)
              ListTile(
                leading: const Icon(Icons.vpn_key),
                title: const Text('View Remote Config'),
                onTap: () {
                  Navigator.pop(context);
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (context) => RemoteConfigPage(
                        appName: package.name ?? 'Unknown App',
                        configValues: state!.rcResult!.configValues ?? {},
                      ),
                    ),
                  );
                },
              ),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );
  }

  void _handleTap(BuildContext context, AppAnalysisState? state) {
    final rcResult = state?.rcResult;
    final apkResult = state?.apkResult;

    // If RC is publicly accessible, navigate to config page
    if (rcResult?.isAccessible == true) {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (context) => RemoteConfigPage(
            appName: package.name ?? 'Unknown App',
            configValues: rcResult!.configValues ?? {},
          ),
        ),
      );
    } else if (apkResult?.hasFirebase == true) {
      // Show Firebase details bottom sheet
      _showFirebaseDetails(context, apkResult!);
    }
  }

  Widget _buildSubtitle(AppAnalysisState? state) {
    final chips = <Widget>[];

    // Waiting to be analyzed
    if (state == null || state.apkResult == null) {
      if (state?.isAnalyzingApk == true) {
        chips.add(
          _buildChip('Analyzing', Colors.blue, Icons.sync, isLoading: true),
        );
      } else if (state?.isCheckingRc == true) {
        chips.add(
          _buildChip(
            'Checking RC',
            Colors.blue,
            Icons.cloud_sync,
            isLoading: true,
          ),
        );
      } else {
        chips.add(_buildChip('Waiting', Colors.grey, Icons.hourglass_empty));
      }
      return Wrap(spacing: 6, runSpacing: 4, children: chips);
    }

    final apkResult = state.apkResult!;
    final rcResult = state.rcResult;

    // Error state
    if (apkResult.error != null) {
      chips.add(_buildChip('Error', Colors.red, Icons.error_outline));
      return Wrap(spacing: 6, runSpacing: 4, children: chips);
    }

    // Firebase status
    if (apkResult.hasFirebase) {
      chips.add(
        _buildChip('Firebase', Colors.orange, Icons.local_fire_department),
      );

      // RC status
      if (rcResult != null) {
        if (rcResult.isAccessible) {
          final count = rcResult.configValues?.length ?? 0;
          chips.add(
            _buildChip(
              'RC Exposed ($count)',
              Colors.red,
              Icons.warning_amber,
              isBold: true,
            ),
          );
        } else {
          chips.add(_buildChip('RC Secure', Colors.green, Icons.lock));
        }
      } else {
        // Missing credentials
        final hasAppId = apkResult.googleAppIds.isNotEmpty;
        final hasApiKey = apkResult.googleApiKeys.isNotEmpty;
        if (!hasAppId || !hasApiKey) {
          chips.add(
            _buildChip(
              'Missing ${!hasAppId ? 'App ID' : 'API Key'}',
              Colors.orange,
              Icons.warning_outlined,
            ),
          );
        }
      }
    } else {
      chips.add(
        _buildChip('No Firebase', Colors.grey, Icons.check_circle_outline),
      );
    }

    return Wrap(spacing: 6, runSpacing: 4, children: chips);
  }

  Widget _buildChip(
    String label,
    Color color,
    IconData icon, {
    bool isLoading = false,
    bool isBold = false,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (isLoading)
            SizedBox(
              width: 12,
              height: 12,
              child: CircularProgressIndicator(
                strokeWidth: 1.5,
                color: color,
                year2023: false,
              ),
            )
          else
            Icon(icon, size: 14, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              color: color,
              fontWeight: isBold ? FontWeight.bold : FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTrailingWidget(BuildContext context, AppAnalysisState? state) {
    final apkResult = state?.apkResult;
    final rcResult = state?.rcResult;

    return PopupMenuButton<String>(
      icon: Icon(Icons.more_vert, color: Colors.grey[600]),
      padding: EdgeInsets.zero,
      onSelected: (value) {
        switch (value) {
          case 'reanalyze':
            context.read<AnalysisProvider>().reanalyzePackage(package);
            break;
          case 'details':
            if (apkResult?.hasFirebase == true) {
              _showFirebaseDetails(context, apkResult!);
            }
            break;
          case 'config':
            if (rcResult?.isAccessible == true) {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => RemoteConfigPage(
                    appName: package.name ?? 'Unknown App',
                    configValues: rcResult?.configValues ?? {},
                  ),
                ),
              );
            }
            break;
        }
      },
      itemBuilder: (context) => [
        const PopupMenuItem(
          value: 'reanalyze',
          child: Row(
            children: [
              Icon(Icons.refresh, size: 20),
              SizedBox(width: 8),
              Text('Re-analyze'),
            ],
          ),
        ),
        if (apkResult?.hasFirebase == true)
          const PopupMenuItem(
            value: 'details',
            child: Row(
              children: [
                Icon(Icons.info_outline, size: 20),
                SizedBox(width: 8),
                Text('Firebase details'),
              ],
            ),
          ),
        if (rcResult?.isAccessible == true)
          const PopupMenuItem(
            value: 'config',
            child: Row(
              children: [
                Icon(Icons.vpn_key, size: 20),
                SizedBox(width: 8),
                Text('View RC config'),
              ],
            ),
          ),
      ],
    );
  }

  void _showFirebaseDetails(
    BuildContext context,
    FirebaseAnalysisResult apkResult,
  ) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.5,
        minChildSize: 0.3,
        maxChildSize: 0.9,
        expand: false,
        builder: (context, scrollController) => SingleChildScrollView(
          controller: scrollController,
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: Container(
                  width: 40,
                  height: 4,
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: Colors.grey[300],
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              Text(
                package.name ?? 'Unknown App',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),

              // Google App IDs section
              if (apkResult.googleAppIds.isNotEmpty) ...[
                const Text(
                  '🔥 Google App IDs:',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),
                ...apkResult.googleAppIds.map(
                  (id) => Container(
                    width: double.infinity,
                    margin: const EdgeInsets.symmetric(vertical: 4),
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.orange.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.orange.withOpacity(0.3)),
                    ),
                    child: SelectableText(
                      id,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                        color: Colors.deepOrange,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
              ],

              // Google API Keys section
              if (apkResult.googleApiKeys.isNotEmpty) ...[
                const Text(
                  '🔑 Google API Keys:',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),
                ...apkResult.googleApiKeys.map(
                  (key) => Container(
                    width: double.infinity,
                    margin: const EdgeInsets.symmetric(vertical: 4),
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.blue.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.blue.withOpacity(0.3)),
                    ),
                    child: SelectableText(
                      key,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                        color: Colors.blue,
                      ),
                    ),
                  ),
                ),
              ],

              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}
