import 'package:device_packages/device_packages.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rcspy/src/pages/settings_page.dart';
import 'package:rcspy/src/providers/analysis_provider.dart';
import 'package:rcspy/src/widgets/app_tile.dart';

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          "RC Spy",
          style: TextStyle(
            fontSize: 18,
            color: Colors.black,
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          // Re-analyze all button
          Selector<AnalysisProvider, bool>(
            selector: (_, provider) => provider.isAnalyzing,
            builder: (context, isAnalyzing, _) {
              return IconButton(
                icon: isAnalyzing
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                          year2023: false,
                        ),
                      )
                    : const Icon(Icons.refresh),
                tooltip: 'Re-analyze all apps',
                onPressed: isAnalyzing
                    ? null
                    : () => _showReanalyzeDialog(context),
              );
            },
          ),
          // Settings button
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Settings',
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const SettingsPage()),
              );
            },
          ),
        ],
      ),
      body: _buildBody(context),
    );
  }

  void _showReanalyzeDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Re-analyze All Apps'),
        content: const Text(
          'This will clear the cache and re-analyze all installed apps. '
          'This may take a while.\n\n'
          'Continue?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(context);
              context.read<AnalysisProvider>().reanalyzeAll();
            },
            child: const Text('Re-analyze'),
          ),
        ],
      ),
    );
  }

  Widget _buildBody(BuildContext context) {
    // Use Selector for loading state - only rebuilds when isLoadingPackages changes
    return Selector<AnalysisProvider, bool>(
      selector: (_, provider) => provider.isLoadingPackages,
      builder: (context, isLoading, _) {
        if (isLoading) {
          return const Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                CircularProgressIndicator(year2023: false),
                SizedBox(height: 16),
                Text('Loading installed apps...'),
              ],
            ),
          );
        }

        return const _AppListWithHeader();
      },
    );
  }
}

/// Separate widget for the app list with header
class _AppListWithHeader extends StatelessWidget {
  const _AppListWithHeader();

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Progress/Stats header - uses Selector for efficient updates
        const _ProgressHeader(),
        const SizedBox(height: 8),
        // Filter bar
        const _FilterBar(),
        const SizedBox(height: 8),
        // App list
        Expanded(
          child: Selector<AnalysisProvider,
              ({List<PackageInfo> packages, AppFilter filter})>(
            selector: (_, provider) => (
              packages: provider.filteredPackages,
              filter: provider.currentFilter,
            ),
            builder: (context, data, _) {
              if (data.packages.isEmpty) {
                return Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.search_off,
                        size: 48,
                        color: Colors.grey[400],
                      ),
                      const SizedBox(height: 12),
                      Text(
                        'No apps match this filter',
                        style: TextStyle(
                          color: Colors.grey[600],
                          fontSize: 16,
                        ),
                      ),
                    ],
                  ),
                );
              }

              return ListView.builder(
                itemCount: data.packages.length,
                itemBuilder: (context, index) {
                  final package = data.packages[index];
                  return AppTile(
                    key: ValueKey(package.id ?? package.name),
                    package: package,
                  );
                },
              );
            },
          ),
        ),
      ],
    );
  }
}

/// Filter bar for filtering apps
class _FilterBar extends StatelessWidget {
  const _FilterBar();

  @override
  Widget build(BuildContext context) {
    return Selector<AnalysisProvider,
        ({AppFilter filter, AnalysisProgress progress})>(
      selector: (_, provider) => (
        filter: provider.currentFilter,
        progress: provider.progress,
      ),
      builder: (context, data, _) {
        return SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Row(
            children: [
              _FilterChip(
                label: 'All',
                count: data.progress.total,
                icon: Icons.apps,
                isSelected: data.filter == AppFilter.all,
                onTap: () =>
                    context.read<AnalysisProvider>().setFilter(AppFilter.all),
              ),
              const SizedBox(width: 8),
              _FilterChip(
                label: 'Vulnerable',
                count: data.progress.vulnerable,
                icon: Icons.warning_amber,
                color: Colors.red,
                isSelected: data.filter == AppFilter.vulnerable,
                onTap: () => context
                    .read<AnalysisProvider>()
                    .setFilter(AppFilter.vulnerable),
              ),
              const SizedBox(width: 8),
              _FilterChip(
                label: 'Firebase',
                count: data.progress.withFirebase,
                icon: Icons.local_fire_department,
                color: Colors.orange,
                isSelected: data.filter == AppFilter.firebase,
                onTap: () => context
                    .read<AnalysisProvider>()
                    .setFilter(AppFilter.firebase),
              ),
              const SizedBox(width: 8),
              _FilterChip(
                label: 'Secure',
                count: data.progress.withFirebase - data.progress.vulnerable,
                icon: Icons.lock,
                color: Colors.green,
                isSelected: data.filter == AppFilter.secure,
                onTap: () =>
                    context.read<AnalysisProvider>().setFilter(AppFilter.secure),
              ),
              const SizedBox(width: 8),
              _FilterChip(
                label: 'No Firebase',
                count: data.progress.total - data.progress.withFirebase,
                icon: Icons.check_circle_outline,
                color: Colors.grey,
                isSelected: data.filter == AppFilter.noFirebase,
                onTap: () => context
                    .read<AnalysisProvider>()
                    .setFilter(AppFilter.noFirebase),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _FilterChip extends StatelessWidget {
  const _FilterChip({
    required this.label,
    required this.count,
    required this.icon,
    required this.isSelected,
    required this.onTap,
    this.color,
  });

  final String label;
  final int count;
  final IconData icon;
  final bool isSelected;
  final VoidCallback onTap;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final chipColor = color ?? Colors.blue;

    return Material(
      color: isSelected ? chipColor.withOpacity(0.15) : Colors.grey[100],
      borderRadius: BorderRadius.circular(20),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(20),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: isSelected ? chipColor : Colors.grey[300]!,
              width: isSelected ? 1.5 : 1,
            ),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                icon,
                size: 16,
                color: isSelected ? chipColor : Colors.grey[600],
              ),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
                  color: isSelected ? chipColor : Colors.grey[700],
                ),
              ),
              const SizedBox(width: 6),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: isSelected ? chipColor.withOpacity(0.2) : Colors.grey[200],
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '$count',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    color: isSelected ? chipColor : Colors.grey[600],
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

/// Progress header that only shows during analysis
class _ProgressHeader extends StatelessWidget {
  const _ProgressHeader();

  @override
  Widget build(BuildContext context) {
    return Selector<
      AnalysisProvider,
      ({bool isAnalyzing, AnalysisProgress progress, int newApps})
    >(
      selector: (_, provider) => (
        isAnalyzing: provider.isAnalyzing,
        progress: provider.progress,
        newApps: provider.newAppsCount,
      ),
      builder: (context, data, _) {
        if (!data.isAnalyzing) {
          return const SizedBox.shrink();
        }

        return Card(
          elevation: 0,
          margin: const EdgeInsets.symmetric(horizontal: 12),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              children: [
                // Progress info text
                if (data.newApps > 0 && data.progress.cached > 0)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Text(
                      'Analyzing ${data.newApps} new app${data.newApps > 1 ? 's' : ''} (${data.progress.cached} cached)',
                      style: TextStyle(
                        fontSize: 12,
                        color: Colors.blue[700],
                      ),
                    ),
                  ),

                // Progress bar
                Row(
                  children: [
                    Expanded(
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(8),
                        child: LinearProgressIndicator(
                          value: data.progress.progress,
                          minHeight: 6,
                          backgroundColor: Colors.grey[300],
                          year2023: false,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Text(
                      '${data.progress.completed}/${data.progress.total}',
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
