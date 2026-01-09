import 'package:device_packages/device_packages.dart';
import 'package:flutter/foundation.dart';
import 'package:rcspy/src/services/apk_analyzer.dart';
import 'package:rcspy/src/services/remote_config_service.dart';
import 'package:rcspy/src/services/storage_service.dart';

class AppAnalysisState {
  final FirebaseAnalysisResult? apkResult;
  final RemoteConfigResult? rcResult;
  final bool isAnalyzingApk;
  final bool isCheckingRc;

  const AppAnalysisState({
    this.apkResult,
    this.rcResult,
    this.isAnalyzingApk = false,
    this.isCheckingRc = false,
  });

  AppAnalysisState copyWith({
    FirebaseAnalysisResult? apkResult,
    RemoteConfigResult? rcResult,
    bool? isAnalyzingApk,
    bool? isCheckingRc,
  }) {
    return AppAnalysisState(
      apkResult: apkResult ?? this.apkResult,
      rcResult: rcResult ?? this.rcResult,
      isAnalyzingApk: isAnalyzingApk ?? this.isAnalyzingApk,
      isCheckingRc: isCheckingRc ?? this.isCheckingRc,
    );
  }
}

class AnalysisProgress {
  final int total;
  final int completed;
  final int withFirebase;
  final int vulnerable;
  final int cached;
  final bool isComplete;

  const AnalysisProgress({
    this.total = 0,
    this.completed = 0,
    this.withFirebase = 0,
    this.vulnerable = 0,
    this.cached = 0,
    this.isComplete = false,
  });

  double get progress => total > 0 ? completed / total : 0;
  int get remaining => total - completed;
}

enum AppFilter {
  all,
  vulnerable,
  firebase,
  secure,
  noFirebase,
}

class AnalysisProvider extends ChangeNotifier {
  static const int _maxParallelAnalysis = 4;

  List<PackageInfo> _packages = [];
  final Map<String, AppAnalysisState> _analysisStates = {};
  AnalysisProgress _progress = const AnalysisProgress();
  bool _isLoadingPackages = true;
  bool _isAnalyzing = false;
  int _newAppsCount = 0;
  AppFilter _currentFilter = AppFilter.all;

  List<PackageInfo> get packages => _packages;
  AnalysisProgress get progress => _progress;
  bool get isLoadingPackages => _isLoadingPackages;
  bool get isAnalyzing => _isAnalyzing;
  int get newAppsCount => _newAppsCount;
  AppFilter get currentFilter => _currentFilter;

  List<PackageInfo> get filteredPackages {
    if (_currentFilter == AppFilter.all) {
      return _packages;
    }

    return _packages.where((package) {
      final packageId = _getPackageId(package);
      final state = _analysisStates[packageId];

      if (state == null) return false;

      switch (_currentFilter) {
        case AppFilter.all:
          return true;
        case AppFilter.vulnerable:
          return state.rcResult?.isAccessible == true;
        case AppFilter.firebase:
          return state.apkResult?.hasFirebase == true;
        case AppFilter.secure:
          return state.apkResult?.hasFirebase == true &&
              state.rcResult?.isAccessible == false;
        case AppFilter.noFirebase:
          return state.apkResult?.hasFirebase == false &&
              state.apkResult?.error == null;
      }
    }).toList();
  }

  void setFilter(AppFilter filter) {
    if (_currentFilter != filter) {
      _currentFilter = filter;
      notifyListeners();
    }
  }

  AppAnalysisState? getState(String packageId) => _analysisStates[packageId];

  Future<void> loadPackages() async {
    _isLoadingPackages = true;
    notifyListeners();

    await StorageService.init();

    final cachedData = StorageService.loadCache();
    int cachedFirebase = 0;
    int cachedVulnerable = 0;

    for (final entry in cachedData.entries) {
      final data = entry.value;
      _analysisStates[entry.key] = AppAnalysisState(
        apkResult: data.toApkResult(),
        rcResult: data.toRcResult(),
      );
      if (data.hasFirebase) cachedFirebase++;
      if (data.rcAccessible == true) cachedVulnerable++;
    }

    _packages = await DevicePackages.getInstalledPackages(
      includeIcon: true,
      includeSystemPackages: false,
    );

    _packages.sort((a, b) {
      final nameA = (a.name ?? a.id ?? '').toLowerCase();
      final nameB = (b.name ?? b.id ?? '').toLowerCase();
      return nameA.compareTo(nameB);
    });

    final analyzedIds = StorageService.getAnalyzedPackageIds();
    final newApps = _packages.where((p) {
      final id = _getPackageId(p);
      return !analyzedIds.contains(id);
    }).toList();

    _newAppsCount = newApps.length;

    _isLoadingPackages = false;

    _progress = AnalysisProgress(
      total: _packages.length,
      completed: _packages.length - newApps.length,
      withFirebase: cachedFirebase,
      vulnerable: cachedVulnerable,
      cached: cachedData.length,
      isComplete: newApps.isEmpty,
    );

    notifyListeners();

    if (newApps.isNotEmpty) {
      await _analyzePackages(newApps, isFullReanalysis: false);
    }
  }

  Future<void> reanalyzeAll() async {
    if (_isAnalyzing) return;

    await StorageService.clearCache();
    _analysisStates.clear();

    await _analyzePackages(_packages, isFullReanalysis: true);
  }

  Future<void> reanalyzePackage(PackageInfo package) async {
    final packageId = _getPackageId(package);

    await StorageService.removeAppData(packageId);

    _analysisStates[packageId] = const AppAnalysisState(isAnalyzingApk: true);
    notifyListeners();

    await _analyzePackage(package, saveToCache: true);

    _updateProgressStats();
    notifyListeners();
  }

  Future<void> _analyzePackages(
    List<PackageInfo> packagesToAnalyze, {
    required bool isFullReanalysis,
  }) async {
    if (packagesToAnalyze.isEmpty) return;

    _isAnalyzing = true;

    int completed = isFullReanalysis ? 0 : _progress.completed;
    int withFirebase = isFullReanalysis ? 0 : _progress.withFirebase;
    int vulnerable = isFullReanalysis ? 0 : _progress.vulnerable;

    _progress = AnalysisProgress(
      total: _packages.length,
      completed: completed,
      withFirebase: withFirebase,
      vulnerable: vulnerable,
    );
    notifyListeners();

    final batches = _createBatches(packagesToAnalyze, _maxParallelAnalysis);

    for (final batch in batches) {
      for (final package in batch) {
        final packageId = _getPackageId(package);
        _analysisStates[packageId] = const AppAnalysisState(
          isAnalyzingApk: true,
        );
      }
      notifyListeners();

      final futures = batch
          .map((p) => _analyzePackage(p, saveToCache: true))
          .toList();
      final results = await Future.wait(futures);

      for (final result in results) {
        completed++;
        if (result.hasFirebase) withFirebase++;
        if (result.isVulnerable) vulnerable++;
      }

      _progress = AnalysisProgress(
        total: _packages.length,
        completed: completed,
        withFirebase: withFirebase,
        vulnerable: vulnerable,
      );
      notifyListeners();
    }

    _isAnalyzing = false;
    _newAppsCount = 0;
    _progress = AnalysisProgress(
      total: _packages.length,
      completed: completed,
      withFirebase: withFirebase,
      vulnerable: vulnerable,
      isComplete: true,
    );
    notifyListeners();
  }

  Future<({bool hasFirebase, bool isVulnerable})> _analyzePackage(
    PackageInfo package, {
    bool saveToCache = false,
  }) async {
    final packageId = _getPackageId(package);
    final apkPath = package.installerPath;

    if (apkPath == null || apkPath.isEmpty) {
      _analysisStates[packageId] = AppAnalysisState(
        apkResult: FirebaseAnalysisResult.error('No APK path'),
        isAnalyzingApk: false,
      );
      if (saveToCache) {
        await StorageService.saveAppData(
          CachedAppData(
            packageId: packageId,
            hasFirebase: false,
            error: 'No APK path',
            analyzedAt: DateTime.now(),
          ),
        );
      }
      return (hasFirebase: false, isVulnerable: false);
    }

    try {
      final apkResult = await ApkAnalyzer.analyzeApk(apkPath);

      bool isVulnerable = false;
      RemoteConfigResult? rcResult;

      if (apkResult.hasFirebase &&
          apkResult.googleAppIds.isNotEmpty &&
          apkResult.googleApiKeys.isNotEmpty) {
        _analysisStates[packageId] = AppAnalysisState(
          apkResult: apkResult,
          isAnalyzingApk: false,
          isCheckingRc: true,
        );

        rcResult = await RemoteConfigService.checkMultipleCombinations(
          googleAppIds: apkResult.googleAppIds,
          apiKeys: apkResult.googleApiKeys,
        );

        _analysisStates[packageId] = AppAnalysisState(
          apkResult: apkResult,
          rcResult: rcResult,
          isAnalyzingApk: false,
          isCheckingRc: false,
        );

        isVulnerable = rcResult.isAccessible;
      } else {
        _analysisStates[packageId] = AppAnalysisState(
          apkResult: apkResult,
          isAnalyzingApk: false,
        );
      }

      if (saveToCache) {
        await StorageService.saveAppData(
          CachedAppData(
            packageId: packageId,
            hasFirebase: apkResult.hasFirebase,
            googleAppIds: apkResult.googleAppIds,
            googleApiKeys: apkResult.googleApiKeys,
            rcAccessible: rcResult?.isAccessible,
            rcConfigValues: rcResult?.configValues,
            analyzedAt: DateTime.now(),
          ),
        );
      }

      return (hasFirebase: apkResult.hasFirebase, isVulnerable: isVulnerable);
    } catch (e) {
      _analysisStates[packageId] = AppAnalysisState(
        apkResult: FirebaseAnalysisResult.error(e.toString()),
        isAnalyzingApk: false,
      );
      if (saveToCache) {
        await StorageService.saveAppData(
          CachedAppData(
            packageId: packageId,
            hasFirebase: false,
            error: e.toString(),
            analyzedAt: DateTime.now(),
          ),
        );
      }
      return (hasFirebase: false, isVulnerable: false);
    }
  }

  void _updateProgressStats() {
    int withFirebase = 0;
    int vulnerable = 0;

    for (final state in _analysisStates.values) {
      if (state.apkResult?.hasFirebase == true) withFirebase++;
      if (state.rcResult?.isAccessible == true) vulnerable++;
    }

    _progress = AnalysisProgress(
      total: _packages.length,
      completed: _packages.length,
      withFirebase: withFirebase,
      vulnerable: vulnerable,
      isComplete: true,
    );
  }

  String _getPackageId(PackageInfo package) => package.id ?? package.name ?? '';

  List<List<PackageInfo>> _createBatches(
    List<PackageInfo> packages,
    int batchSize,
  ) {
    final batches = <List<PackageInfo>>[];
    for (var i = 0; i < packages.length; i += batchSize) {
      final end = (i + batchSize < packages.length)
          ? i + batchSize
          : packages.length;
      batches.add(packages.sublist(i, end));
    }
    return batches;
  }
}
