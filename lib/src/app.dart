import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rcspy/src/pages/home_page.dart';
import 'package:rcspy/src/providers/analysis_provider.dart';

class RCSpy extends StatelessWidget {
  const RCSpy({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => AnalysisProvider()..loadPackages(),
      child: MaterialApp(
        title: "RC Spy",
        debugShowCheckedModeBanner: false,
        home: const HomePage(),
        themeMode: ThemeMode.light,
        theme: ThemeData(
          colorSchemeSeed: Colors.blue,
          scaffoldBackgroundColor: Colors.white,
          brightness: Brightness.light,
          visualDensity: VisualDensity.adaptivePlatformDensity,
          appBarTheme: AppBarTheme(
            elevation: 0,
            scrolledUnderElevation: 0,
            backgroundColor: Colors.white,
          ),
        ),
      ),
    );
  }
}
