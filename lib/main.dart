import 'package:flutter/material.dart';
import 'package:qr_code_scanner/qr_code_scanner.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'dart:convert';
import 'package:logger/logger.dart';

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(primarySwatch: Colors.blueGrey),
      home: const QRViewExample(),
    );
  }
}

class QRViewExample extends StatefulWidget {
  const QRViewExample({super.key});

  @override
  State<StatefulWidget> createState() => _QRViewExampleState();
}

class _QRViewExampleState extends State<QRViewExample> {
  final GlobalKey qrKey = GlobalKey(debugLabel: 'QR');
  Barcode? result;
  QRViewController? controller;
  final logger = Logger();

  @override
  void reassemble() {
    super.reassemble();
    controller!.pauseCamera();
    controller!.resumeCamera();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('QR Safe Scanner')),
      body: Column(
        children: <Widget>[
          Expanded(flex: 4, child: _buildQrView(context)),
          Expanded(
            flex: 1,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: <Widget>[
                if (result != null)
                  Text('Result: ${result!.code}')
                else
                  const Text('Scan a code'),
                ElevatedButton(
                  onPressed: result != null && result!.code != null
                      ? () => _checkWithVirusTotal(result!.code!)
                      : null,
                  child: const Text('Check with VirusTotal'),
                ),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _buildQrView(BuildContext context) {
    return QRView(
      key: qrKey,
      onQRViewCreated: _onQRViewCreated,
      overlay: QrScannerOverlayShape(
        borderColor: Colors.white,
        borderRadius: 10,
        borderLength: 30,
        borderWidth: 10,
        cutOutSize: MediaQuery.of(context).size.width * 0.8,
      ),
    );
  }

  void _onQRViewCreated(QRViewController controller) {
    setState(() {
      this.controller = controller;
    });
    controller.scannedDataStream.listen((scanData) {
      setState(() {
        result = scanData;
      });
    });
  }

  Future<void> _checkWithVirusTotal(String url) async {
    const apiKey = '72a07f99c4b045ae9de25307f755973fbe40d7ccaf4625ba6fdb6b14590c60af';
    final encodedUrl = base64Url.encode(utf8.encode(url)).replaceAll('=', '');
    final apiUrl = 'https://www.virustotal.com/api/v3/urls/$encodedUrl';

    logger.d('Checking URL: $apiUrl'); // Debugging line

    try {
      final response = await http.get(
        Uri.parse(apiUrl),
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/json',
        },
      );

      logger.d('Response status: ${response.statusCode}'); // Debugging line
      logger.d('Response body: ${response.body}'); // Debugging line

      if (response.statusCode == 200) {
        final jsonResponse = json.decode(response.body);
        final scanResult = jsonResponse['data']['attributes']['last_analysis_stats'];

        int malicious = scanResult['malicious'] ?? 0;
        int suspicious = scanResult['suspicious'] ?? 0;

        if (malicious > 0 || suspicious > 0) {
          _showWarningDialog(url);
        } else {
          _showSafeDialog(url);
        }
      } else {
        _showErrorDialog('Error: Unable to scan the URL with VirusTotal.');
      }
    } catch (e) {
      _showErrorDialog('Error: $e');
    }
  }

  void _showWarningDialog(String url) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('URL Berbahaya'),
        content: Text('Website ini terdeteksi berbahaya atau mencurigakan.\n\n$url'),
        actions: <Widget>[
          TextButton(
            child: const Text('OK'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  void _showSafeDialog(String url) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Website Aman'),
        content: Text('Website ini aman untuk dikunjungi.\n\n$url'),
        actions: <Widget>[
          TextButton(
            child: const Text('Buka di Browser'),
            onPressed: () {
              Navigator.of(context).pop();
              _launchURL(url);
            },
          ),
          TextButton(
            child: const Text('Tutup'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  void _showErrorDialog(String message) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Error'),
        content: Text(message),
        actions: <Widget>[
          TextButton(
            child: const Text('OK'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  Future<void> _launchURL(String url) async {
    final Uri uri = Uri.parse(url);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri);
    } else {
      _showErrorDialog('Could not open the URL.');
    }
  }

  @override
  void dispose() {
    controller?.dispose();
    super.dispose();
  }
}