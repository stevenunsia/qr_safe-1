import 'package:flutter/material.dart';
import 'package:qr_code_scanner/qr_code_scanner.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'dart:convert';
import 'package:logger/logger.dart';
import 'dart:io';

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
    const apiKey = 'a42713d726472bee6d829a171256c872e73be2e472e66a8022c29153a39f10ea';
    final apiUrl = 'https://www.virustotal.com/api/v3/urls';

    logger.d('Checking URL: $url');

    try {
      final postResponse = await http.post(
        Uri.parse(apiUrl),
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'url=$url',
      );

      logger.d('POST Response status: ${postResponse.statusCode}');
      logger.d('POST Response body: ${postResponse.body}');

      if (postResponse.statusCode == 200) {
        final jsonResponse = json.decode(postResponse.body);
        final resourceId = jsonResponse['data']['id']; 

        await Future.delayed(Duration(seconds: 10));

        await _getVirusTotalReport(resourceId, url);
      } else {
        _showErrorDialog('Gagal mengirim URL ke VirusTotal. Kode status: ${postResponse.statusCode}');
      }
    } on SocketException catch (e) {
      logger.e('SocketException: $e');
      _showErrorDialog('Network error: Tidak dapat menghubungi VirusTotal. Periksa koneksi internet Anda.');
    } catch (e) {
      logger.e('Exception: $e');
      _showErrorDialog('Error: $e');
    }
  }

  Future<void> _getVirusTotalReport(String resourceId, String url) async {
    const apiKey = 'a42713d726472bee6d829a171256c872e73be2e472e66a8022c29153a39f10ea';
    final reportUrl = 'https://www.virustotal.com/api/v3/analyses/$resourceId';

    try {
      final response = await http.get(
        Uri.parse(reportUrl),
        headers: {
          'x-apikey': apiKey,
        },
      );

      logger.d('GET Response status: ${response.statusCode}');
      logger.d('GET Response body: ${response.body}');

      if (response.statusCode == 200) {
        final jsonResponse = json.decode(response.body);
        final scanResult = jsonResponse['data']['attributes']['stats'];

        int malicious = scanResult['malicious'] ?? 0;
        int suspicious = scanResult['suspicious'] ?? 0;

        logger.d('Malicious: $malicious, Suspicious: $suspicious');

        if (malicious > 0 || suspicious > 0) {
          _showWarningDialog(url);
        } else {
          _showSafeDialog(url);
        }
      } else {
        _showErrorDialog('Gagal mendapatkan hasil dari VirusTotal.');
      }
    } catch (e) {
      _showErrorDialog('Error: $e');
    }
  }

  void _showWarningDialog(String url) {
    logger.d('Showing warning dialog for URL: $url');
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('URL Berbahaya'),
        content: Text('Website ini terdeteksi berbahaya atau mencurigakan.\n\n$url'),
        actions: <Widget>[
          TextButton(child: const Text('OK'), onPressed: () => Navigator.of(context).pop()),
        ],
      ),
    );
  }

  void _showSafeDialog(String url) {
    logger.d('Showing safe dialog for URL: $url');
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
    logger.d('Showing error dialog with message: $message');
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
    logger.d('Attempting to launch URL: $url');
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