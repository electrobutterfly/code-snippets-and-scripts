<?php
//////////////////////////////////////////////////////////////////////
// fingerprint.php
// @copyright     (c) 2025 Klaus Simon
// @license       Custom Attribution-NonCommercial Sale License
// @description   PolyDefense - A Hybrid SSL Authentication System
//
// Permission is granted to use, modify, and distribute this script
// for any purpose except commercial sale without explicit permission.
// Attribution must be retained in all copies.
//
// For commercial licensing: licensing@electrobutterfly.com
// Full license: LICENSE file in repository
//////////////////////////////////////////////////////////////////////


if ($argc < 2) {
    echo "Usage: php generate_fingerprint.php <path_to_certificate>\n";
    exit(1);
}

$certPath = $argv[1];

if (!file_exists($certPath)) {
    echo "Error: Certificate file not found: $certPath\n";
    exit(1);
}

$certificate = file_get_contents($certPath);
if ($certificate === false) {
    echo "Error: Could not read certificate file\n";
    exit(1);
}

// Generate SHA256 fingerprint
$fingerprint = openssl_x509_fingerprint($certificate, 'sha256', false);

if ($fingerprint === false) {
    echo "Error: Invalid certificate format or could not generate fingerprint\n";
    exit(1);
}

// Extract Common Name (CN) from certificate
$certData = openssl_x509_parse($certificate);
$commonName = $certData['subject']['CN'] ?? 'Not found';

echo "==========================================\n";
echo "CLIENT CERTIFICATE FINGERPRINT\n";
echo "==========================================\n";
echo "Certificate: " . basename($certPath) . "\n";
echo "Common Name: " . $commonName . "\n";
echo "Algorithm: SHA256\n";
echo "Fingerprint: " . $fingerprint . "\n";
echo "==========================================\n";
echo "\nCopy this to your server configuration:\n";
echo "\$expectedClientCertFingerprint = '" . $fingerprint . "';\n";
echo "\$requiredClientCN = '" . $commonName . "';\n";
echo "==========================================\n";
?>
