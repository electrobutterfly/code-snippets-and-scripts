<?php
//////////////////////////////////////////////////////////////////////
// server.php
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

// ==========================================
// USER CONFIGURATION - UPDATE THESE VALUES!
// ==========================================

$serverPrivateKeyPath = $_ENV['AUTH_SERVER_PRIVATE_KEY_PATH'] ?? './keys/server.key'; // Place somewhere outside webroot
$clientPublicKeyPath = $_ENV['AUTH_CLIENT_PUBLIC_KEY_PATH'] ?? './keys/client.pub'; // Place somewhere outside webroot
$expectedClientCertFingerprint = $_ENV['AUTH_CLIENT_CERT_FINGERPRINT'] ?? 'a71b86718fee7539fe46cbc4bad12345dc0952530a5f6053a246997783e476f'; // SHA256 fingerprint of client certificate

// IP Access Control
$ipAccessControlEnabled = false; // Enable/disable IP whitelist
$allowedIPs = [
    '192.168.1.100',           // Single IP
    '10.0.0.0/24',             // CIDR block
    '172.16.0.0/16',           // Larger network block
    '127.0.0.1',               // Localhost
    '::1'                      // IPv6 localhost
];

// Certificate validation
$requiredClientCN = 'secure-client';                // Expected Common Name in client certificate
$checkCertificateExpiry = true;                     // Check if client certificate is expired

// Email alerts for certificate expiry
$emailAlertsEnabled = true;
$adminEmail = 'admin@yourdomain.com';
$emailFrom = 'certificate-monitor@yourdomain.com';
$emailSubject = '🚨 Certificate Expiry Alert';
$emailMethod = 'sendmail'; // Options: 'sendmail', 'smtp', 'mail'

$alertDaysThreshold = 30;  // Send alerts 30 days before expiry

// Rate limiting configuration
$maxRequestsPerMinute = 60;
$debugMode = true; // SET TO FALSE IN PRODUCTION!

// Storage configuration
$storagePath = './storage';                         // Secure storage directory
$maxStorageSize = 100 * 1024 * 1024;               // 100MB total storage limit
$maxFileCount = 10000;                             // Maximum 10,000 files
$maxFileSize = 100 * 1024;                         // 100KB per file limit
$cleanupThreshold = 0.8;                           // Cleanup at 80% capacity

// Challenge settings
$challengeTimeout = 59; // 59 seconds - syncs with rate limiting

// Security configuration
$maxJsonInputSize = 102400; // 100KB maximum JSON input size

// ==========================================
// HYBRID AUTHENTICATION - DON'T MODIFY BELOW
// ==========================================

// STRICT ERROR HANDLING - PREVENT JSON CORRUPTION
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

// Start output buffering with error checking
while (ob_get_level() > 0) {
    ob_end_clean();
}
ob_start();

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Content-Security-Policy: default-src \'self\'');
header('Referrer-Policy: no-referrer');
header('Content-Type: application/json; charset=UTF-8');

// Custom exceptions for better error handling
class AuthenticationException extends Exception {}
class RateLimitException extends Exception {}
class ValidationException extends Exception {}
class SecurityException extends Exception {}
class IPAccessException extends Exception {}
class ConfigurationException extends Exception {}

class IPAccessController {
    private $enabled;
    private $allowedIPs;
    
    public function __construct($enabled, $allowedIPs) {
        $this->enabled = $enabled;
        $this->allowedIPs = $allowedIPs;
    }
    
    public function checkAccess($ip) {
        if (!$this->enabled) {
            return true;
        }
        
        foreach ($this->allowedIPs as $allowed) {
            if ($this->ipMatches($ip, $allowed)) {
                return true;
            }
        }
        
        throw new IPAccessException("Access denied");
    }
    
    private function ipMatches($ip, $range) {
        if (strpos($range, '/') !== false) {
            // CIDR notation
            list($subnet, $bits) = explode('/', $range);
            $ip = ip2long($ip);
            $subnet = ip2long($subnet);
            if ($ip === false || $subnet === false) {
                return false;
            }
            $mask = -1 << (32 - $bits);
            return ($ip & $mask) == ($subnet & $mask);
        } else {
            // Single IP
            return $ip === $range;
        }
    }
}

// SECURITY: IP ACCESS CONTROL - FIRST LINE OF DEFENSE
try {
    $ipController = new IPAccessController($ipAccessControlEnabled, $allowedIPs);
    $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ipController->checkAccess($clientIP);
} catch (IPAccessException $e) {
    // Clear any output that might have been generated before IP check
    ob_clean();
    http_response_code(403);
    echo json_encode([
        'status' => 'error',
        'message' => 'Access denied'
    ]);
    exit;
}

// Security validation: Require certificate fingerprint in production
if (!$debugMode && empty($expectedClientCertFingerprint)) {
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Server configuration error'
    ]);
    exit;
}

// Validate fingerprint format if provided
if (!empty($expectedClientCertFingerprint) && !preg_match('/^[a-f0-9]{64}$/i', $expectedClientCertFingerprint)) {
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'status' => 'error', 
        'message' => 'Server configuration error'
    ]);
    exit;
}

// Rest of your classes remain exactly the same...
class SecurityValidator {
    public static function validateJsonInput($maxSize = 102400) {
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;
        
        if ($contentLength > $maxSize) {
            throw new ValidationException("Input too large");
        }
        
        $input = file_get_contents('php://input');
        
        if (strlen($input) > $maxSize) {
            throw new ValidationException("Input too large");
        }
        
        if (empty($input)) {
            throw new ValidationException("No input data received");
        }
        
        $data = json_decode($input, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ValidationException("Invalid JSON format");
        }
        
        return $data;
    }
    
    public static function validateSignature($signature) {
        if (empty($signature) || strlen($signature) > 1000) {
            throw new ValidationException("Invalid signature format");
        }
        
        if (!preg_match('/^[a-zA-Z0-9+\/]+={0,2}$/', $signature) || (strlen($signature) % 4 !== 0)) {
            throw new ValidationException("Invalid signature encoding");
        }
        
        return true;
    }
    
    public static function validateChallenge($challenge) {
        if (empty($challenge) || strlen($challenge) > 10000) {
            throw new ValidationException("Invalid challenge format");
        }
        
        if (!preg_match('/^[a-zA-Z0-9+\/]+={0,2}$/', $challenge) || (strlen($challenge) % 4 !== 0)) {
            throw new ValidationException("Invalid challenge encoding");
        }
        
        return true;
    }
    
    public static function validateCertificate($certificate) {
        if (empty($certificate)) {
            return null;
        }
        
        if (strlen($certificate) > 10000) {
            throw new ValidationException("Certificate too large");
        }
        
        // Basic PEM certificate validation
        if (!preg_match('/-----BEGIN CERTIFICATE-----/', $certificate)) {
            throw new ValidationException("Invalid certificate format");
        }
        
        return $certificate;
    }
}

class SecureStorageManager {
    private $storagePath;
    private $maxStorageSize;
    private $maxFileCount;
    private $maxFileSize;
    private $cleanupThreshold;
    private $debugMode;
    
    public function __construct($storagePath, $maxStorageSize = 100000000, $maxFileCount = 10000, $maxFileSize = 102400, $cleanupThreshold = 0.8, $debugMode = false) {
        $this->storagePath = $storagePath;
        $this->maxStorageSize = $maxStorageSize;
        $this->maxFileCount = $maxFileCount;
        $this->maxFileSize = $maxFileSize;
        $this->cleanupThreshold = $cleanupThreshold;
        $this->debugMode = $debugMode;
        
        $this->initializeStorage();
    }
    
    private function log($message) {
        if ($this->debugMode) {
            error_log("STORAGE_DEBUG: " . $message);
        }
    }
    
    private function initializeStorage() {
        if (!is_dir($this->storagePath)) {
            if (!mkdir($this->storagePath, 0700, true)) {
                throw new Exception("Failed to create storage directory: " . $this->storagePath);
            }
            $this->log("Created storage directory: " . $this->storagePath);
        }
        
        // Set secure permissions on directory
        if (is_dir($this->storagePath)) {
            if (!chmod($this->storagePath, 0700)) {
                throw new Exception("Failed to set secure permissions on storage directory");
            }
        }
        
        // Initialize secret file
        $this->initializeSecret();
        
        $this->log("Storage initialized: " . $this->storagePath);
        $this->log("Max storage: " . $this->format_bytes($this->maxStorageSize));
        $this->log("Max files: " . $this->maxFileCount);
        $this->log("Max file size: " . $this->format_bytes($this->maxFileSize));
    }
    
    private function initializeSecret() {
        $secretFile = $this->storagePath . '/.secret';
        if (!file_exists($secretFile)) {
            if (!function_exists('random_bytes')) {
                throw new Exception("Secure random generator unavailable");
            }
            
            $secret = bin2hex(random_bytes(32));
            if (file_put_contents($secretFile, $secret) === false) {
                throw new Exception("Failed to create secret file");
            }
            if (!chmod($secretFile, 0600)) {
                throw new Exception("Failed to set secure permissions on secret file");
            }
            $this->log("Generated new storage secret");
        }
    }
    
    public function writeFile($filename, $data, $compress = false) {
        $this->enforceStorageLimits();
        
        $filepath = $this->storagePath . '/' . $filename;
        
        // Validate filename to prevent directory traversal
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename: " . $filename);
        }
        
        // Check file size limit
        if (strlen($data) > $this->maxFileSize) {
            throw new ValidationException("File size exceeds limit: " . $this->format_bytes(strlen($data)) . " > " . $this->format_bytes($this->maxFileSize));
        }
        
        // Compress data if requested
        if ($compress && function_exists('gzcompress')) {
            $data = gzcompress($data, 9);
            $this->log("Compressed data: " . $this->format_bytes(strlen($data)));
        }
        
        // Add HMAC for integrity protection
        $hmac = hash_hmac('sha256', $data, $this->getStorageSecret());
        $fileData = json_encode([
            'data' => base64_encode($data),
            'hmac' => $hmac,
            'timestamp' => time(),
            'compressed' => $compress
        ]);
        
        // Write with file locking
        if ($fp = fopen($filepath, 'c+')) {
            if (flock($fp, LOCK_EX)) {
                ftruncate($fp, 0);
                fwrite($fp, $fileData);
                fflush($fp);
                flock($fp, LOCK_UN);
                $this->log("File written: " . $filename . " (" . $this->format_bytes(strlen($fileData)) . ")");
            } else {
                fclose($fp);
                throw new Exception("Failed to acquire lock for file: " . $filename);
            }
            fclose($fp);
        } else {
            throw new Exception("Failed to open file for writing: " . $filename);
        }
        
        return true;
    }
    
    public function readFile($filename) {
        $filepath = $this->storagePath . '/' . $filename;
        
        if (!file_exists($filepath)) {
            return null;
        }
        
        // Validate filename
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename: " . $filename);
        }
        
        // Read with file locking
        if ($fp = fopen($filepath, 'r')) {
            if (flock($fp, LOCK_SH)) {
                $fileData = file_get_contents($filepath);
                flock($fp, LOCK_UN);
            } else {
                fclose($fp);
                throw new Exception("Failed to acquire lock for reading: " . $filename);
            }
            fclose($fp);
        } else {
            throw new Exception("Failed to open file for reading: " . $filename);
        }
        
        $data = json_decode($fileData, true);
        if (!$data || !isset($data['data']) || !isset($data['hmac'])) {
            $this->log("Corrupted file detected: " . $filename);
            unlink($filepath);
            return null;
        }
        
        // Verify HMAC
        $expectedHmac = hash_hmac('sha256', $data['data'], $this->getStorageSecret());
        if (!hash_equals($data['hmac'], $expectedHmac)) {
            $this->log("HMAC verification failed for file: " . $filename);
            unlink($filepath);
            return null;
        }
        
        $content = base64_decode($data['data']);
        
        // Decompress if needed
        if (isset($data['compressed']) && $data['compressed'] && function_exists('gzuncompress')) {
            $content = gzuncompress($content);
        }
        
        $this->log("File read: " . $filename . " (" . $this->format_bytes(strlen($content)) . ")");
        return $content;
    }
    
    public function deleteFile($filename) {
        $filepath = $this->storagePath . '/' . $filename;
        
        if (file_exists($filepath)) {
            if (unlink($filepath)) {
                $this->log("File deleted: " . $filename);
                return true;
            } else {
                throw new Exception("Failed to delete file: " . $filename);
            }
        }
        return false;
    }
    
    public function fileExists($filename) {
        $filepath = $this->storagePath . '/' . $filename;
        return file_exists($filepath);
    }
    
    public function enforceStorageLimits() {
        $usage = $this->getStorageUsage();
        
        $this->log("Storage usage: " . $this->format_bytes($usage['total_size']) . " / " . 
                  $this->format_bytes($this->maxStorageSize) . " (" . 
                  round(($usage['total_size'] / $this->maxStorageSize) * 100, 2) . "%), " . 
                  $usage['file_count'] . " / " . $this->maxFileCount . " files");
        
        // Check if we need to cleanup
        if ($usage['total_size'] > ($this->maxStorageSize * $this->cleanupThreshold) || 
            $usage['file_count'] > ($this->maxFileCount * $this->cleanupThreshold)) {
            $this->log("Storage threshold exceeded, starting cleanup...");
            $this->cleanup();
        }
        
        // Hard limits - reject if exceeded
        if ($usage['total_size'] > $this->maxStorageSize) {
            throw new Exception("Storage limit exceeded: " . $this->format_bytes($usage['total_size']) . " > " . $this->format_bytes($this->maxStorageSize));
        }
        
        if ($usage['file_count'] > $this->maxFileCount) {
            throw new Exception("File count limit exceeded: " . $usage['file_count'] . " > " . $this->maxFileCount);
        }
    }
    
    public function cleanup() {
        $files = [];
        $iterator = new DirectoryIterator($this->storagePath);
        
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile() && $fileinfo->getFilename() !== '.secret') {
                $files[] = [
                    'filename' => $fileinfo->getFilename(),
                    'mtime' => $fileinfo->getMTime(),
                    'size' => $fileinfo->getSize()
                ];
            }
        }
        
        // Sort by modification time (oldest first)
        usort($files, function($a, $b) {
            return $a['mtime'] - $b['mtime'];
        });
        
        $deletedCount = 0;
        $deletedSize = 0;
        $usage = $this->getStorageUsage();
        
        // Delete oldest files until we're below 50% capacity
        $targetSize = $this->maxStorageSize * 0.5;
        $targetCount = $this->maxFileCount * 0.5;
        
        foreach ($files as $file) {
            if ($usage['total_size'] <= $targetSize && $usage['file_count'] <= $targetCount) {
                break;
            }
            
            if ($this->deleteFile($file['filename'])) {
                $deletedCount++;
                $deletedSize += $file['size'];
                $usage['total_size'] -= $file['size'];
                $usage['file_count']--;
            }
        }
        
        if ($deletedCount > 0) {
            $this->log("Cleanup completed: deleted " . $deletedCount . " files (" . $this->format_bytes($deletedSize) . ")");
        }
        
        return $deletedCount;
    }
    
    public function getStorageUsage() {
        $totalSize = 0;
        $fileCount = 0;
        
        if (!is_dir($this->storagePath)) {
            return ['total_size' => 0, 'file_count' => 0];
        }
        
        $iterator = new DirectoryIterator($this->storagePath);
        
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile()) {
                $totalSize += $fileinfo->getSize();
                $fileCount++;
            }
        }
        
        return [
            'total_size' => $totalSize,
            'file_count' => $fileCount
        ];
    }
    
    public function getStorageInfo() {
        $usage = $this->getStorageUsage();
        return [
            'path' => $this->storagePath,
            'max_size' => $this->maxStorageSize,
            'max_files' => $this->maxFileCount,
            'current_size' => $usage['total_size'],
            'current_files' => $usage['file_count'],
            'usage_percent' => ($usage['total_size'] / $this->maxStorageSize) * 100,
            'file_usage_percent' => ($usage['file_count'] / $this->maxFileCount) * 100
        ];
    }
    
    private function isValidFilename($filename) {
        // Prevent directory traversal and ensure safe filenames
        return preg_match('/^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*$/', $filename) && 
               strpos($filename, '..') === false &&
               strpos($filename, '/') === false &&
               strpos($filename, '\\') === false;
    }
    
    private function getStorageSecret() {
        $secretFile = $this->storagePath . '/.secret';
        if (!file_exists($secretFile)) {
            throw new SecurityException("Storage secret not found");
        }
        
        $secret = file_get_contents($secretFile);
        if ($secret === false) {
            throw new SecurityException("Failed to read storage secret");
        }
        
        return hash('sha256', $secret, true);
    }
    
    private function format_bytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
}

class HybridAuthenticator {
    private $serverPrivateKeyPath;
    private $clientPublicKeyPath;
    private $requiredClientCN;
    private $checkExpiry;
    private $debugMode;
    private $expectedClientCertFingerprint;
    private $challengeTimeout;
    
    public function __construct($serverPrivateKeyPath, $clientPublicKeyPath, $requiredClientCN, $expectedClientCertFingerprint = '', $checkExpiry = true, $debugMode = false, $challengeTimeout = 300) {
        $this->serverPrivateKeyPath = $serverPrivateKeyPath;
        $this->clientPublicKeyPath = $clientPublicKeyPath;
        $this->requiredClientCN = $requiredClientCN;
        $this->expectedClientCertFingerprint = $expectedClientCertFingerprint;
        $this->checkExpiry = $checkExpiry;
        $this->debugMode = $debugMode;
        $this->challengeTimeout = $challengeTimeout;
        
        // Validate configuration in production mode
        if (!$debugMode && !empty($expectedClientCertFingerprint) && !preg_match('/^[a-f0-9]{64}$/i', $expectedClientCertFingerprint)) {
            throw new ConfigurationException("Invalid client certificate fingerprint format in production mode");
        }
    }
    
    private function log($message) {
        if ($this->debugMode) {
            error_log("HYBRID_AUTH_DEBUG: " . $message);
        }
    }
    
    public function generateChallenge() {
        $this->log("Generating challenge");
        
        if (!function_exists('random_bytes')) {
            throw new SecurityException("Secure random generator unavailable");
        }
        
        $randomChallenge = bin2hex(random_bytes(32));
        $timestamp = time();
        $expires = $timestamp + $this->challengeTimeout;
        
        $challengeData = [
            'challenge' => $randomChallenge,
            'timestamp' => $timestamp,
            'expires' => $expires,
            'server_id' => 'auth-server'
        ];
        
        // Sign the challenge with server's private key
        $challengeString = $randomChallenge . '|' . $timestamp . '|' . $expires . '|' . 'auth-server';
        $signature = $this->signData($challengeString, $this->serverPrivateKeyPath);
        $challengeData['signature'] = $signature;
        
        // Add HMAC for additional integrity protection
        $hmacKey = hash('sha256', $randomChallenge . $timestamp, true);
        
        // Create consistent data structure for HMAC (exclude monitoring fields)
        $dataForHmac = [
            'challenge' => $randomChallenge,
            'timestamp' => $timestamp,
            'expires' => $expires,
            'server_id' => 'auth-server',
            'signature' => $signature
        ];
        
        $hmac = hash_hmac('sha256', json_encode($dataForHmac), $hmacKey);
        $challengeData['hmac'] = $hmac;
        
        // Add monitoring data AFTER HMAC calculation (not included in HMAC)
        $challengeData['generation_microtime'] = microtime(true);
        
        $this->log("Challenge generated: " . $randomChallenge);
        
        return base64_encode(json_encode($challengeData));
    }
    
    public function verifyChallengeResponse($encodedChallenge, $clientSignature, $clientCertificate = null) {
        $this->log("Verifying challenge response");
        
        SecurityValidator::validateChallenge($encodedChallenge);
        SecurityValidator::validateSignature($clientSignature);
        
        if ($clientCertificate) {
            $clientCertificate = SecurityValidator::validateCertificate($clientCertificate);
        }
        
        // Decode the challenge data
        $challengeJson = base64_decode($encodedChallenge);
        if ($challengeJson === false) {
            throw new ValidationException("Failed to base64 decode challenge");
        }
        
        $challengeData = json_decode($challengeJson, true);
        if (!$challengeData) {
            throw new ValidationException("Invalid challenge format");
        }
        
        // Verify HMAC integrity
        if (!isset($challengeData['hmac'])) {
            throw new ValidationException("Missing HMAC in challenge");
        }
        
        $receivedHmac = $challengeData['hmac'];
        
        // Use same data structure as generation (exclude monitoring fields)
        $dataForHmac = [
            'challenge' => $challengeData['challenge'],
            'timestamp' => $challengeData['timestamp'],
            'expires' => $challengeData['expires'],
            'server_id' => $challengeData['server_id'],
            'signature' => $challengeData['signature']
        ];
        
        $hmacKey = hash('sha256', $challengeData['challenge'] . $challengeData['timestamp'], true);
        $expectedHmac = hash_hmac('sha256', json_encode($dataForHmac), $hmacKey);
        
        if (!hash_equals($receivedHmac, $expectedHmac)) {
            $this->log("HMAC verification failed. Expected: " . $expectedHmac . ", Got: " . $receivedHmac);
            throw new ValidationException("Challenge integrity check failed");
        }
        
        // Verify challenge hasn't expired
        if (time() > $challengeData['expires']) {
            throw new ValidationException("Challenge expired");
        }
        
        // Verify server signature on challenge
        $challengeString = $challengeData['challenge'] . '|' . $challengeData['timestamp'] . '|' . $challengeData['expires'] . '|' . $challengeData['server_id'];
        if (!$this->verifySignature($challengeString, $challengeData['signature'])) {
            throw new ValidationException("Invalid challenge signature");
        }
        
        // TIMING MONITORING: Calculate challenge lifecycle (only if monitoring data exists)
        if (isset($challengeData['generation_microtime'])) {
            $verificationTime = microtime(true);
            $totalTime = $verificationTime - $challengeData['generation_microtime'];
            
            $this->log("Challenge lifecycle: " . round($totalTime, 2) . " seconds");
            
            // Track near-expirations
            $timeRemaining = $challengeData['expires'] - time();
            if ($timeRemaining < ($this->challengeTimeout * 0.25)) {
                $this->log("WARNING: Challenge used with only " . $timeRemaining . " seconds remaining");
            }
        }
        
        $this->log("Challenge verified: " . $challengeData['challenge']);
        
        // Verify client signature on challenge
        if ($clientCertificate) {
            // Verify using client certificate with fingerprint validation
            $this->verifyWithCertificate($challengeData['challenge'], $clientSignature, $clientCertificate);
        } else {
            // Verify using client public key file
            $this->verifyWithPublicKey($challengeData['challenge'], $clientSignature, $this->clientPublicKeyPath);
        }
        
        $this->log("Client authentication successful");
        return $challengeData['challenge'];
    }
    
    private function verifyWithCertificate($challenge, $signature, $clientCertificatePem) {
        $this->log("Verifying with client certificate");
        
        $certInfo = openssl_x509_parse($clientCertificatePem);
        if ($certInfo === false) {
            throw new ValidationException("Failed to parse client certificate");
        }
        
        // Check Common Name
        $clientCN = $certInfo['subject']['CN'] ?? '';
        if (empty($clientCN) || $clientCN !== $this->requiredClientCN) {
            throw new AuthenticationException("Client Common Name mismatch. Expected: " . $this->requiredClientCN . ", Got: " . $clientCN);
        }
        
        // Check certificate fingerprint if configured
        if (!empty($this->expectedClientCertFingerprint)) {
            $certFingerprint = openssl_x509_fingerprint($clientCertificatePem, 'sha256', false);
            if (!hash_equals(strtolower($this->expectedClientCertFingerprint), strtolower($certFingerprint))) {
                throw new AuthenticationException("Client certificate fingerprint mismatch");
            }
            $this->log("Certificate fingerprint verified");
        }
        
        // Check certificate expiry if enabled
        if ($this->checkExpiry) {
            $currentTime = time();
            if ($currentTime < $certInfo['validFrom_time_t']) {
                throw new AuthenticationException("Client certificate is not yet valid");
            }
            if ($currentTime > $certInfo['validTo_time_t']) {
                throw new AuthenticationException("Client certificate has expired");
            }
        }
        
        // Verify signature with certificate's public key
        $publicKey = openssl_pkey_get_public($clientCertificatePem);
        if (!$publicKey) {
            throw new AuthenticationException("Failed to extract public key from certificate");
        }
        
        $result = openssl_verify($challenge, base64_decode($signature), $publicKey, OPENSSL_ALGO_SHA256);
        openssl_pkey_free($publicKey);
        
        if ($result !== 1) {
            throw new AuthenticationException("Invalid client signature");
        }
        
        return true;
    }
    
    private function verifyWithPublicKey($challenge, $signature, $publicKeyPath) {
        $this->log("Verifying with client public key");
        
        if (!file_exists($publicKeyPath)) {
            throw new AuthenticationException("Client public key not found: " . $publicKeyPath);
        }
        
        $publicKey = openssl_pkey_get_public("file://" . $publicKeyPath);
        if (!$publicKey) {
            throw new AuthenticationException("Failed to load client public key");
        }
        
        $result = openssl_verify($challenge, base64_decode($signature), $publicKey, OPENSSL_ALGO_SHA256);
        openssl_pkey_free($publicKey);
        
        if ($result !== 1) {
            throw new AuthenticationException("Invalid client signature");
        }
        
        return true;
    }
    
    private function signData($data, $privateKeyPath) {
        $privateKey = openssl_pkey_get_private("file://" . $privateKeyPath);
        if (!$privateKey) {
            throw new SecurityException("Failed to load private key for signing");
        }
        
        $signature = '';
        $success = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        openssl_pkey_free($privateKey);
        
        if (!$success) {
            throw new SecurityException("Failed to sign data");
        }
        
        return base64_encode($signature);
    }
    
    private function verifySignature($data, $signature) {
        // Use server's public key for signature verification (not private key)
        $publicKey = openssl_pkey_get_public("file://" . $this->serverPrivateKeyPath);
        if (!$publicKey) {
            // Try to extract public key from private key
            $privateKey = openssl_pkey_get_private("file://" . $this->serverPrivateKeyPath);
            if (!$privateKey) {
                throw new SecurityException("Failed to load server key for verification");
            }
            
            $keyDetails = openssl_pkey_get_details($privateKey);
            $publicKey = openssl_pkey_get_public($keyDetails['key']);
            openssl_pkey_free($privateKey);
        }
        
        if (!$publicKey) {
            throw new SecurityException("Failed to extract public key for verification");
        }
        
        $result = openssl_verify($data, base64_decode($signature), $publicKey, OPENSSL_ALGO_SHA256);
        openssl_pkey_free($publicKey);
        
        return $result === 1;
    }
}

class CertificateExpiryMonitor {
    private $adminEmail;
    private $alertThreshold;
    private $debugMode;
    private $emailFrom;
    private $emailSubject;
    private $lastAlertSent = [];
    
    public function __construct($adminEmail, $alertThreshold = 30, $debugMode = false, $emailFrom = '', $emailSubject = '') {
        $this->adminEmail = $adminEmail;
        $this->alertThreshold = $alertThreshold;
        $this->debugMode = $debugMode;
        $this->emailFrom = $emailFrom;
        $this->emailSubject = $emailSubject ?: '🚨 Certificate Expiry Alert';
    }
    
    private function log($message) {
        if ($this->debugMode) {
            error_log("CERT_MONITOR_DEBUG: " . $message);
        }
    }
    
    public function checkAndAlert($certificatePem, $clientId) {
        $certInfo = openssl_x509_parse($certificatePem);
        if ($certInfo === false) {
            $this->log("Failed to parse certificate for expiry check");
            return false;
        }
        
        $currentTime = time();
        $validTo = $certInfo['validTo_time_t'];
        $daysUntilExpiry = floor(($validTo - $currentTime) / (60 * 60 * 24));
        
        $this->log("Certificate for " . $clientId . " expires in " . $daysUntilExpiry . " days");
        
        if ($daysUntilExpiry <= $this->alertThreshold) {
            $alertKey = $clientId . '_' . date('Y-m-d');
            
            if (!isset($this->lastAlertSent[$alertKey])) {
                $this->sendExpiryAlert($certInfo, $clientId, $daysUntilExpiry);
                $this->lastAlertSent[$alertKey] = true;
                return true;
            }
        }
        
        return false;
    }
    
    private function sendExpiryAlert($certInfo, $clientId, $daysUntilExpiry) {
        $subject = $this->emailSubject . ": " . $clientId;
        $validTo = date('Y-m-d H:i:s', $certInfo['validTo_time_t']);
        $serial = $certInfo['serialNumber'];
        $from = $this->emailFrom ?: 'certificate-monitor@yourdomain.com';
        
        $message = "
Certificate Expiry Alert

Client ID: {$clientId}
Serial Number: {$serial}
Expiry Date: {$validTo}
Days Until Expiry: {$daysUntilExpiry}

This certificate will expire soon. Please renew it to avoid service disruption.

Generated by: PolyDefense Authentication System
Time: " . date('Y-m-d H:i:s') . "
        ";
        
        if ($this->debugMode) {
            $this->log("WOULD SEND EMAIL ALERT: " . $subject);
            $this->log("Message: " . $message);
        } else {
            $headers = "From: {$from}\r\n";
            $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
            mail($this->adminEmail, $subject, $message, $headers);
        }
        
        $this->log("Expiry alert sent for certificate: " . $clientId);
    }
}

class RequestRateLimiter {
    private $maxRequests;
    private $timeWindow;
    private $storageManager;
    private $successfulAuths = [];
    
    public function __construct($maxRequests = 60, $timeWindow = 60, $storageManager = null) {
        $this->maxRequests = $maxRequests;
        $this->timeWindow = $timeWindow;
        $this->storageManager = $storageManager;
    }
    
    public function isAllowed($identifier, $isAuthAttempt = false) {
        // Don't count successful authentication attempts against rate limit
        if ($isAuthAttempt && $this->isRecentlyAuthenticated($identifier)) {
            return true;
        }
        
        $filename = $this->getFilename($identifier);
        $requests = [];
        
        if ($this->storageManager->fileExists($filename)) {
            $data = $this->storageManager->readFile($filename);
            if ($data) {
                $requests = json_decode($data, true) ?: [];
            }
        }
        
        $currentTime = time();
        $requests = array_filter($requests, function($time) use ($currentTime) {
            return ($currentTime - $time) < $this->timeWindow;
        });
        
        if (count($requests) >= $this->maxRequests) {
            return false;
        }
        
        // Only record the request if it's not a successful auth
        if (!$isAuthAttempt || !$this->isRecentlyAuthenticated($identifier)) {
            $requests[] = time();
            $this->storageManager->writeFile($filename, json_encode($requests));
        }
        
        return true;
    }
    
    public function recordSuccessfulAuth($identifier) {
        $this->successfulAuths[$identifier] = time();
        // Clean up old entries
        $this->cleanupAuthRecords();
    }
    
    private function isRecentlyAuthenticated($identifier) {
        $this->cleanupAuthRecords();
        return isset($this->successfulAuths[$identifier]) && 
               (time() - $this->successfulAuths[$identifier]) < 300; // 5 minutes
    }
    
    private function cleanupAuthRecords() {
        $currentTime = time();
        foreach ($this->successfulAuths as $identifier => $timestamp) {
            if (($currentTime - $timestamp) > 300) { // 5 minutes
                unset($this->successfulAuths[$identifier]);
            }
        }
    }
    
    public function getRemainingRequests($identifier, $isAuthAttempt = false) {
        // If this is an auth attempt and recently authenticated, return max
        if ($isAuthAttempt && $this->isRecentlyAuthenticated($identifier)) {
            return $this->maxRequests;
        }
        
        $filename = $this->getFilename($identifier);
        $requests = [];
        
        if ($this->storageManager->fileExists($filename)) {
            $data = $this->storageManager->readFile($filename);
            if ($data) {
                $requests = json_decode($data, true) ?: [];
            }
        }
        
        $currentTime = time();
        $requests = array_filter($requests, function($time) use ($currentTime) {
            return ($currentTime - $time) < $this->timeWindow;
        });
        
        return max(0, $this->maxRequests - count($requests));
    }
    
    private function getFilename($identifier) {
        return 'rate_limit_' . md5($identifier) . '.dat';
    }
}

function log_message($message, $debugMode) {
    if ($debugMode) {
        error_log("HYBRID_AUTH_DEBUG: " . $message);
    }
}

function format_bytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

// MAIN REQUEST HANDLING
try {
    // Clear any output buffer before starting
    ob_clean();

    // TIMING STATS DEBUG ENDPOINT
    if ($debugMode && isset($_GET['action']) && $_GET['action'] == 'timing_stats') {
        $stats = [
            'challenge_timeout' => $challengeTimeout,
            'rate_limit' => $maxRequestsPerMinute,
            'recommended_max_client_time' => $challengeTimeout - 10,
            'timestamp' => time(),
            'server_time' => date('Y-m-d H:i:s'),
            'timezone' => date_default_timezone_get(),
            'ip_access_control_enabled' => $ipAccessControlEnabled,
            'allowed_ips_count' => count($allowedIPs)
        ];
        echo json_encode($stats, JSON_PRETTY_PRINT);
        exit;
    }

    // Initialize secure storage manager
    $storageManager = new SecureStorageManager(
        $storagePath,
        $maxStorageSize,
        $maxFileCount,
        $maxFileSize,
        $cleanupThreshold,
        $debugMode
    );
    
    // Log storage info in debug mode
    if ($debugMode) {
        $storageInfo = $storageManager->getStorageInfo();
        log_message("=== STORAGE INFORMATION ===", $debugMode);
        log_message("Storage Path: " . $storageInfo['path'], $debugMode);
        log_message("Current Usage: " . round($storageInfo['usage_percent'], 2) . "% (" . 
                   $storageInfo['current_files'] . " files)", $debugMode);
        log_message("File Usage: " . round($storageInfo['file_usage_percent'], 2) . "%", $debugMode);
        log_message("=== END STORAGE INFORMATION ===", $debugMode);
    }
    
    // Initialize rate limiter with storage manager
    $rateLimiter = new RequestRateLimiter($maxRequestsPerMinute, 60, $storageManager);
    
    // Create enhanced client identifier with IP and User-Agent
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $clientIdentifier = md5($clientIP . '|' . $userAgent);
    
    // Initialize authenticator with certificate fingerprint validation
    $authenticator = new HybridAuthenticator(
        $serverPrivateKeyPath,
        $clientPublicKeyPath,
        $requiredClientCN,
        $expectedClientCertFingerprint,
        $checkCertificateExpiry,
        $debugMode,
        $challengeTimeout
    );
    
    // Initialize expiry monitor
    $expiryMonitor = new CertificateExpiryMonitor(
        $adminEmail,
        $alertDaysThreshold,
        $debugMode,
        $emailFrom,
        $emailSubject
    );
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Check rate limiting for challenge requests
        if (!$rateLimiter->isAllowed($clientIdentifier, false)) {
            throw new RateLimitException("Too many challenge requests. Please slow down.");
        }
        
        log_message("Challenge requested from IP: " . $clientIP . " (ID: " . $clientIdentifier . ")", $debugMode);
        
        $encodedChallenge = $authenticator->generateChallenge();
        
        // Ensure clean output
        ob_clean();
        echo json_encode([
            'status' => 'challenge',
            'challenge' => $encodedChallenge,
            'remaining_attempts' => $rateLimiter->getRemainingRequests($clientIdentifier, false),
            'challenge_timeout' => $challengeTimeout
        ], JSON_PRETTY_PRINT);
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        log_message("Authentication attempt from IP: " . $clientIP . " (ID: " . $clientIdentifier . ")", $debugMode);
        
        // Use SecurityValidator for secure input validation
        $input = SecurityValidator::validateJsonInput($maxJsonInputSize);
        
        $signature = $input['signature'] ?? '';
        $encodedChallenge = $input['challenge'] ?? '';
        $clientCertificate = $input['certificate'] ?? null;
        
        if (empty($signature) || empty($encodedChallenge)) {
            throw new ValidationException("Missing required authentication data");
        }
        
        // Check rate limiting for authentication attempts
        if (!$rateLimiter->isAllowed($clientIdentifier, true)) {
            throw new RateLimitException("Too many authentication attempts. Please slow down.");
        }
        
        // Verify the challenge response
        $challenge = $authenticator->verifyChallengeResponse($encodedChallenge, $signature, $clientCertificate);
        
        // Record successful authentication (won't count against rate limit for a while)
        $rateLimiter->recordSuccessfulAuth($clientIdentifier);
        
        // Check certificate expiry and send alert if needed
        if ($emailAlertsEnabled && $clientCertificate) {
            $expiryMonitor->checkAndAlert($clientCertificate, $requiredClientCN);
        }
        
        log_message("Authentication SUCCESS for IP: " . $clientIP . " (ID: " . $clientIdentifier . ")", $debugMode);
        
        // Ensure clean output
        ob_clean();
        echo json_encode([
            'status' => 'success',
            'data' => [
                'message' => 'Hybrid authentication successful!',
                'client_id' => $requiredClientCN,
                'timestamp' => time(),
                'remaining_attempts' => $rateLimiter->getRemainingRequests($clientIdentifier, true)
            ]
        ], JSON_PRETTY_PRINT);
        
    } else {
        ob_clean();
        http_response_code(405);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Method not allowed'
        ], JSON_PRETTY_PRINT);
    }
    
} catch (RateLimitException $e) {
    ob_clean();
    http_response_code(429);
    $errorMessage = $debugMode ? $e->getMessage() : "Rate limit exceeded";
    $response = ['status' => 'error', 'message' => $errorMessage];
    
    if (isset($rateLimiter) && isset($clientIdentifier)) {
        $response['remaining_attempts'] = $rateLimiter->getRemainingRequests($clientIdentifier, true);
    }
    
    echo json_encode($response, JSON_PRETTY_PRINT);
} catch (AuthenticationException $e) {
    ob_clean();
    http_response_code(401);
    $errorMessage = $debugMode ? $e->getMessage() : "Authentication failed";
    $response = ['status' => 'error', 'message' => $errorMessage];
    
    if (isset($rateLimiter) && isset($clientIdentifier)) {
        $response['remaining_attempts'] = $rateLimiter->getRemainingRequests($clientIdentifier, true);
    }
    
    echo json_encode($response, JSON_PRETTY_PRINT);
} catch (ValidationException $e) {
    ob_clean();
    http_response_code(400);
    $errorMessage = $debugMode ? $e->getMessage() : "Invalid request";
    $response = ['status' => 'error', 'message' => $errorMessage];
    echo json_encode($response, JSON_PRETTY_PRINT);
} catch (ConfigurationException $e) {
    ob_clean();
    http_response_code(500);
    $errorMessage = $debugMode ? $e->getMessage() : "Server configuration error";
    $response = ['status' => 'error', 'message' => $errorMessage];
    echo json_encode($response, JSON_PRETTY_PRINT);
} catch (Exception $e) {
    ob_clean();
    http_response_code(500);
    $errorMessage = $debugMode ? $e->getMessage() : "Internal server error";
    $response = ['status' => 'error', 'message' => $errorMessage];
    echo json_encode($response, JSON_PRETTY_PRINT);
}

exit;
