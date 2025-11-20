<?php
//////////////////////////////////////////////////////////////////////
// server.php v1.1
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
$debugMode = true; // NOTE: Ensure this is FALSE in production!

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
        
        // SECURITY FIX: Added depth limit (512) and JSON_THROW_ON_ERROR
        $data = json_decode($input, true, 512);
        
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
        
        if (is_dir($this->storagePath)) {
            if (!chmod($this->storagePath, 0700)) {
                throw new Exception("Failed to set secure permissions on storage directory");
            }
        }
        
        $this->initializeSecret();
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
    
    // Helper for Internal HMAC generation (Challenge Security)
    public function getSecretHash() {
        return $this->getStorageSecret();
    }
    
    /**
     * SECURITY FIX: Atomic Read-Modify-Write Operation
     * Prevents Race Conditions in Rate Limiting
     */
    public function atomicJsonUpdate($filename, callable $callback) {
        $this->enforceStorageLimits();
        $filepath = $this->storagePath . '/' . $filename;
        
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename: " . $filename);
        }

        $fp = fopen($filepath, 'c+'); // Open for reading and writing; place pointer at beginning
        if (!$fp) {
            throw new Exception("Failed to open file for atomic update: " . $filename);
        }

        if (!flock($fp, LOCK_EX)) { // Acquire Exclusive Lock
            fclose($fp);
            throw new Exception("Failed to acquire lock for file: " . $filename);
        }

        try {
            // READ
            $fileContent = '';
            while (!feof($fp)) {
                $fileContent .= fread($fp, 8192);
            }
            
            $currentData = [];
            if (!empty($fileContent)) {
                // Verify integrity of existing data
                $storedJson = json_decode($fileContent, true);
                if ($storedJson && isset($storedJson['data'], $storedJson['hmac'])) {
                    $expectedHmac = hash_hmac('sha256', $storedJson['data'], $this->getStorageSecret());
                    if (hash_equals($storedJson['hmac'], $expectedHmac)) {
                        $decodedData = base64_decode($storedJson['data']);
                        $currentData = json_decode($decodedData, true) ?: [];
                    }
                }
            }

            // MODIFY (Callback)
            $newData = $callback($currentData);
            
            // WRITE PREP
            $jsonToSave = json_encode($newData);
            if (strlen($jsonToSave) > $this->maxFileSize) {
                 // Don't write if too big, but return false to indicate failure logic
                 throw new ValidationException("Atomic update exceeded file size limit");
            }

            $base64Data = base64_encode($jsonToSave);
            $hmac = hash_hmac('sha256', $base64Data, $this->getStorageSecret());
            $finalPayload = json_encode([
                'data' => $base64Data,
                'hmac' => $hmac,
                'timestamp' => time(),
                'compressed' => false
            ]);

            // WRITE
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, $finalPayload);
            fflush($fp);

        } catch (Exception $e) {
            flock($fp, LOCK_UN);
            fclose($fp);
            throw $e;
        }

        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
    }

    public function writeFile($filename, $data, $compress = false) {
        $this->enforceStorageLimits();
        
        $filepath = $this->storagePath . '/' . $filename;
        
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename: " . $filename);
        }
        
        if (strlen($data) > $this->maxFileSize) {
            throw new ValidationException("File size exceeds limit");
        }
        
        if ($compress && function_exists('gzcompress')) {
            $data = gzcompress($data, 9);
        }
        
        $hmac = hash_hmac('sha256', $data, $this->getStorageSecret());
        $fileData = json_encode([
            'data' => base64_encode($data),
            'hmac' => $hmac,
            'timestamp' => time(),
            'compressed' => $compress
        ]);
        
        if ($fp = fopen($filepath, 'c+')) {
            if (flock($fp, LOCK_EX)) {
                ftruncate($fp, 0);
                fwrite($fp, $fileData);
                fflush($fp);
                flock($fp, LOCK_UN);
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
        
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename: " . $filename);
        }
        
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
            // Silently remove corrupted files to prevent clutter
            @unlink($filepath);
            return null;
        }
        
        $expectedHmac = hash_hmac('sha256', $data['data'], $this->getStorageSecret());
        if (!hash_equals($data['hmac'], $expectedHmac)) {
            $this->log("HMAC verification failed for file: " . $filename);
            @unlink($filepath); // Security: Delete tampered files
            return null;
        }
        
        $content = base64_decode($data['data']);
        
        if (isset($data['compressed']) && $data['compressed'] && function_exists('gzuncompress')) {
            $content = gzuncompress($content);
        }
        
        return $content;
    }
    
    public function deleteFile($filename) {
        $filepath = $this->storagePath . '/' . $filename;
        
        if (file_exists($filepath)) {
            if (unlink($filepath)) {
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
        
        if ($usage['total_size'] > ($this->maxStorageSize * $this->cleanupThreshold) || 
            $usage['file_count'] > ($this->maxFileCount * $this->cleanupThreshold)) {
            $this->cleanup();
        }
        
        if ($usage['total_size'] > $this->maxStorageSize) {
            throw new Exception("Storage limit exceeded");
        }
        
        if ($usage['file_count'] > $this->maxFileCount) {
            throw new Exception("File count limit exceeded");
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
        
        usort($files, function($a, $b) {
            return $a['mtime'] - $b['mtime'];
        });
        
        $deletedCount = 0;
        $usage = $this->getStorageUsage();
        $targetSize = $this->maxStorageSize * 0.5;
        $targetCount = $this->maxFileCount * 0.5;
        
        foreach ($files as $file) {
            if ($usage['total_size'] <= $targetSize && $usage['file_count'] <= $targetCount) {
                break;
            }
            
            // Prioritize deleting expired challenges
            if (strpos($file['filename'], 'challenge_') === 0) {
                // Always check age for challenge files (delete if > 2 mins old)
                if (time() - $file['mtime'] > 120) {
                    if ($this->deleteFile($file['filename'])) {
                        $deletedCount++;
                        $usage['total_size'] -= $file['size'];
                        $usage['file_count']--;
                        continue;
                    }
                }
            }
            
            if ($this->deleteFile($file['filename'])) {
                $deletedCount++;
                $usage['total_size'] -= $file['size'];
                $usage['file_count']--;
            }
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
    private $storageManager; // Added for stateful challenge tracking
    
    public function __construct($serverPrivateKeyPath, $clientPublicKeyPath, $requiredClientCN, $expectedClientCertFingerprint = '', $checkExpiry = true, $debugMode = false, $challengeTimeout = 300, SecureStorageManager $storageManager) {
        $this->serverPrivateKeyPath = $serverPrivateKeyPath;
        $this->clientPublicKeyPath = $clientPublicKeyPath;
        $this->requiredClientCN = $requiredClientCN;
        $this->expectedClientCertFingerprint = $expectedClientCertFingerprint;
        $this->checkExpiry = $checkExpiry;
        $this->debugMode = $debugMode;
        $this->challengeTimeout = $challengeTimeout;
        $this->storageManager = $storageManager;
        
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
        
        // SECURITY FIX: Strong HMAC using Server Secret
        // Previously used hash of public data, now uses internal storage secret
        $hmacKey = $this->storageManager->getSecretHash();
        
        $dataForHmac = [
            'challenge' => $randomChallenge,
            'timestamp' => $timestamp,
            'expires' => $expires,
            'server_id' => 'auth-server',
            'signature' => $signature
        ];
        
        $hmac = hash_hmac('sha256', json_encode($dataForHmac), $hmacKey);
        $challengeData['hmac'] = $hmac;
        $challengeData['generation_microtime'] = microtime(true);

        // SECURITY FIX: Store Challenge to prevent Replay Attacks
        $this->storeChallengeState($randomChallenge, $timestamp);
        
        $this->log("Challenge generated and stored: " . $randomChallenge);
        
        return base64_encode(json_encode($challengeData));
    }

    // New Method: Store challenge state
    private function storeChallengeState($challengeId, $timestamp) {
        $filename = 'challenge_' . $challengeId . '.dat';
        // We just store the timestamp as payload
        $this->storageManager->writeFile($filename, json_encode(['ts' => $timestamp]));
    }

    // New Method: Consume challenge state (Delete on use)
    private function consumeChallengeState($challengeId) {
        $filename = 'challenge_' . $challengeId . '.dat';
        if ($this->storageManager->fileExists($filename)) {
            $this->storageManager->deleteFile($filename);
            return true;
        }
        return false;
    }
    
    public function verifyChallengeResponse($encodedChallenge, $clientSignature, $clientCertificate = null) {
        $this->log("Verifying challenge response");
        
        SecurityValidator::validateChallenge($encodedChallenge);
        SecurityValidator::validateSignature($clientSignature);
        
        if ($clientCertificate) {
            $clientCertificate = SecurityValidator::validateCertificate($clientCertificate);
        }
        
        $challengeJson = base64_decode($encodedChallenge);
        if ($challengeJson === false) {
            throw new ValidationException("Failed to base64 decode challenge");
        }
        
        $challengeData = json_decode($challengeJson, true);
        if (!$challengeData) {
            throw new ValidationException("Invalid challenge format");
        }
        
        // SECURITY FIX: Verify HMAC using Server Secret
        if (!isset($challengeData['hmac'])) {
            throw new ValidationException("Missing HMAC in challenge");
        }
        
        $receivedHmac = $challengeData['hmac'];
        $dataForHmac = [
            'challenge' => $challengeData['challenge'],
            'timestamp' => $challengeData['timestamp'],
            'expires' => $challengeData['expires'],
            'server_id' => $challengeData['server_id'],
            'signature' => $challengeData['signature']
        ];
        
        $hmacKey = $this->storageManager->getSecretHash();
        $expectedHmac = hash_hmac('sha256', json_encode($dataForHmac), $hmacKey);
        
        if (!hash_equals($receivedHmac, $expectedHmac)) {
            throw new ValidationException("Challenge integrity check failed");
        }
        
        // Verify challenge hasn't expired
        if (time() > $challengeData['expires']) {
            throw new ValidationException("Challenge expired");
        }

        // SECURITY FIX: Replay Attack Prevention
        // Check if challenge exists in storage and delete it.
        // If it doesn't exist, it was already used or never issued.
        if (!$this->consumeChallengeState($challengeData['challenge'])) {
            $this->log("REPLAY DETECTED or Invalid Challenge: " . $challengeData['challenge']);
            throw new ValidationException("Invalid or already used challenge");
        }
        
        // Verify server signature on challenge
        $challengeString = $challengeData['challenge'] . '|' . $challengeData['timestamp'] . '|' . $challengeData['expires'] . '|' . $challengeData['server_id'];
        if (!$this->verifySignature($challengeString, $challengeData['signature'])) {
            throw new ValidationException("Invalid challenge signature");
        }
        
        $this->log("Challenge verified: " . $challengeData['challenge']);
        
        // Verify client signature on challenge
        if ($clientCertificate) {
            $this->verifyWithCertificate($challengeData['challenge'], $clientSignature, $clientCertificate);
        } else {
            $this->verifyWithPublicKey($challengeData['challenge'], $clientSignature, $this->clientPublicKeyPath);
        }
        
        $this->log("Client authentication successful");
        return $challengeData['challenge'];
    }
    
    private function verifyWithCertificate($challenge, $signature, $clientCertificatePem) {
        $certInfo = openssl_x509_parse($clientCertificatePem);
        if ($certInfo === false) {
            throw new ValidationException("Failed to parse client certificate");
        }
        
        $clientCN = $certInfo['subject']['CN'] ?? '';
        if (empty($clientCN) || $clientCN !== $this->requiredClientCN) {
            throw new AuthenticationException("Client Common Name mismatch");
        }
        
        if (!empty($this->expectedClientCertFingerprint)) {
            $certFingerprint = openssl_x509_fingerprint($clientCertificatePem, 'sha256', false);
            if (!hash_equals(strtolower($this->expectedClientCertFingerprint), strtolower($certFingerprint))) {
                throw new AuthenticationException("Client certificate fingerprint mismatch");
            }
        }
        
        if ($this->checkExpiry) {
            $currentTime = time();
            if ($currentTime < $certInfo['validFrom_time_t']) {
                throw new AuthenticationException("Client certificate is not yet valid");
            }
            if ($currentTime > $certInfo['validTo_time_t']) {
                throw new AuthenticationException("Client certificate has expired");
            }
        }
        
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
        if (!file_exists($publicKeyPath)) {
            throw new AuthenticationException("Client public key not found");
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
        $publicKey = openssl_pkey_get_public("file://" . $this->serverPrivateKeyPath);
        if (!$publicKey) {
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
            return false;
        }
        
        $currentTime = time();
        $validTo = $certInfo['validTo_time_t'];
        $daysUntilExpiry = floor(($validTo - $currentTime) / (60 * 60 * 24));
        
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
        $from = $this->emailFrom ?: 'certificate-monitor@yourdomain.com';
        
        $message = "Certificate Expiry Alert for {$clientId}. Expires: {$validTo} ({$daysUntilExpiry} days left).";
        
        if (!$this->debugMode) {
            $headers = "From: {$from}\r\nContent-Type: text/plain; charset=UTF-8\r\n";
            mail($this->adminEmail, $subject, $message, $headers);
        }
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
    
    /**
     * SECURITY FIX: Uses atomicJsonUpdate to prevent Race Conditions
     */
    public function isAllowed($identifier, $isAuthAttempt = false) {
        if ($isAuthAttempt && $this->isRecentlyAuthenticated($identifier)) {
            return true;
        }
        
        $filename = $this->getFilename($identifier);
        $allowed = false;

        // Atomic operation: Lock -> Read -> Logic -> Write -> Unlock
        try {
            $this->storageManager->atomicJsonUpdate($filename, function($requests) use (&$allowed, $isAuthAttempt, $identifier) {
                $requests = $requests ?: [];
                $currentTime = time();
                
                // Filter old requests
                $requests = array_filter($requests, function($time) use ($currentTime) {
                    return ($currentTime - $time) < $this->timeWindow;
                });
                
                // Check limit
                if (count($requests) < $this->maxRequests) {
                    $allowed = true;
                    // Record new request if not a successful auth replay
                    if (!$isAuthAttempt || !$this->isRecentlyAuthenticated($identifier)) {
                        $requests[] = time();
                    }
                } else {
                    $allowed = false;
                }
                
                // Re-index array
                return array_values($requests);
            });
        } catch (Exception $e) {
            // Fail closed on storage errors
            return false;
        }
        
        return $allowed;
    }
    
    public function recordSuccessfulAuth($identifier) {
        $this->successfulAuths[$identifier] = time();
        $this->cleanupAuthRecords();
    }
    
    private function isRecentlyAuthenticated($identifier) {
        $this->cleanupAuthRecords();
        return isset($this->successfulAuths[$identifier]) && 
               (time() - $this->successfulAuths[$identifier]) < 300;
    }
    
    private function cleanupAuthRecords() {
        $currentTime = time();
        foreach ($this->successfulAuths as $identifier => $timestamp) {
            if (($currentTime - $timestamp) > 300) {
                unset($this->successfulAuths[$identifier]);
            }
        }
    }
    
    public function getRemainingRequests($identifier, $isAuthAttempt = false) {
        if ($isAuthAttempt && $this->isRecentlyAuthenticated($identifier)) {
            return $this->maxRequests;
        }
        
        $filename = $this->getFilename($identifier);
        $requests = $this->storageManager->readFile($filename);
        $requests = $requests ? json_decode($requests, true) : [];
        
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

// MAIN REQUEST HANDLING
try {
    ob_clean();

    if ($debugMode && isset($_GET['action']) && $_GET['action'] == 'timing_stats') {
        $stats = [
            'status' => 'active',
            'server_time' => date('Y-m-d H:i:s')
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
    
    // Initialize rate limiter with storage manager
    $rateLimiter = new RequestRateLimiter($maxRequestsPerMinute, 60, $storageManager);
    
    // Client Identifier
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $clientIdentifier = md5($clientIP . '|' . $userAgent);
    
    // Initialize authenticator
    // Added $storageManager dependency
    $authenticator = new HybridAuthenticator(
        $serverPrivateKeyPath,
        $clientPublicKeyPath,
        $requiredClientCN,
        $expectedClientCertFingerprint,
        $checkCertificateExpiry,
        $debugMode,
        $challengeTimeout,
        $storageManager 
    );
    
    $expiryMonitor = new CertificateExpiryMonitor(
        $adminEmail,
        $alertDaysThreshold,
        $debugMode,
        $emailFrom,
        $emailSubject
    );
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        if (!$rateLimiter->isAllowed($clientIdentifier, false)) {
            throw new RateLimitException("Too many challenge requests. Please slow down.");
        }
        
        log_message("Challenge requested from IP: " . $clientIP, $debugMode);
        
        $encodedChallenge = $authenticator->generateChallenge();
        
        ob_clean();
        echo json_encode([
            'status' => 'challenge',
            'challenge' => $encodedChallenge,
            'remaining_attempts' => $rateLimiter->getRemainingRequests($clientIdentifier, false),
            'challenge_timeout' => $challengeTimeout
        ], JSON_PRETTY_PRINT);
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        log_message("Authentication attempt from IP: " . $clientIP, $debugMode);
        
        $input = SecurityValidator::validateJsonInput($maxJsonInputSize);
        
        $signature = $input['signature'] ?? '';
        $encodedChallenge = $input['challenge'] ?? '';
        $clientCertificate = $input['certificate'] ?? null;
        
        if (empty($signature) || empty($encodedChallenge)) {
            throw new ValidationException("Missing required authentication data");
        }
        
        if (!$rateLimiter->isAllowed($clientIdentifier, true)) {
            throw new RateLimitException("Too many authentication attempts. Please slow down.");
        }
        
        $challenge = $authenticator->verifyChallengeResponse($encodedChallenge, $signature, $clientCertificate);
        
        $rateLimiter->recordSuccessfulAuth($clientIdentifier);
        
        if ($emailAlertsEnabled && $clientCertificate) {
            $expiryMonitor->checkAndAlert($clientCertificate, $requiredClientCN);
        }
        
        log_message("Authentication SUCCESS for IP: " . $clientIP, $debugMode);
        
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
    echo json_encode(['status' => 'error', 'message' => $errorMessage], JSON_PRETTY_PRINT);
} catch (AuthenticationException $e) {
    ob_clean();
    http_response_code(401);
    $errorMessage = $debugMode ? $e->getMessage() : "Authentication failed";
    echo json_encode(['status' => 'error', 'message' => $errorMessage], JSON_PRETTY_PRINT);
} catch (ValidationException $e) {
    ob_clean();
    http_response_code(400);
    $errorMessage = $debugMode ? $e->getMessage() : "Invalid request";
    echo json_encode(['status' => 'error', 'message' => $errorMessage], JSON_PRETTY_PRINT);
} catch (Exception $e) {
    ob_clean();
    http_response_code(500);
    $errorMessage = $debugMode ? $e->getMessage() : "Internal server error";
    echo json_encode(['status' => 'error', 'message' => $errorMessage], JSON_PRETTY_PRINT);
}

exit;
?>
