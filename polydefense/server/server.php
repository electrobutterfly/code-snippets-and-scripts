<?php
//////////////////////////////////////////////////////////////////////
// server.php (v1.2)
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

class SecurityValidator {
    // Memory Exhaustion Protection - Stream Reader
    public static function validateJsonInput($maxSize = 102400) {
        $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
        
        if ($contentLength > $maxSize) {
            throw new ValidationException("Input too large");
        }
        
        $input = '';
        $fp = fopen('php://input', 'r');
        if (!$fp) {
            throw new ValidationException("Could not open input stream");
        }

        $totalRead = 0;
        while (!feof($fp)) {
            $chunk = fread($fp, 8192); // Read in 8KB chunks
            if ($chunk === false) break;
            $totalRead += strlen($chunk);
            $input .= $chunk;

            if ($totalRead > $maxSize) {
                fclose($fp);
                throw new ValidationException("Input too large");
            }
        }
        fclose($fp);
        
        if (empty($input)) {
            throw new ValidationException("No input data received");
        }
        
        // JSON DoS Protection - Depth Limit
        $data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
        
        return $data;
    }
    
    public static function validateSignature($signature) {
        if (empty($signature) || strlen($signature) > 4096) {
            throw new ValidationException("Invalid signature format");
        }
        
        if (!preg_match('/^[a-zA-Z0-9+\/]+={0,2}$/', $signature)) {
            throw new ValidationException("Invalid signature encoding");
        }
        
        return true;
    }
    
    public static function validateChallenge($challenge) {
        if (empty($challenge) || strlen($challenge) > 10000) {
            throw new ValidationException("Invalid challenge format");
        }
        
        if (!preg_match('/^[a-zA-Z0-9+\/]+={0,2}$/', $challenge)) {
            throw new ValidationException("Invalid challenge encoding");
        }
        
        return true;
    }
    
    public static function validateCertificate($certificate) {
        if (empty($certificate)) {
            return null;
        }
        
        if (strlen($certificate) > 16384) {
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
                throw new ConfigurationException("Failed to create storage directory");
            }
            $this->log("Created storage directory: " . $this->storagePath);
        }
        
        // Create locks directory for atomic operations
        $locksDir = $this->storagePath . '/locks';
        
        // FIX: Race Condition in Lock Directory Creation
        // Logic: If it doesn't exist AND we fail to make it AND it still doesn't exist -> Error
        if (!is_dir($locksDir) && !@mkdir($locksDir, 0700, true) && !is_dir($locksDir)) {
            throw new ConfigurationException("Failed to create locks directory");
        }
        
        // Set secure permissions on directory
        if (is_dir($this->storagePath)) {
            if (!chmod($this->storagePath, 0700)) {
                throw new ConfigurationException("Failed to set secure permissions");
            }
        }
        
        // Initialize secret file
        $this->initializeSecret();
        
        $this->log("Storage initialized: " . $this->storagePath);
    }
    
    private function initializeSecret() {
        $secretFile = $this->storagePath . '/.secret';
        if (!file_exists($secretFile)) {
            if (!function_exists('random_bytes')) {
                throw new SecurityException("Secure random generator unavailable");
            }
            
            // FIX: Entropy check
            try {
                $secret = bin2hex(random_bytes(32));
            } catch (Exception $e) {
                throw new SecurityException("System entropy source failure");
            }

            if (file_put_contents($secretFile, $secret) === false) {
                throw new SecurityException("Failed to create secret file");
            }
            if (!chmod($secretFile, 0600)) {
                throw new SecurityException("Failed to set secure permissions on secret file");
            }
            $this->log("Generated new storage secret");
        }
    }

    public function getSecretHash() {
        return $this->getStorageSecret();
    }

    // FIX: Directory-based Atomic Locking with Exponential Backoff
    private function acquireLock($filename) {
        $lockDir = $this->storagePath . '/locks/' . md5($filename);
        // mkdir is atomic
        if (@mkdir($lockDir, 0700)) {
            return $lockDir;
        }
        return false;
    }

    private function releaseLock($lockDir) {
        if ($lockDir && is_dir($lockDir)) {
            @rmdir($lockDir);
        }
    }

    // Helper for exponential backoff
    private function waitForLock($filename) {
        $lockDir = false;
        $attempts = 0;
        
        // Try for approx 1 second total
        while (!$lockDir && $attempts < 10) {
            $lockDir = $this->acquireLock($filename);
            if (!$lockDir) {
                // Exponential backoff: 5ms, 10ms, 20ms... capped
                // 5000us * 2^attempt
                $baseWait = 5000 * pow(2, $attempts);
                $jitter = rand(0, 1000);
                $wait = min(200000, $baseWait + $jitter); // Cap at 200ms
                
                usleep((int)$wait);
                $attempts++;
            }
        }
        
        return $lockDir;
    }

    public function atomicJsonUpdate($filename, callable $callback) {
        $this->enforceStorageLimits();
        $filepath = $this->storagePath . '/' . $filename;
        
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename");
        }

        $lockDir = $this->waitForLock($filename);
        if (!$lockDir) {
            throw new SecurityException("System busy: could not acquire lock");
        }

        try {
            // Read existing
            $currentData = [];
            if (file_exists($filepath)) {
                $fileContent = file_get_contents($filepath);
                if ($fileContent) {
                    $stored = json_decode($fileContent, true);
                    if ($stored && isset($stored['data'], $stored['hmac'])) {
                        $expectedHmac = hash_hmac('sha256', $stored['data'], $this->getStorageSecret());
                        if (hash_equals($stored['hmac'], $expectedHmac)) {
                            $currentData = json_decode(base64_decode($stored['data']), true) ?: [];
                        }
                    }
                }
            }

            // Apply callback logic
            $newData = $callback($currentData);

            // Write back
            $jsonData = json_encode($newData);
            $base64 = base64_encode($jsonData);
            $hmac = hash_hmac('sha256', $base64, $this->getStorageSecret());
            
            $finalPayload = json_encode([
                'data' => $base64,
                'hmac' => $hmac,
                'timestamp' => time()
            ]);

            // Atomic write using temp file and rename
            $tempFile = $filepath . '.tmp';
            if (file_put_contents($tempFile, $finalPayload) !== false) {
                // FIX: fsync for durability (if supported)
                if (function_exists('fsync')) {
                    $fp = fopen($tempFile, 'r+');
                    if ($fp) {
                        fsync($fp);
                        fclose($fp);
                    }
                }
                rename($tempFile, $filepath);
            } else {
                throw new SecurityException("Failed to write storage file");
            }

        } finally {
            $this->releaseLock($lockDir);
        }

        return true;
    }
    
    public function writeFile($filename, $data, $compress = false) {
        $this->enforceStorageLimits();
        
        $filepath = $this->storagePath . '/' . $filename;
        
        // Validate filename to prevent directory traversal
        if (!$this->isValidFilename($filename)) {
            throw new ValidationException("Invalid filename");
        }
        
        // Check file size limit
        if (strlen($data) > $this->maxFileSize) {
            throw new ValidationException("File size exceeds limit");
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
        
        // FIX: Directory locking + fsync
        $lockDir = $this->waitForLock($filename);
        if (!$lockDir) {
             throw new SecurityException("System busy: could not acquire lock");
        }

        try {
            $fp = fopen($filepath, 'w');
            if ($fp) {
                fwrite($fp, $fileData);
                fflush($fp); 
                // FIX: fsync for durability
                if (function_exists('fsync')) {
                    fsync($fp);
                }
                fclose($fp);
                $this->log("File written: " . $filename);
            } else {
                throw new SecurityException("Failed to open file for writing: " . $filename);
            }
        } finally {
            $this->releaseLock($lockDir);
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
            throw new ValidationException("Invalid filename");
        }
        
        // FIX: Directory locking for read
        $lockDir = $this->waitForLock($filename);
        if (!$lockDir) {
             throw new SecurityException("System busy: could not acquire lock");
        }

        $fileData = '';
        try {
            $fileData = file_get_contents($filepath);
        } finally {
            $this->releaseLock($lockDir);
        }
        
        $data = json_decode($fileData, true);
        if (!$data || !isset($data['data']) || !isset($data['hmac'])) {
            $this->log("Corrupted file detected: " . $filename);
            @unlink($filepath);
            return null;
        }
        
        // Verify HMAC
        $expectedHmac = hash_hmac('sha256', $data['data'], $this->getStorageSecret());
        if (!hash_equals($data['hmac'], $expectedHmac)) {
            $this->log("HMAC verification failed for file: " . $filename);
            @unlink($filepath);
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
                throw new SecurityException("Failed to delete file: " . $filename);
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
            throw new SecurityException("Storage limit exceeded");
        }
        
        if ($usage['file_count'] > $this->maxFileCount) {
            throw new SecurityException("File count limit exceeded");
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
    
    // FIX: Stricter Regex (Alpha-numeric start, 100 char limit, .dat extension enforced)
    private function isValidFilename($filename) {
        return preg_match('/^[a-z0-9][a-z0-9_\-]{1,100}\.dat$/i', $filename) === 1;
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
    private $storageManager; 
    
    public function __construct($serverPrivateKeyPath, $clientPublicKeyPath, $requiredClientCN, $expectedClientCertFingerprint = '', $checkExpiry = true, $debugMode = false, $challengeTimeout = 300, $storageManager = null) {
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
        
        try {
            $randomChallenge = bin2hex(random_bytes(32));
        } catch (Exception $e) {
            throw new SecurityException("Entropy failure");
        }

        $timestamp = time();
        $expires = $timestamp + $this->challengeTimeout;
        
        $challengeData = [
            'challenge' => $randomChallenge,
            'timestamp' => $timestamp,
            'expires' => $expires,
            'server_id' => 'auth-server'
        ];
        
        $challengeString = $randomChallenge . '|' . $timestamp . '|' . $expires . '|' . 'auth-server';
        $signature = $this->signData($challengeString, $this->serverPrivateKeyPath);
        $challengeData['signature'] = $signature;
        
        $hmacKey = '';
        if ($this->storageManager) {
            $hmacKey = $this->storageManager->getSecretHash();
        } else {
            $hmacKey = hash('sha256', $randomChallenge . $timestamp, true);
        }
        
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

        if ($this->storageManager) {
            // Store with .dat extension enforced by isValidFilename
            $this->storageManager->writeFile('chal_' . $randomChallenge . '.dat', json_encode(['ts' => $timestamp]));
        }
        
        $this->log("Challenge generated: " . $randomChallenge);
        
        return base64_encode(json_encode($challengeData));
    }
    
    public function verifyChallengeResponse($encodedChallenge, $clientSignature, $clientCertificate = null) {
        $this->log("Verifying challenge response");
        
        SecurityValidator::validateChallenge($encodedChallenge);
        SecurityValidator::validateSignature($clientSignature);
        
        // Enforce Certificate
        if (empty($clientCertificate)) {
            throw new ValidationException("Client certificate is required");
        }
        $clientCertificate = SecurityValidator::validateCertificate($clientCertificate);
        
        $challengeJson = base64_decode($encodedChallenge);
        if ($challengeJson === false) {
            throw new ValidationException("Failed to base64 decode challenge");
        }
        
        $challengeData = json_decode($challengeJson, true);
        if (!$challengeData) {
            throw new ValidationException("Invalid challenge format");
        }
        
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
        
        $hmacKey = '';
        if ($this->storageManager) {
            $hmacKey = $this->storageManager->getSecretHash();
        }
        
        $expectedHmac = hash_hmac('sha256', json_encode($dataForHmac), $hmacKey);
        
        if (!hash_equals($receivedHmac, $expectedHmac)) {
            $this->log("HMAC verification failed. Expected: " . $expectedHmac . ", Got: " . $receivedHmac);
            throw new ValidationException("Challenge integrity check failed");
        }
        
        if (time() > $challengeData['expires']) {
            throw new ValidationException("Challenge expired");
        }

        if ($this->storageManager) {
            $chalFile = 'chal_' . $challengeData['challenge'] . '.dat';
            if (!$this->storageManager->fileExists($chalFile)) {
                throw new SecurityException("Challenge invalid or already used (Replay Attack)");
            }
            $this->storageManager->deleteFile($chalFile);
        }
        
        $challengeString = $challengeData['challenge'] . '|' . $challengeData['timestamp'] . '|' . $challengeData['expires'] . '|' . $challengeData['server_id'];
        if (!$this->verifySignature($challengeString, $challengeData['signature'])) {
            throw new ValidationException("Invalid challenge signature");
        }
        
        if (isset($challengeData['generation_microtime'])) {
            $verificationTime = microtime(true);
            $totalTime = $verificationTime - $challengeData['generation_microtime'];
            
            $this->log("Challenge lifecycle: " . round($totalTime, 2) . " seconds");
            
            $timeRemaining = $challengeData['expires'] - time();
            if ($timeRemaining < ($this->challengeTimeout * 0.25)) {
                $this->log("WARNING: Challenge used with only " . $timeRemaining . " seconds remaining");
            }
        }
        
        $this->log("Challenge verified: " . $challengeData['challenge']);
        
        $this->verifyWithCertificate($challengeData['challenge'], $clientSignature, $clientCertificate);
        
        $this->log("Client authentication successful");
        return $challengeData['challenge'];
    }
    
    private function verifyWithCertificate($challenge, $signature, $clientCertificatePem) {
        $this->log("Verifying with client certificate");
        
        $certInfo = openssl_x509_parse($clientCertificatePem);
        if ($certInfo === false) {
            throw new ValidationException("Failed to parse client certificate");
        }
        
        $clientCN = $certInfo['subject']['CN'] ?? '';
        if (empty($clientCN)) {
             throw new AuthenticationException("Client CN missing");
        }

        if (!hash_equals($this->requiredClientCN, $clientCN)) {
            throw new AuthenticationException("Client Common Name mismatch. Expected: " . $this->requiredClientCN . ", Got: " . $clientCN);
        }
        
        if (!empty($this->expectedClientCertFingerprint)) {
            $certFingerprint = openssl_x509_fingerprint($clientCertificatePem, 'sha256', false);
            if (!hash_equals(strtolower($this->expectedClientCertFingerprint), strtolower($certFingerprint))) {
                throw new AuthenticationException("Client certificate fingerprint mismatch");
            }
            $this->log("Certificate fingerprint verified");
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
        if ($isAuthAttempt && $this->isRecentlyAuthenticated($identifier)) {
            return true;
        }
        
        // Enforce .dat extension
        $filename = $this->getFilename($identifier);
        $allowed = false;
        
        try {
            $this->storageManager->atomicJsonUpdate($filename, function($requests) use (&$allowed, $identifier, $isAuthAttempt) {
                $currentTime = time();
                $requests = $requests ?: [];
                
                $requests = array_filter($requests, function($time) use ($currentTime) {
                    return ($currentTime - $time) < $this->timeWindow;
                });
                
                if (count($requests) < $this->maxRequests) {
                    $allowed = true;
                    if (!$isAuthAttempt || !$this->isRecentlyAuthenticated($identifier)) {
                        $requests[] = time();
                    }
                } else {
                    $allowed = false;
                }
                
                return array_values($requests);
            });
        } catch (Exception $e) {
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
        // Ensures compatibility with stricter regex
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
    ob_clean();

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

    $storageManager = new SecureStorageManager(
        $storagePath,
        $maxStorageSize,
        $maxFileCount,
        $maxFileSize,
        $cleanupThreshold,
        $debugMode
    );
    
    if ($debugMode) {
        $storageInfo = $storageManager->getStorageInfo();
        log_message("=== STORAGE INFORMATION ===", $debugMode);
        log_message("Storage Path: " . $storageInfo['path'], $debugMode);
        log_message("Current Usage: " . round($storageInfo['usage_percent'], 2) . "% (" . 
                   $storageInfo['current_files'] . " files)", $debugMode);
        log_message("File Usage: " . round($storageInfo['file_usage_percent'], 2) . "%", $debugMode);
        log_message("=== END STORAGE INFORMATION ===", $debugMode);
    }
    
    $rateLimiter = new RequestRateLimiter($maxRequestsPerMinute, 60, $storageManager);
    
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $clientIdentifier = md5($clientIP . '|' . $userAgent);
    
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
        
        log_message("Challenge requested from IP: " . $clientIP . " (ID: " . $clientIdentifier . ")", $debugMode);
        
        $encodedChallenge = $authenticator->generateChallenge();
        
        ob_clean();
        echo json_encode([
            'status' => 'challenge',
            'challenge' => $encodedChallenge,
            'remaining_attempts' => $rateLimiter->getRemainingRequests($clientIdentifier, false),
            'challenge_timeout' => $challengeTimeout
        ], JSON_PRETTY_PRINT);
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        log_message("Authentication attempt from IP: " . $clientIP . " (ID: " . $clientIdentifier . ")", $debugMode);
        
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
        
        log_message("Authentication SUCCESS for IP: " . $clientIP . " (ID: " . $clientIdentifier . ")", $debugMode);
        
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
?>
