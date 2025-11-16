<?php
//////////////////////////////////////////////////////////////////////
// server.php
// @copyright     (c) 2025 Klaus Simon
// @license       Custom Attribution-NonCommercial Sale License
// @description   Part of the Secure Public Key Server/Client 
//                Authentication System
 
// Permission is granted to use, modify, and distribute this script
// for any purpose except commercial sale without explicit permission.
// Attribution must be retained in all copies.
 
// For commercial licensing: licensing@electrobutterfly.com
// Full license: LICENSE file in repository
//////////////////////////////////////////////////////////////////////

// ==========================================
// USER CONFIGURATION - UPDATE THESE VALUES!
// ==========================================

$publicKeyPath = './keys/dummy.pub';
$sharedSecret = '1820010959935ß5&dajadouu8..asusts$gg';

// Challenge request protection
$maxChallengesPerMinute = 60;   // Maximum challenge requests per minute per IP
$challengeTimeout = 300;
$debugMode = true;

// Rate limiting configuration
$maxConsecutiveFailures = 5;    // Block after 5 consecutive failures
$failureWindow = 900;           // 15 minute window for counting failures
$blockDuration = 1800;          // 30 minute block after too many failures

// ==========================================
// SECURITY HARDENED - DON'T MODIFY BELOW
// ==========================================

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

if (!$debugMode) {
    ini_set('display_errors', 0);
}
error_reporting(E_ALL);

class SecurityValidator {
    public static function validateJsonInput($maxSize = 10240) {
        $input = file_get_contents('php://input');
        
        if (strlen($input) > $maxSize) {
            throw new Exception("Input too large");
        }
        
        if (empty($input)) {
            throw new Exception("No input data received");
        }
        
        $data = json_decode($input, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Invalid JSON format");
        }
        
        return $data;
    }
    
    public static function validateSignature($signature) {
        if (empty($signature) || strlen($signature) > 1000) {
            throw new Exception("Invalid signature format");
        }
        
        if (!preg_match('/^[a-zA-Z0-9\/+]+={0,2}$/', $signature)) {
            throw new Exception("Invalid signature encoding");
        }
        
        return true;
    }
    
    public static function validateChallenge($challenge) {
        if (empty($challenge) || strlen($challenge) > 1000) {
            throw new Exception("Invalid challenge format");
        }
        
        return true;
    }
}

class ChallengeRateLimiter {
    private $maxRequests;
    private $timeWindow;
    private $storagePath;
    
    public function __construct($maxRequests = 60, $timeWindow = 60, $storagePath = null) {
        $this->maxRequests = $maxRequests;
        $this->timeWindow = $timeWindow;
        $this->storagePath = $storagePath ?: sys_get_temp_dir();
    }
    
    public function isAllowed($identifier) {
        $filename = $this->getFilename($identifier);
        $requests = [];
        
        if (file_exists($filename)) {
            $data = file_get_contents($filename);
            $requests = json_decode($data, true) ?: [];
            
            // Remove requests outside the time window
            $currentTime = time();
            $requests = array_filter($requests, function($time) use ($currentTime) {
                return ($currentTime - $time) < $this->timeWindow;
            });
        }
        
        if (count($requests) >= $this->maxRequests) {
            return false;
        }
        
        $requests[] = time();
        file_put_contents($filename, json_encode($requests));
        return true;
    }
    
    public function getRemainingChallenges($identifier) {
        $filename = $this->getFilename($identifier);
        $requests = [];
        
        if (file_exists($filename)) {
            $data = file_get_contents($filename);
            $requests = json_decode($data, true) ?: [];
            
            $currentTime = time();
            $requests = array_filter($requests, function($time) use ($currentTime) {
                return ($currentTime - $time) < $this->timeWindow;
            });
        }
        
        return max(0, $this->maxRequests - count($requests));
    }
    
    private function getFilename($identifier) {
        return $this->storagePath . '/challenge_requests_' . md5($identifier);
    }
}

class FailureRateLimiter {
    private $maxFailures;
    private $failureWindow;
    private $blockDuration;
    private $storagePath;
    
    public function __construct($maxFailures = 5, $failureWindow = 900, $blockDuration = 1800, $storagePath = null) {
        $this->maxFailures = $maxFailures;
        $this->failureWindow = $failureWindow;
        $this->blockDuration = $blockDuration;
        $this->storagePath = $storagePath ?: sys_get_temp_dir();
    }
    
    public function recordSuccess($identifier) {
        // Reset failure count on successful authentication
        $filename = $this->getFilename($identifier);
        if (file_exists($filename)) {
            unlink($filename);
        }
        return true;
    }
    
    public function recordFailure($identifier) {
        $filename = $this->getFilename($identifier);
        $failures = [];
        
        if (file_exists($filename)) {
            $data = file_get_contents($filename);
            $failures = json_decode($data, true) ?: [];
            
            // Remove failures outside the time window
            $currentTime = time();
            $failures = array_filter($failures, function($time) use ($currentTime) {
                return ($currentTime - $time) < $this->failureWindow;
            });
        }
        
        // Add current failure
        $failures[] = time();
        file_put_contents($filename, json_encode($failures));
        
        return count($failures);
    }
    
    public function isBlocked($identifier) {
        $filename = $this->getFilename($identifier);
        
        if (!file_exists($filename)) {
            return false;
        }
        
        $data = file_get_contents($filename);
        $failures = json_decode($data, true) ?: [];
        
        // Remove old failures
        $currentTime = time();
        $failures = array_filter($failures, function($time) use ($currentTime) {
            return ($currentTime - $time) < $this->failureWindow;
        });
        
        // Check if we have too many failures
        if (count($failures) >= $this->maxFailures) {
            // Check if block duration has passed
            $oldestFailure = min($failures);
            if (($currentTime - $oldestFailure) < $this->blockDuration) {
                return true;
            } else {
                // Block duration passed, reset failures
                unlink($filename);
                return false;
            }
        }
        
        return false;
    }
    
    public function getRemainingAttempts($identifier) {
        if ($this->isBlocked($identifier)) {
            return 0;
        }
        
        $filename = $this->getFilename($identifier);
        
        if (!file_exists($filename)) {
            return $this->maxFailures;
        }
        
        $data = file_get_contents($filename);
        $failures = json_decode($data, true) ?: [];
        
        // Remove old failures
        $currentTime = time();
        $failures = array_filter($failures, function($time) use ($currentTime) {
            return ($currentTime - $time) < $this->failureWindow;
        });
        
        return max(0, $this->maxFailures - count($failures));
    }
    
    public function getBlockTimeRemaining($identifier) {
        if (!$this->isBlocked($identifier)) {
            return 0;
        }
        
        $filename = $this->getFilename($identifier);
        $data = file_get_contents($filename);
        $failures = json_decode($data, true) ?: [];
        
        $oldestFailure = min($failures);
        $blockUntil = $oldestFailure + $this->blockDuration;
        
        return max(0, $blockUntil - time());
    }
    
    private function getFilename($identifier) {
        return $this->storagePath . '/auth_failures_' . md5($identifier);
    }
}

class PublicKeyAuthenticator {
    private $publicKeyPath;
    private $allowedKeys = [];
    private $sharedSecret;
    private $debug;
    
    public function __construct($publicKeyPath, $sharedSecret, $debug = false) {
        $this->publicKeyPath = $publicKeyPath;
        $this->sharedSecret = $sharedSecret;
        $this->debug = $debug;
        $this->loadPublicKeys();
    }
    
    private function log($message) {
        if ($this->debug) {
            error_log("AUTH_DEBUG: " . $message);
        }
    }
    
    private function loadPublicKeys() {
        if (!file_exists($this->publicKeyPath)) {
            throw new Exception("Public key file not found: " . $this->publicKeyPath);
        }
        
        $publicKeyContent = file_get_contents($this->publicKeyPath);
        if ($publicKeyContent === false) {
            throw new Exception("Failed to read public key file");
        }
        
        $this->allowedKeys[] = $this->parsePublicKey($publicKeyContent);
    }
    
    private function parsePublicKey($keyContent) {
        if (strpos($keyContent, '-----BEGIN PUBLIC KEY-----') !== false) {
            return $keyContent;
        }
        
        if (strpos($keyContent, 'ssh-rsa') === 0) {
            return $this->convertOpenSSHToPEM($keyContent);
        }
        
        $keyContent = str_replace(["\r", "\n"], '', trim($keyContent));
        
        return "-----BEGIN PUBLIC KEY-----\n" . 
               chunk_split($keyContent, 64, "\n") . 
               "-----END PUBLIC KEY-----\n";
    }
    
    private function convertOpenSSHToPEM($opensshKey) {
        $parts = explode(' ', $opensshKey);
        if (count($parts) < 2) {
            throw new Exception("Invalid OpenSSH key format");
        }
        
        $keyData = base64_decode($parts[1]);
        if ($keyData === false) {
            throw new Exception("Failed to decode OpenSSH key data");
        }
        
        $offset = 0;
        
        $len = unpack('N', substr($keyData, $offset, 4))[1];
        $offset += 4;
        $algorithm = substr($keyData, $offset, $len);
        $offset += $len;
        
        $len = unpack('N', substr($keyData, $offset, 4))[1];
        $offset += 4;
        $exponent = substr($keyData, $offset, $len);
        $offset += $len;
        
        $len = unpack('N', substr($keyData, $offset, 4))[1];
        $offset += 4;
        $modulus = substr($keyData, $offset, $len);
        
        return $this->createRSAPublicKey($modulus, $exponent);
    }
    
    private function createRSAPublicKey($modulus, $exponent) {
        $modulusAsn1 = $this->encodeASN1Integer($modulus);
        $exponentAsn1 = $this->encodeASN1Integer($exponent);
        
        $sequence = $this->encodeASN1Sequence($modulusAsn1 . $exponentAsn1);
        $bitString = "\x00" . $sequence;
        
        $oid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
        $oidSequence = $this->encodeASN1Sequence($oid . "\x05\x00");
        $publicKey = $this->encodeASN1Sequence($oidSequence . $this->encodeASN1BitString($bitString));
        
        $pem = "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split(base64_encode($publicKey), 64, "\n") .
               "-----END PUBLIC KEY-----\n";
        
        return $pem;
    }
    
    private function encodeASN1Integer($data) {
        if (ord($data[0]) > 0x7F) {
            $data = "\x00" . $data;
        }
        return "\x02" . $this->encodeASN1Length(strlen($data)) . $data;
    }
    
    private function encodeASN1Sequence($data) {
        return "\x30" . $this->encodeASN1Length(strlen($data)) . $data;
    }
    
    private function encodeASN1BitString($data) {
        return "\x03" . $this->encodeASN1Length(strlen($data)) . $data;
    }
    
    private function encodeASN1Length($length) {
        if ($length < 128) {
            return chr($length);
        } else {
            $bytes = [];
            while ($length > 0) {
                array_unshift($bytes, $length & 0xFF);
                $length >>= 8;
            }
            return chr(0x80 | count($bytes)) . implode('', array_map('chr', $bytes));
        }
    }
    
    public function verifySignature($data, $signature, $publicKeyPem) {
        $signature = base64_decode($signature);
        if ($signature === false) {
            throw new Exception("Failed to decode signature");
        }
        
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new Exception("Invalid public key format");
        }
        
        $result = openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256);
        openssl_free_key($key);
        
        return $result === 1;
    }
    
    public function authenticate($challenge, $signature) {
        foreach ($this->allowedKeys as $publicKey) {
            try {
                if ($this->verifySignature($challenge, $signature, $publicKey)) {
                    return true;
                }
            } catch (Exception $e) {
                $this->log("Key verification failed: " . $e->getMessage());
            }
        }
        return false;
    }
    
    public function generateEncryptedChallenge() {
        if (!function_exists('random_bytes')) {
            throw new Exception("Secure random generator unavailable");
        }
        
        $randomChallenge = bin2hex(random_bytes(32));
        $timestamp = time();
        
        $data = $randomChallenge . '|' . $this->sharedSecret . '|' . $timestamp;
        
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->sharedSecret, 0, $iv);
        
        if ($encrypted === false) {
            throw new Exception("Failed to encrypt challenge");
        }
        
        return base64_encode($iv . $encrypted);
    }
    
    public function decryptAndValidateChallenge($encryptedChallenge, $maxAge) {
        $data = base64_decode($encryptedChallenge);
        if ($data === false) {
            throw new Exception("Failed to base64 decode challenge");
        }
        
        if (strlen($data) < 16) {
            throw new Exception("Challenge data too short");
        }
        
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->sharedSecret, 0, $iv);
        if ($decrypted === false) {
            throw new Exception("Failed to decrypt challenge");
        }
        
        $parts = explode('|', $decrypted);
        if (count($parts) !== 3) {
            throw new Exception("Invalid challenge format");
        }
        
        list($randomChallenge, $secret, $timestamp) = $parts;
        
        if (!hash_equals($secret, $this->sharedSecret)) {
            throw new Exception("Shared secret mismatch");
        }
        
        if ((time() - $timestamp) > $maxAge) {
            throw new Exception("Challenge expired");
        }
        
        return $randomChallenge;
    }
}

// Handle the authentication request
header('Content-Type: application/json');

// Clear any previous output
if (ob_get_length()) {
    ob_clean();
}

function log_message($message, $debugMode) {
    if ($debugMode) {
        error_log("AUTH_DEBUG: " . $message);
    }
}

try {
    // Initialize failure-based rate limiter
    $rateLimiter = new FailureRateLimiter($maxConsecutiveFailures, $failureWindow, $blockDuration);
    $clientIdentifier = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Check if client is blocked due to too many failures
    if ($rateLimiter->isBlocked($clientIdentifier)) {
        $blockTimeRemaining = $rateLimiter->getBlockTimeRemaining($clientIdentifier);
        throw new Exception("Too many authentication failures. Please try again in " . ceil($blockTimeRemaining / 60) . " minutes.");
    }
    
    // Initialize authenticator
    $authenticator = new PublicKeyAuthenticator($publicKeyPath, $sharedSecret, $debugMode);
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Lightweight protection against challenge request floods
        $challengeLimiter = new ChallengeRateLimiter($maxChallengesPerMinute, 60);
        if (!$challengeLimiter->isAllowed($clientIdentifier)) {
            throw new Exception("Too many challenge requests. Please slow down.");
        }
        
        log_message("Challenge requested from IP: " . $clientIdentifier, $debugMode);
        
        $encryptedChallenge = $authenticator->generateEncryptedChallenge();
        
        echo json_encode([
            'status' => 'challenge',
            'challenge' => $encryptedChallenge,
            'remaining_attempts' => $rateLimiter->getRemainingAttempts($clientIdentifier),
            'remaining_challenges' => $challengeLimiter->getRemainingChallenges($clientIdentifier)
        ]);
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        log_message("Authentication attempt from IP: " . $clientIdentifier, $debugMode);
        
        $input = SecurityValidator::validateJsonInput();
        
        $signature = $input['signature'] ?? '';
        $encryptedChallenge = $input['challenge'] ?? '';
        
        SecurityValidator::validateChallenge($encryptedChallenge);
        SecurityValidator::validateSignature($signature);
        
        // Decrypt and validate the challenge
        $challenge = $authenticator->decryptAndValidateChallenge($encryptedChallenge, $challengeTimeout);
        
        if ($authenticator->authenticate($challenge, $signature)) {
            // SUCCESS: Reset failure counter
            $rateLimiter->recordSuccess($clientIdentifier);
            log_message("Authentication SUCCESS for IP: " . $clientIdentifier, $debugMode);
            
            echo json_encode([
                'status' => 'success',
                'data' => [
                    'secret_message' => 'Authentication successful! Your protected data is here.',
                    'timestamp' => time(),
                    'user' => 'authenticated_client',
                    'remaining_attempts' => $rateLimiter->getRemainingAttempts($clientIdentifier)
                ]
            ]);
        } else {
            // FAILURE: Record failed attempt and check if blocked
            $failureCount = $rateLimiter->recordFailure($clientIdentifier);
            log_message("Authentication FAILED for IP: " . $clientIdentifier . " (Failure #" . $failureCount . ")", $debugMode);
            
            if ($rateLimiter->isBlocked($clientIdentifier)) {
                $blockTimeRemaining = $rateLimiter->getBlockTimeRemaining($clientIdentifier);
                throw new Exception("Too many authentication failures. Account temporarily locked. Try again in " . ceil($blockTimeRemaining / 60) . " minutes.");
            } else {
                throw new Exception("Authentication failed - invalid signature. Remaining attempts: " . $rateLimiter->getRemainingAttempts($clientIdentifier));
            }
        }
    } else {
        http_response_code(405);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Method not allowed'
        ]);
    }
    
} catch (Exception $e) {
    $errorMessage = $debugMode ? $e->getMessage() : "Authentication failed";
    
    if (!headers_sent()) {
        http_response_code(400);
    }
    
    $response = [
        'status' => 'error', 
        'message' => $errorMessage
    ];
    
    // Add remaining attempts info if available
    if (isset($rateLimiter) && isset($clientIdentifier)) {
        $response['remaining_attempts'] = $rateLimiter->getRemainingAttempts($clientIdentifier);
        
        if ($rateLimiter->isBlocked($clientIdentifier)) {
            $response['block_time_remaining'] = $rateLimiter->getBlockTimeRemaining($clientIdentifier);
        }
    }
    
    echo json_encode($response);
}

exit;
?>
