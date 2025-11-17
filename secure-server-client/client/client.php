<?php
//////////////////////////////////////////////////////////////////////
// client.php
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
// USER CONFIGURATION - UPDATE THERS VALUES!
// ==========================================

$privateKeyPath = $_ENV['AUTH_PRIVATE_KEY_PATH'] ?? './keys/dummy.key';
$serverUrl = $_ENV['AUTH_SERVER_URL'] ?? 'https://domain.com/auth/server2.php';
$sharedSecret = $_ENV['AUTH_SHARED_SECRET'] ?? '1820010959935ß5&dajadouu8..asusts$gg';
$debugMode = true;
$verifySSL = false;  // SECURITY NOTE: Set to true in production environment

// ==========================================
// SECURITY HARDENED - DON'T MODIFY BELOW
// ==========================================

class ClientAuthenticator {
    private $privateKeyPath;
    private $serverUrl;
    private $sharedSecret;
    private $debug;
    private $verifySSL;
    private $lastRequestTime = 0;
    private $minRequestInterval = 0.1; // 100 milliseconds minimum between requests
    
    public function __construct($privateKeyPath, $serverUrl, $sharedSecret, $debug = false, $verifySSL = true) {
        $this->privateKeyPath = $privateKeyPath;
        $this->serverUrl = $serverUrl;
        $this->sharedSecret = $sharedSecret;
        $this->debug = $debug;
        $this->verifySSL = $verifySSL;
    }
    
    private function log($message) {
        if ($this->debug) {
            echo $message . "\n";
        }
    }
    
    private function enforceRateLimit() {
        $now = microtime(true);
        if (($now - $this->lastRequestTime) < $this->minRequestInterval) {
            throw new Exception("Rate limit exceeded - please wait between requests");
        }
        $this->lastRequestTime = $now;
    }
    
    private function makeRequest($url, $postData = null) {
        $this->enforceRateLimit();
        
        $contextOptions = [
            'http' => [
                'timeout' => 30,
                'ignore_errors' => true,
                'user_agent' => 'SecureAuthClient/1.0',
                'follow_location' => 0 // Prevent redirect attacks
            ],
            'ssl' => [
                'verify_peer' => $this->verifySSL,
                'verify_peer_name' => $this->verifySSL,
                'allow_self_signed' => false,
                'verify_depth' => 5,
                'ciphers' => 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
            ]
        ];
        
        if ($postData !== null) {
            $contextOptions['http']['method'] = 'POST';
            $contextOptions['http']['header'] = 'Content-Type: application/json';
            $contextOptions['http']['content'] = json_encode($postData);
        }
        
        $context = stream_context_create($contextOptions);
        $response = file_get_contents($url, false, $context);
        
        if ($response === FALSE) {
            $error = error_get_last();
            throw new Exception("Request failed: " . ($error['message'] ?? 'Unknown error'));
        }
        
        return $response;
    }
    
    private function validateServerResponse($responseData) {
        if (!isset($responseData['status'])) {
            throw new Exception("Invalid server response - no status field");
        }
        
        if (!in_array($responseData['status'], ['challenge', 'success', 'error'])) {
            throw new Exception("Invalid server response - unknown status: " . $responseData['status']);
        }
        
        return true;
    }
    
    private function decryptChallenge($encryptedChallenge) {
        $this->log("=== Decrypting Challenge ===");
        
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
        if (count($parts) !== 4) {
            throw new Exception("Invalid challenge format");
        }
        
        list($randomChallenge, $secret, $timestamp, $hmac) = $parts;
        
        // Verify HMAC for integrity
        $dataToVerify = $randomChallenge . '|' . $secret . '|' . $timestamp;
        $expectedHmac = hash_hmac('sha256', $dataToVerify, $this->sharedSecret);
        
        if (!hash_equals($hmac, $expectedHmac)) {
            throw new Exception("Challenge integrity check failed");
        }
        
        // SECURITY FIX: Use hash_equals to prevent timing attacks
        if (!hash_equals($secret, $this->sharedSecret)) {
            throw new Exception("Shared secret verification failed");
        }
        
        $this->log("✓ Challenge decrypted successfully");
        $this->log("Challenge length: " . strlen($randomChallenge) . " bytes");
        $this->log("Timestamp: " . date('Y-m-d H:i:s', $timestamp));
        
        return $randomChallenge;
    }
    
    private function loadPrivateKey() {
        $this->log("=== Loading Private Key ===");
        $this->log("Key path: " . $this->privateKeyPath);
        
        if (!file_exists($this->privateKeyPath)) {
            throw new Exception("Private key not found at: " . $this->privateKeyPath);
        }
        
        $this->log("✓ Key file exists");
        
        if ($this->debug) {
            $perms = fileperms($this->privateKeyPath);
            $this->log("File permissions: " . substr(sprintf('%o', $perms), -4));
        }
        
        $privateKey = openssl_pkey_get_private("file://" . $this->privateKeyPath);
        if (!$privateKey) {
            $error = openssl_error_string();
            throw new Exception("Failed to load private key: " . $error);
        }
        
        $this->log("✓ Private key loaded successfully");
        
        if ($this->debug) {
            $keyDetails = openssl_pkey_get_details($privateKey);
            if ($keyDetails) {
                $this->log("Key type: " . ($keyDetails['type'] === OPENSSL_KEYTYPE_RSA ? "RSA" : "Unknown"));
                $this->log("Key bits: " . $keyDetails['bits']);
            }
        }
        
        return $privateKey;
    }
    
    private function signData($data, $privateKey) {
        $this->log("=== Signing Data ===");
        $this->log("Data length: " . strlen($data) . " bytes");
        
        $signature = '';
        $success = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        
        if (!$success) {
            $error = openssl_error_string();
            throw new Exception("Failed to sign data: " . $error);
        }
        
        $base64Signature = base64_encode($signature);
        $this->log("✓ Data signed successfully");
        
        if ($this->debug) {
            $this->log("Signature length: " . strlen($signature) . " bytes");
        }
        
        return $base64Signature;
    }
    
    public function authenticateAndGetData() {
        $this->log("🚀 Starting Authentication Process");
        $this->log("Server URL: " . $this->serverUrl);
        $this->log("Private Key Path: " . $this->privateKeyPath);
        $this->log("SSL Verification: " . ($this->verifySSL ? "ENABLED" : "DISABLED"));
        
        if (!$this->verifySSL) {
            $this->log("⚠️  WARNING: SSL verification is disabled - this is insecure for production!");
        }
        
        try {
            // Step 1: Get encrypted challenge from server
            $this->log("\n=== Step 1: Requesting Challenge from Server ===");
            $this->log("Sending GET request to: " . $this->serverUrl);
            
            $challengeResponse = $this->makeRequest($this->serverUrl);
            
            $this->log("✓ Received response from server");
            
            $challengeData = json_decode($challengeResponse, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("Invalid JSON response from server: " . json_last_error_msg());
            }

            // DEBUG: Check what the server actually returned (only in debug mode)
            if ($this->debug && $challengeData['status'] === 'error') {
                $this->log("❌ SERVER ERROR DETAILS:");
                $this->log("Error message: " . ($challengeData['message'] ?? 'No message'));
                $this->log("Remaining attempts: " . ($challengeData['remaining_attempts'] ?? 'unknown'));
                if (isset($challengeData['block_time_remaining'])) {
                    $this->log("Block time remaining: " . $challengeData['block_time_remaining'] . " seconds");
                }
            }

            // Validate server response structure
            $this->validateServerResponse($challengeData);
            
            if ($challengeData['status'] !== 'challenge') {
                throw new Exception("Unexpected server response. Expected 'challenge', got: " . $challengeData['status']);
            }
            
            if (!isset($challengeData['challenge'])) {
                throw new Exception("No challenge in server response");
            }
            
            $encryptedChallenge = $challengeData['challenge'];
            $this->log("✓ Encrypted challenge received");
            $this->log("Remaining attempts: " . ($challengeData['remaining_attempts'] ?? 'unknown'));
            
            // Step 2: Decrypt the challenge
            $this->log("\n=== Step 2: Decrypting Challenge ===");
            $challenge = $this->decryptChallenge($encryptedChallenge);
            
            // Step 3: Sign the decrypted challenge
            $this->log("\n=== Step 3: Signing the Challenge ===");
            $privateKey = $this->loadPrivateKey();
            $signature = $this->signData($challenge, $privateKey);
            
            // Step 4: Send signature and encrypted challenge back to server
            $this->log("\n=== Step 4: Sending Response to Server ===");
            $this->log("Sending POST request to: " . $this->serverUrl);
            
            $postData = [
                'signature' => $signature,
                'challenge' => $encryptedChallenge
            ];
            
            // Reset rate limit timer for authentication flow steps
            $this->lastRequestTime = 0;
            
            $response = $this->makeRequest($this->serverUrl, $postData);
            $this->log("✓ Final response received");
            
            $result = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                $error = json_last_error_msg();
                throw new Exception("Invalid JSON in final response: " . $error);
            }
            
            // Validate final server response
            $this->validateServerResponse($result);
            
            // Clean up
            openssl_free_key($privateKey);
            
            return $result;
            
        } catch (Exception $e) {
            $this->log("❌ ERROR: " . $e->getMessage());
            
            if ($this->debug) {
                $this->log("Backtrace:");
                debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
            }
            
            return [
                'status' => 'error', 
                'message' => $e->getMessage()
            ];
        }
    }
}

// ==========================================
// MAIN EXECUTION
// ==========================================

if ($debugMode) {
    echo "==================================================\n";
    echo "🔐 SECURE CLIENT AUTHENTICATION DEBUG SCRIPT\n";
    echo "==================================================\n";
    echo "Start time: " . date('Y-m-d H:i:s') . "\n";
    echo "PHP Version: " . PHP_VERSION . "\n";
    echo "OpenSSL Version: " . OPENSSL_VERSION_TEXT . "\n\n";
    
    echo "=== Configuration ===\n";
    echo "Private Key Path: " . $privateKeyPath . "\n";
    echo "Server URL: " . $serverUrl . "\n";
    echo "Debug Mode: " . ($debugMode ? "ON" : "OFF") . "\n";
    echo "SSL Verification: " . ($verifySSL ? "ENABLED" : "DISABLED") . "\n";
    echo "Key exists: " . (file_exists($privateKeyPath) ? "Yes" : "No") . "\n";
    echo "Key readable: " . (is_readable($privateKeyPath) ? "Yes" : "No") . "\n\n";
}

// Run the authentication
$client = new ClientAuthenticator($privateKeyPath, $serverUrl, $sharedSecret, $debugMode, $verifySSL);
$result = $client->authenticateAndGetData();

// Display final result
if ($debugMode) {
    echo "\n" . str_repeat("=", 50) . "\n";
    echo "🎯 FINAL RESULT\n";
    echo str_repeat("=", 50) . "\n";
}

if ($result['status'] === 'success') {
    echo "✅ AUTHENTICATION SUCCESSFUL!\n";
    echo "Data received:\n";
    print_r($result['data']);
} else {
    echo "❌ AUTHENTICATION FAILED\n";
    echo "Error: " . ($result['message'] ?? 'Unknown error') . "\n";
    if (isset($result['remaining_attempts'])) {
        echo "Remaining attempts: " . $result['remaining_attempts'] . "\n";
    }
}

if ($debugMode) {
    echo "\n" . str_repeat("=", 50) . "\n";
    echo "End time: " . date('Y-m-d H:i:s') . "\n";
    echo "Script completed.\n";
}
?>
