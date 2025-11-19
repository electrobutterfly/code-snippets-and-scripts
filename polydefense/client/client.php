<?php
//////////////////////////////////////////////////////////////////////
// client.php
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

$clientPrivateKeyPath = $_ENV['AUTH_CLIENT_PRIVATE_KEY_PATH'] ?? './keys/client.key'; // Place somewhere outside webroot
$serverPublicKeyPath = $_ENV['AUTH_SERVER_PUBLIC_KEY_PATH'] ?? './keys/server.pub'; // Place somewhere outside webroot
$clientCertificatePath = $_ENV['AUTH_CLIENT_CERTIFICATE_PATH'] ?? './keys/client.crt'; // Place somewhere outside webroot
$serverUrl = $_ENV['AUTH_SERVER_URL'] ?? 'https://electrobutterfly.com/auth/server2.php';

// TLS Configuration
$verifyPeer = false;           // Set to true in production
$verifyPeerName = false;       // Set to true in production

$debugMode = false;

// ==========================================
// HYBRID AUTHENTICATION CLIENT - DON'T MODIFY BELOW
// ==========================================

class HybridAuthClient {
    private $clientPrivateKeyPath;
    private $serverPublicKeyPath;
    private $clientCertificatePath;
    private $serverUrl;
    private $verifyPeer;
    private $verifyPeerName;
    private $debug;
    private $currentAuthStartTime = 0;
    
    public function __construct($clientPrivateKeyPath, $serverPublicKeyPath, $serverUrl, $clientCertificatePath = null, $verifyPeer = true, $verifyPeerName = true, $debug = false) {
        $this->clientPrivateKeyPath = $clientPrivateKeyPath;
        $this->serverPublicKeyPath = $serverPublicKeyPath;
        $this->clientCertificatePath = $clientCertificatePath;
        $this->serverUrl = $serverUrl;
        $this->verifyPeer = $verifyPeer;
        $this->verifyPeerName = $verifyPeerName;
        $this->debug = $debug;
    }
    
    private function log($message) {
        if ($this->debug) {
            echo $message . "\n";
        }
    }
    
    private function loadPrivateKey() {
        $this->log("=== Loading Private Key ===");
        
        if (!file_exists($this->clientPrivateKeyPath)) {
            throw new Exception("Private key not found: " . $this->clientPrivateKeyPath);
        }
        
        $privateKey = openssl_pkey_get_private("file://" . $this->clientPrivateKeyPath);
        if (!$privateKey) {
            throw new Exception("Failed to load private key");
        }
        
        $this->log("✓ Private key loaded successfully");
        return $privateKey;
    }
    
    private function signData($data, $privateKey) {
        $this->log("=== Signing Data ===");
        $this->log("Data length: " . strlen($data) . " bytes");
        
        $signature = '';
        $success = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        
        if (!$success) {
            throw new Exception("Failed to sign data");
        }
        
        $base64Signature = base64_encode($signature);
        $this->log("✓ Data signed successfully");
        
        return $base64Signature;
    }
    
    private function verifyServerChallenge($challengeData) {
        $this->log("=== Verifying Server Challenge ===");
        
        if (!file_exists($this->serverPublicKeyPath)) {
            throw new Exception("Server public key not found: " . $this->serverPublicKeyPath);
        }
        
        $publicKey = openssl_pkey_get_public("file://" . $this->serverPublicKeyPath);
        if (!$publicKey) {
            throw new Exception("Failed to load server public key");
        }
        
        $challengeString = $challengeData['challenge'] . '|' . $challengeData['timestamp'] . '|' . $challengeData['expires'] . '|' . $challengeData['server_id'];
        $result = openssl_verify($challengeString, base64_decode($challengeData['signature']), $publicKey, OPENSSL_ALGO_SHA256);
        openssl_pkey_free($publicKey);
        
        if ($result !== 1) {
            throw new Exception("Invalid server signature on challenge");
        }
        
        // Check challenge expiration
        if (time() > $challengeData['expires']) {
            throw new Exception("Challenge has expired");
        }
        
        $this->log("✓ Server challenge verified successfully");
        return true;
    }
    
    private function makeRequest($url, $postData = null) {
        $contextOptions = [
            'ssl' => [
                'verify_peer' => $this->verifyPeer,
                'verify_peer_name' => $this->verifyPeerName,
                'allow_self_signed' => !$this->verifyPeer,
            ],
            'http' => [
                'timeout' => 30,
                'ignore_errors' => true,
                'user_agent' => 'HybridAuthClient/1.0',
                'follow_location' => 0
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
    
    public function authenticateAndGetData() {
        $this->currentAuthStartTime = microtime(true);
        
        $this->log("🚀 Starting PolyDefense");
        $this->log("Server URL: " . $this->serverUrl);
        $this->log("Client Private Key: " . $this->clientPrivateKeyPath);
        $this->log("Server Public Key: " . $this->serverPublicKeyPath);
        $this->log("Client Certificate: " . ($this->clientCertificatePath ?: 'Not using certificate'));
        $this->log("Verify Peer: " . ($this->verifyPeer ? "ENABLED" : "DISABLED"));
        
        if (!$this->verifyPeer) {
            $this->log("⚠️  WARNING: Server certificate verification is disabled - this is insecure for production!");
        }
        
        try {
            // Step 1: Get challenge from server
            $this->log("\n=== Step 1: Requesting Challenge from Server ===");
            $challengeResponse = $this->makeRequest($this->serverUrl);
            
            $challengeData = json_decode($challengeResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("Invalid JSON response from server: " . json_last_error_msg());
            }
            
            if ($challengeData['status'] !== 'challenge') {
                throw new Exception("Unexpected server response. Expected 'challenge', got: " . $challengeData['status']);
            }
            
            $encryptedChallenge = $challengeData['challenge'];
            $this->log("✓ Encrypted challenge received");
            $this->log("Remaining attempts: " . ($challengeData['remaining_attempts'] ?? 'unknown'));
            
            // Step 2: Decode and verify server challenge
            $this->log("\n=== Step 2: Verifying Server Challenge ===");
            $challengeData = json_decode(base64_decode($encryptedChallenge), true);
            if (!$challengeData) {
                throw new Exception("Invalid challenge format");
            }
            
            $this->verifyServerChallenge($challengeData);
            $this->log("Challenge: " . $challengeData['challenge']);
            
            // Step 3: Sign the challenge with client private key
            $this->log("\n=== Step 3: Signing Challenge ===");
            $privateKey = $this->loadPrivateKey();
            $signature = $this->signData($challengeData['challenge'], $privateKey);
            openssl_free_key($privateKey);
            
            // Step 4: Send response to server
            $this->log("\n=== Step 4: Sending Response to Server ===");
            
            $postData = [
                'signature' => $signature,
                'challenge' => $encryptedChallenge
            ];
            
            // Include client certificate if available
            if ($this->clientCertificatePath && file_exists($this->clientCertificatePath)) {
                $postData['certificate'] = file_get_contents($this->clientCertificatePath);
                $this->log("Including client certificate in request");
            }
            
            $response = $this->makeRequest($this->serverUrl, $postData);
            $this->log("✓ Final response received");
            
            $result = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("Invalid JSON in final response: " . json_last_error_msg());
            }
            
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
        } finally {
            $this->currentAuthStartTime = 0;
        }
    }
}

// ==========================================
// MAIN EXECUTION
// ==========================================

if ($debugMode) {
    echo "==================================================\n";
    echo "🔐 POLYDEFESE HYBRID AUTHENTICATION DEBUG SCRIPT\n";
    echo "==================================================\n";
    echo "Start time: " . date('Y-m-d H:i:s') . "\n";
    echo "PHP Version: " . PHP_VERSION . "\n";
    echo "OpenSSL Version: " . OPENSSL_VERSION_TEXT . "\n\n";
    
    echo "=== Configuration ===\n";
    echo "Client Private Key: " . $clientPrivateKeyPath . "\n";
    echo "Server Public Key: " . $serverPublicKeyPath . "\n";
    echo "Client Certificate: " . ($clientCertificatePath ?: 'Not used') . "\n";
    echo "Server URL: " . $serverUrl . "\n";
    echo "Debug Mode: " . ($debugMode ? "ON" : "OFF") . "\n";
    echo "Verify Peer: " . ($verifyPeer ? "ENABLED" : "DISABLED") . "\n";
    
    // Check file existence
    echo "Client private key exists: " . (file_exists($clientPrivateKeyPath) ? "Yes" : "No") . "\n";
    echo "Server public key exists: " . (file_exists($serverPublicKeyPath) ? "Yes" : "No") . "\n";
    echo "Client certificate exists: " . (file_exists($clientCertificatePath) ? "Yes" : "No") . "\n\n";
}

// Run the hybrid authentication
$client = new HybridAuthClient(
    $clientPrivateKeyPath,
    $serverPublicKeyPath,
    $serverUrl,
    $clientCertificatePath,
    $verifyPeer,
    $verifyPeerName,
    $debugMode
);

$result = $client->authenticateAndGetData();

// Display final result
if ($debugMode) {
    echo "\n" . str_repeat("=", 50) . "\n";
    echo "🎯 FINAL RESULT\n";
    echo str_repeat("=", 50) . "\n";
}

if ($result['status'] === 'success') {
    echo "✅ HYBRID AUTHENTICATION SUCCESSFUL!\n";
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
