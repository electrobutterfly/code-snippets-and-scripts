# Secure Public Key Server/Client Authentication System



## Overview

A robust challenge-response authentication system using RSA key pairs and encrypted challenges for secure server-to-server communication. Perfect for API protection, automated scripts, and secure data access.



## Quick Start

### 1. File Structure Summary

```text
/your-server/
├── server.php           # Server authentication endpoint
└── keys/
    ├── .htaccess        # Secure access to the directory
    └── dummy.pub         # Public key
    
    
/client-directory/
├── client.php           # Client authentication script
└── keys/
    ├── dummy.key         # Private key (keep secure!)
    └── .htaccess        # Secure access to the directory
```



### 2. Generate RSA Key Pair

```bash
# Create keys directory
mkdir -p keys
cd keys

# Generate private key (no password for automation)
openssl genrsa -out dummy.key 2048

# Generate public key from private key
openssl rsa -in dummy.key -pubout -out dummy.pub

# Set secure permissions
chmod 600 dummy.key  # Private: owner read-only
chmod 644 dummy.pub  # Public: world-readable
```



### 3. Server Configuration (`server.php`)

```php
$publicKeyPath = './keys/dummy.pub';
$sharedSecret = 'your_64_character_secure_random_secret';
$debugMode = true;  // Set to false in production
```



### 4. Client Configuration (`client.php`)

```php
$privateKeyPath = './keys/dummy.key';
$serverUrl = 'https://yourserver.com/server.php';
$sharedSecret = 'your_64_character_secure_random_secret'; // Same as server
$debugMode = true;
```



## How It Works

### Authentication Flow

1. **Client** requests challenge from server (GET)
2. **Server** generates encrypted time-bound challenge
3. **Client** decrypts challenge, signs it with private key
4. **Client** sends signature back to server (POST)
5. **Server** verifies signature with public key
6. **Access granted** to protected resources



## Usage Examples

### Example 1: Basic Authentication

```php
// Simple client usage
$client = new ClientAuthenticator(
    './keys/dummy.key',
    'https://api.example.com/server.php',
    'your_shared_secret'
);

$result = $client->authenticateAndGetData();

if ($result['status'] === 'success') {
    echo "Access granted! Data: " . print_r($result['data'], true);
} else {
    echo "Access denied: " . $result['message'];
}
```



### Example 2: Database Gateway

```php
// Protect database access
class SecureDatabase {
    public function query($sql) {
        // First authenticate
        $client = new ClientAuthenticator(...);
        $auth = $client->authenticateAndGetData();
        
        if ($auth['status'] !== 'success') {
            throw new Exception('Authentication required');
        }
        
        // Now execute sensitive query
        return $this->pdo->query($sql);
    }
}
```



### Example 3: API Protection

```php
// In your API endpoint
require_once 'server.php';

$authenticator = new PublicKeyAuthenticator($publicKeyPath, $sharedSecret);

if ($_POST['action'] === 'get_data') {
    $authResult = $authenticator->verifyRequest($_POST);
    
    if ($authResult['authenticated']) {
        // Return sensitive data
        $sensitiveData = [
            'users' => $db->getAllUsers(),
            'financials' => $db->getFinancialRecords()
        ];
        echo json_encode($sensitiveData);
    }
}
```



## Security Configuration

### Rate Limiting Settings

```php
// In server.php - Adjust as needed
$maxChallengesPerMinute = 60;    // Challenge requests per minute
$maxConsecutiveFailures = 5;     // Auth failures before block
$failureWindow = 900;            // 15-minute failure window  
$blockDuration = 1800;           // 30-minute block duration
$challengeTimeout = 300;         // 5-minute challenge expiry
$maxStorageSize = 100 * 1024 * 1024; // 100MB maximum storage for rate limits
```



### File Security

```bash
# Critical: Set proper permissions
chmod 600 keys/dummy.key      # Private key: owner read-only
chmod 644 keys/dummy.pub      # Public key: world-readable  
chmod 755 server.php         # Server script: executable
chmod 755 client.php         # Client script: executable

# Verify permissions
ls -la keys/
# Should show:
# -rw------- dummy.key  (private key)
# -rw-r--r-- dummy.pub  (public key)
```



## Troubleshooting

### Common Issues

**Permission Errors:**

```bash
# Fix: Set correct ownership
chown www-data:www-data keys/dummy.pub  # Ubuntu web server
chown apache:apache keys/dummy.pub      # CentOS web server
```



**Key Generation Problems:**

```bash
# Verify key pair matches
openssl rsa -in dummy.key -pubout -out generated.pub
diff generated.pub dummy.pub  # Should show no differences
```



**SSL Certificate Issues:**

```php
// For testing only (remove in production)
$verifySSL = false;

// Production fix: Ensure valid SSL certificate
$verifySSL = true;
```



**Debug Mode:**

```php
// Enable detailed logging
$debugMode = true;
// Check server error logs for AUTH_DEBUG messages
```



### Error Messages

- `"Too many authentication failures"` - Wait 30 minutes or check credentials

- `"Challenge expired"` - Complete authentication within 5 minutes

- `"Invalid signature"` - Verify private key matches public key

- `"Shared secret mismatch"` - Ensure identical secrets on both sides

  

## Security Best Practices

### Key Management

- **Generate 2048-bit or higher RSA keys**
- **Store private keys with `600` permissions**
- **Never commit keys to version control**
- **Rotate keys every 6-12 months**
- **Use different key pairs for different environments**

### Network Security

- **Always use HTTPS in production**
- **Implement firewall rules to restrict access**
- **Use VPN for internal server communication**
- **Monitor authentication attempts**

### Application Security

- **Keep challenge timeouts short (5 minutes recommended)**
- **Use long, cryptographically random shared secrets**
- **Implement proper logging and monitoring**
- **Regular security audits**



## Why This is Secure

### Security Features

- ✅ **No passwords transmitted** - Uses cryptographic proofs

- ✅ **Challenge-response protocol** - Prevents replay attacks

- ✅ **Challenges Are Cryptographically Secure**

  - Each challenge contains 256 bits of true randomness (`random_bytes(32)`)
  - Even with millions of challenges, no pattern can be found
  - The randomness comes from your system's cryptographically secure random generator

- ✅ **Time-bound challenges** - 5-minute expiration

- ✅ **Failure-based rate limiting** - Blocks after 5 consecutive failures

- ✅ **Encrypted challenges** - AES-256-CBC with random IV

- ✅ **RSA-SHA256 signatures** - Industry-standard cryptography

- ✅ **Without the Shared Secret, Challenges Are Useless**

- ✅ **An attacker can request challenges all day, but they cannot:**

  - Decrypt the challenge (needs shared secret)

  - Sign the decrypted challenge (needs private key)
  
  - Use old challenges (5-minute expiration)
  
  - Send requests from many different IP addresses
  
  - Send requests with random identifiers
  
  - Quickly fill the filesystem with rate limit files
  
  - Cause disk space exhaustion or filesystem performance degradation
  
    

## Support

For issues:

1. Enable debug mode (`$debugMode = true`)

2. Check server error logs

3. Verify file permissions and paths

4. Ensure OpenSSL extension is enabled

5. Please report any issues and bugs found at the [Issue Tracker](https://github.com/electrobutterfly/code-snippets-and-scripts/issues)

   

This system provides enterprise-grade security for automated authentication while maintaining simplicity of implementation.



## Authors and acknowledgment

© 2025 Klaus Simon.



## License

This project is licensed under the Custom Attribution-NonCommercial Sale License.

**You are free to:**

- Use, modify, and share the code for any purpose (personal, educational, commercial).
- Incorporate it into your own projects.

<u>**The main restriction:**</u>

- You cannot sell a product **whose primary purpose is to resell this software's functionality**.

**For commercial sale licensing,** please contact: licensing@electrobutterfly.com

*See the [LICENSE](./LICENSE) file for full terms.*



## Project status

Software, Code snippets or scripts might be added from time to time as my work progress goes on
and I decide to make the code public.

------

<img src="https://electrobutterfly.com/images/logo-small-github.png" alt="Logo" style="float:left; margin-right:10px; width:150px;">
