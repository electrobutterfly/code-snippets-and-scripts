# Simple CORS Proxy Server

## Overview

This script sets up a **CORS Anywhere proxy server** that acts as an intermediary to bypass Cross-Origin Resource Sharing (CORS) restrictions in web browsers. CORS is a security mechanism that prevents web pages from making requests to domains different from their own, which can be problematic during development or when accessing APIs from client-side JavaScript.



## What It Does

- **🌐 HTTP Proxy**: Listens on port 8080 for HTTP requests
- **🔒 HTTPS Proxy**: Listens on port 8443 for HTTPS requests (if certificates are available)
- **🔄 CORS Bypass**: Adds appropriate CORS headers to responses, allowing cross-origin requests
- **🍪 Cookie Removal**: Strips cookies from forwarded requests for enhanced privacy
- **🌍 Universal Access**: Binds to `0.0.0.0` making it accessible from any network interface



## Prerequisites

1. **🟢 Node.js** installed on your system
2. **📦 npm** (Node Package Manager) - comes with Node.js



## Setup Steps

### 1. 📥 Install Dependencies

```bash
npm install cors-anywhere
```

### 2. 🔐 SSL Certificates (Optional, for HTTPS)

For HTTPS functionality (port 8443), you need an SSL certificates:

server.key - Private key file
server.cert - Certificate file

For testing, create a self-signed SSL certificate in the same directory as the server or use your own:

```bash
openssl req -nodes -new -x509 -keyout server.key -out server.cert
```

Or for a more proper certificate (if you have a domain):

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.cert -days 365 -nodes -subj "/CN=your-domain.com"

```

If you get file permission error with the server key:

```bash
sudo chmod 640 server.key
sudo chown root:node server.key
```



### 3. 📁 File Structure

Ensure your project directory contains:

```text
📁 your-project/
├── 📄 server.js          (main server script)
├── 🔑 server.key         (optional, for HTTPS - private key)
└── 📜 server.cert        (optional, for HTTPS - certificate file)
```



## Running the Server

### 🚀 Basic Execution

```bash
node server.js
```



### ✅ Expected Output

```text
🌐 CORS Anywhere HTTP running on http://0.0.0.0:8080
🔒 CORS Anywhere HTTPS running on https://0.0.0.0:8443  (if certificates exist)
```



## Usage Examples

Once running, you can use it as a proxy by prefixing your target URL:

```javascript
// Instead of making a direct request to an API:
// fetch('https://api.example.com/data')

// Use the proxy:
fetch('http://localhost:8080/https://api.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```



### Common Use Cases:

**🛠️ Development**: Access third-party APIs during frontend development

**🧪 Testing**: Test API responses without CORS errors

**⚡ Prototyping**: Quickly prototype applications that consume external APIs



## Security Notes

⚠️ **Important Security Considerations**:

- This server removes CORS restrictions entirely - use carefully in production
- Running on `0.0.0.0` makes it accessible from any machine on the network
- Consider adding authentication or IP restrictions for production use
- The HTTPS version only runs if valid certificates are provided



## Stopping the Server

Press `Ctrl+C` in the terminal where the server is running to stop it.



## Issues and bugs

Please report any issues and bugs found at the [Issue Tracker](https://github.com/electrobutterfly/code-snippets-and-scripts/issues)




## Authors and acknowledgment

© 2025 Klaus Simon.



## License

This project is licensed under the [MIT License](https://opensource.org/license/MIT).

**You are free to:**

- Do anything with this software - just keep my name in it.
- No restrictions except attribution.

*See the [LICENSE](./LICENSE) file for full terms.*



## Project status

Software, Code snippets or scripts might be added from time to time as my work progress goes on
and I decide to make the code public.

------

<img src="https://electrobutterfly.com/images/logo-small-github.png" alt="Logo" style="float:left; margin-right:10px; width:150px;">
