# 🚀 CORS Proxy Server Setup Guide



## 📋 Prerequisites



### 🔧 Required Software

- **Node.js** (version 14 or higher)
  - Download from: [nodejs.org](https://nodejs.org/)
  - Verify installation: `node --version`



### 📁 Project Structure

```text
cors-proxy/
├── 🟨 server.js                 # Main server file
├── 🔐 server.key (optional)     # HTTPS private key
├── 🔒 server.cert (optional)    # HTTPS certificate
└── 📄 README.md                 # Documentation
```



## 🛠️ Installation Steps



### 1. 📥 Download the Script

```bash
# Create project directory
mkdir cors-proxy
cd cors-proxy

# Save the server.js file in this directory
```



### 2. 🏃‍♂️ Run the Server

#### Basic HTTP Server:

```bash
node server.js
```



#### Using Environment Variables:

```bash
# Change default ports
PORT=3000 HTTPS_PORT=3443 node server.js
```



### 3. 🔐 Optional HTTPS Setup (Recommended for Production)



#### Generate Self-Signed Certificates:

```bash
openssl req -nodes -new -x509 -keyout server.key -out server.cert -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```



#### Certificate Locations Checked:

- `./server.key` and `./server.cert`
- `./certs/server.key` and `./certs/server.cert`
- `/usr/local/lib/node_modules/cors-anywhere/server.key` and `.cert`



## 🌐 Usage Examples



### Method 1: 🎯 Using `/raw` Endpoint (Recommended)

```javascript
// Fetch from any URL with CORS headers
fetch('http://localhost:8080/raw?url=https://api.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```



### Method 2: 🔗 Using Path-based Proxy

```javascript
// Alternative syntax
fetch('http://localhost:8080/https://api.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```



### Method 3: 📤 POST Requests

```javascript
// POST data through proxy
fetch('http://localhost:8080/raw?url=https://api.example.com/endpoint', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ key: 'value' })
});
```



## 🎮 API Endpoints

| Endpoint | Method | Parameters       | Description                     |
| :------- | :----- | :--------------- | :------------------------------ |
| `/raw`   | 🟢 GET  | `url` (required) | Proxy any URL with CORS headers |
| `/raw`   | 🟠 POST | `url` (required) | Proxy POST requests             |
| `/{url}` | 🟢 GET  | -                | Path-based proxy (URL in path)  |
| `/{url}` | 🟠 POST | -                | Path-based POST proxy           |



## ⚙️ Configuration

### Environment Variables

```bash
export PORT=3000           # HTTP port (default: 8080)
export HTTPS_PORT=3443     # HTTPS port (default: 8443)
```



### 🔧 Server Features

- ✅ **CORS Headers** - Automatic `Access-Control-Allow-Origin: *`
- ✅ **Multiple HTTP Methods** - GET, POST, PUT, PATCH, DELETE
- ✅ **Preflight Support** - Handles OPTIONS requests
- ✅ **Timeout Handling** - 30-second request timeout
- ✅ **Error Handling** - Comprehensive error responses
- ✅ **HTTPS Support** - Optional SSL/TLS encryption



## 🚦 Verification

### Test the Server

```bash
# Test basic functionality
curl "http://localhost:8080/raw?url=https://httpbin.org/json"

# Test CORS headers
curl -I "http://localhost:8080/raw?url=https://httpbin.org/json"
```



### Expected Output

```json
{
  "slideshow": {
    "author": "Yours Truly",
    "date": "date of publication",
    "slides": [...],
    "title": "Sample Slide Show"
  }
}
```



### Example

Return an HTML page that includes an iframe whose src is set to the raw endpoint for the same URL.
So, for a request to `/https://httpbin.org/json`, we return:

```html
<!DOCTYPE html>
<html>
<head>
    <title>CORS Proxy</title>
    <style>
        body, html, iframe {
            margin: 0;
            padding: 0;
            border: 0;
            width: 100%;
            height: 100%;
        }
    </style>
</head>
<body>
    <iframe src="/raw?url=https://httpbin.org/json"></iframe>
</body>
</html>
```

This way, the iframe will load the raw content and the browser will handle the content according to its Content-Type. So if the content is HTML, it will be rendered in the iframe. If it's JSON, the browser's built-in JSON viewer will show it.

But note: the raw endpoint returns the content with the original Content-Type, so the iframe will display it appropriately.

- `/raw?url=...` -> raw content
- `/?url=...` -> raw content (because it uses `handleRawRequest`)
- `/https://...` -> HTML page with iframe



## 🛡️ Security Notes

- 🌐 **Public Access**: Server binds to `0.0.0.0` (accessible from any network)
- ⚠️ **No Authentication**: Anyone can use your proxy server
- 🔒 **HTTPS Recommended**: Use HTTPS in production environments
- 🕒 **Timeout Protection**: 30-second timeout prevents hanging requests



## 🐛 Troubleshooting

### Common Issues:

1. **Port Already in Use**

   ```bash
   Error: listen EADDRINUSE :::8080
   ```

   **Solution**: Change port using `PORT=3000 node server.js`

   

2. **Certificate Errors (HTTPS)**

   ```bash
   HTTPS not available: ENOENT: no such file or directory
   ```

   **Solution**: Generate certificates or run HTTP-only

   

3. **Network Access Denied**

   ```bash
   Proxy error: Error: connect ECONNREFUSED
   ```

   **Solution**: Check target URL and network connectivity



### 🔍Debug Mode

```bash
# Enable verbose logging
DEBUG=* node server.js
```



## 📊 Performance

- ⚡ **Lightweight**: No external dependencies
- 🔄 **Streaming**: Efficient pipe-based data transfer
- 🎯 **Minimal Overhead**: Direct proxy with CORS headers only



## 🚀 Production Deployment

### Using PM2 (Recommended):

```bash
# Install PM2
npm install -g pm2

# Start as daemon
pm2 start server.js --name "cors-proxy"

# Save process list
pm2 save

# Setup startup script
pm2 startup
```



### Using Docker:

```dockerfile
FROM node:18-alpine
COPY server.js .
EXPOSE 8080 8443
CMD ["node", "server.js"]
```



------

## 🎉 Success!

Your CORS proxy server is now running and ready to handle cross-origin requests! 🚀

**Default URLs:**

- 🔗 HTTP: `http://localhost:8080`
- 🔐 HTTPS: `https://localhost:8443` (if certificates configured)





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
