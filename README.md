# A Repository of various useful scripts , script-snippets and complete Software written in Javascript, and PHP



## [📁 Process WPDB Geodatabase Files](./wpdb-geodatabase-processor)

The goal is to process and split the **huge geodatabase files in "geojson format"** which can be as big as 10GB each, or even much bigger, without crashing the script running out of memory. It splits hem into smaller json chunks which then can be handled better for easy injection as layers into maps by web applications. Written for node.js



## [📁 Simple CORS Proxy](./cors-proxy-simple)

This script sets up a **CORS Anywhere proxy server** that acts as an intermediary to bypass Cross-Origin Resource Sharing (CORS) restrictions in web browsers. CORS is a security mechanism that prevents web pages from making requests to domains different from their own, which can be problematic during development or when accessing APIs from client-side JavaScript. Written for node.js



## [📁 Simple CORS Proxy v.2](./cors-proxy-2)

CORS proxy server to provide cross-origin request handling with support for multiple HTTP methods.
Easy to deploy with optional HTTPS support and no external dependencies. Efficient pipe-based streaming data transfer.
Direct proxy with CORS headers only. Functionality gives you full control over your proxy infrastructure. Written for node.js



## [📁 Git Repository Synchronization Script](./repo-sync)

A specialized Bash script designed to synchronize GitHub repositories when traditional Git operations fail due to repository corruption, file rewriting, or divergent histories. This tool uses intelligent cherry-picking to bypass merge conflicts and maintain synchronization between repositories with different commit hashes.



## [📁 Secure Public Key Server/Client Authentication System](./secure-server-client)

This software written in php is a secure challenge-response authentication system that uses RSA key pairs and encrypted time-bound challenges. It enables passwordless, cryptographically verified communication between clients and servers for API protection and automated scripts. The system prevents replay attacks with 5-minute expirations and brute force with failure-based rate limiting. It's designed for secure server-to-server communication where traditional credentials are impractical.



## [📁 PolyDefense - A Hybrid SSL Authentication System](./polydefense)

This system provides robust mutual authentication between a client and server in PHP, using a hybrid approach that combines the best aspects of certificate-based and public key authentication, after passing the ip whitelist as a first line defense. It uses a challenge-response protocol with digital signatures to ensure both parties can verify each other's identity without shared secrets.



## Authors and acknowledgment

© 2025 Klaus Simon.

## License

Projects are licensed under the Custom Attribution-NonCommercial Sale License unless otherwise stated that any other License applies.

**You are free to:**

- Use, modify, and share the code for any purpose (personal, educational, commercial).
- Incorporate it into your own projects.

**The main restriction:**
- You cannot sell a product **whose primary purpose is to resell this software's functionality**.

**For commercial sale licensing,** please contact: licensing@electrobutterfly.com

*See the [LICENSE](./LICENSE) file for full terms.*

## Project status

Software, Code snippets or scripts might be added from time to time as my work progress goes on
and I decide to make the code public for everyone to use.

------

<img src="https://electrobutterfly.com/images/logo-small-github.png" alt="Logo" style="float:left; margin-right:10px; width:150px;">
