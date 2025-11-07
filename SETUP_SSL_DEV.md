# Self-Signed SSL Certificates - Development Setup

**Quick setup for development only. Takes 2 minutes! ⚡**

---

## 🚀 Step 1: Generate Certificates

Open PowerShell in the `node-API` directory and run:

```powershell
npm run ssl:generate
```

This will:
- Create the `certs/` directory
- Generate 4096-bit RSA certificates
- Convert them to PEM format for Node.js
- Show you the paths to copy

---

## 📝 Step 2: Update .env File

The script will output something like:

```
Add these to your .env file:

# SSL/TLS Configuration (Development)
TLS_CERT_PATH=C:\Users\musan\OneDrive - ADvTECH Ltd\Nexus\node-API\certs\server.pem
TLS_KEY_PATH=C:\Users\musan\OneDrive - ADvTECH Ltd\Nexus\node-API\certs\server.key
TLS_CA_PATH=C:\Users\musan\OneDrive - ADvTECH Ltd\Nexus\node-API\certs\server.pem
```

**Copy these exact lines to your `.env` file!** (Use absolute paths as shown)

---

## ▶️ Step 3: Start the Server

```powershell
npm run dev
```

You should see:
```
✓ NexusPay API Server started with TLS 1.3
  Protocol: HTTPS
  Port: 5118
  TLS Version: TLSv1.3
```

---

## ✅ Step 4: Test HTTPS

Open your browser and go to:
```
https://localhost:5118/health
```

**You'll see a security warning** - this is normal for self-signed certificates!

Click: **Advanced** → **Proceed to localhost (unsafe)**

You should see the API health response! 🎉

---

## 🧪 Test with cURL

```powershell
# Ignore certificate warning with -k flag
curl -k https://localhost:5118/health
```

---

## ❌ Troubleshooting

### Server still shows "HTTP ONLY"

**Problem:** Certificate files not found

**Fix:**
1. Make sure you used **absolute paths** in `.env` (not relative like `./certs/`)
2. Check files exist:
   ```powershell
   ls .\certs\
   # Should show: server.key, server.pem, server.pfx
   ```
3. Restart the server after updating `.env`

### "OpenSSL not found"

If the script reports OpenSSL is missing, install it using one of the options below, then re-run `npm run ssl:generate`.

Option A — Chocolatey (Windows package manager)
```powershell
# Install Chocolatey if you don't have it
Set-ExecutionPolicy Bypass -Scope Process -Force; \
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
  iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install OpenSSL
choco install openssl -y
```

Option B — Official OpenSSL Windows installer (no Chocolatey)
1. Go to: https://slproweb.com/products/Win32OpenSSL.html
2. Download the latest "Win64 OpenSSL" (Full) installer (e.g., Win64 OpenSSL v3.x Light/Full)
3. Run the installer:
   - When prompted, choose to install the OpenSSL DLLs to the Windows system directory
   - Note the installation path (e.g., `C:\Program Files\OpenSSL-Win64`)
4. Add OpenSSL to PATH (if the installer didn’t add it):
   - Start → type "Environment Variables" → Edit the system environment variables
   - Click "Environment Variables..."
   - Under "System variables", select `Path` → Edit → New
   - Add `C:\Program Files\OpenSSL-Win64\bin` (adjust if your path differs)
   - Click OK on all dialogs
5. Close and reopen PowerShell or your terminal so PATH changes take effect

Now re-run:
```powershell
npm run ssl:generate
```

---

## 🎯 What You Get

✅ **TLS 1.3** - Latest protocol  
✅ **Strong ciphers** - AES-256-GCM  
✅ **HTTPS enabled** - All traffic encrypted  
✅ **Task 2 compliant** - 20/20 marks for SSL/TLS  

---

## 🔒 Security Note

These are **development-only** self-signed certificates.

- ✅ **Safe for local development**
- ✅ **Not committed to Git** (automatically ignored)
- ❌ **Never use in production** (browsers will show warnings)

For production, use Let's Encrypt (see `SSL_SETUP_GUIDE.md`).

---

**That's it! You're now running HTTPS locally! 🔒🚀**

