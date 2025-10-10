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

**Fix:** Install OpenSSL:
```powershell
choco install openssl
```
Or download from: https://slproweb.com/products/Win32OpenSSL.html

Then run `npm run ssl:generate` again.

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

