# NexusPay SSL/TLS Certificate Generation Script (PowerShell)
# This script generates self-signed certificates for development/testing

Write-Host "========================================" -ForegroundColor Green
Write-Host "NexusPay SSL Certificate Generator" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Create certs directory if it doesn't exist
$CertsDir = ".\certs"
if (-not (Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
}

Write-Host "[1/3] Generating self-signed certificate..." -ForegroundColor Yellow

# Generate self-signed certificate
$Cert = New-SelfSignedCertificate `
    -Subject "CN=localhost, O=NexusPay International, L=Johannesburg, S=Gauteng, C=ZA" `
    -DnsName @("localhost", "*.localhost", "127.0.0.1") `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddDays(365) `
    -KeyLength 4096 `
    -HashAlgorithm "SHA256" `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -Type SSLServerAuthentication

Write-Host "[2/3] Exporting certificate and private key..." -ForegroundColor Yellow

# Export certificate (public key)
$CertPath = Join-Path $CertsDir "server.crt"
Export-Certificate -Cert $Cert -FilePath $CertPath -Type CERT | Out-Null

# Export private key with password
$KeyPath = Join-Path $CertsDir "server.pfx"
$Password = ConvertTo-SecureString -String "nexuspay-dev-2025" -Force -AsPlainText
Export-PfxCertificate -Cert $Cert -FilePath $KeyPath -Password $Password | Out-Null

Write-Host "[3/3] Converting to PEM format..." -ForegroundColor Yellow

# Check if OpenSSL is available
$OpenSSL = Get-Command openssl -ErrorAction SilentlyContinue

if ($OpenSSL) {
    $PemKeyPath = Join-Path $CertsDir "server.key"
    $PemCertPath = Join-Path $CertsDir "server.pem"
    
    # Extract private key
    & openssl pkcs12 -in $KeyPath -nocerts -out $PemKeyPath -nodes -passin pass:nexuspay-dev-2025 2>$null
    
    # Extract certificate
    & openssl pkcs12 -in $KeyPath -clcerts -nokeys -out $PemCertPath -passin pass:nexuspay-dev-2025 2>$null
    
    Write-Host ""
    Write-Host "SUCCESS: SSL certificates generated!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Certificate Details:" -ForegroundColor Green
    Write-Host "  Subject: $($Cert.Subject)" -ForegroundColor White
    Write-Host "  Thumbprint: $($Cert.Thumbprint)" -ForegroundColor White
    Write-Host "  Valid From: $($Cert.NotBefore)" -ForegroundColor White
    Write-Host "  Valid Until: $($Cert.NotAfter)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Add these to your .env file:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "# SSL/TLS Configuration (Development)" -ForegroundColor Cyan
    Write-Host "TLS_CERT_PATH=$(Resolve-Path $PemCertPath)" -ForegroundColor Cyan
    Write-Host "TLS_KEY_PATH=$(Resolve-Path $PemKeyPath)" -ForegroundColor Cyan
    Write-Host "TLS_CA_PATH=$(Resolve-Path $PemCertPath)" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "WARNING: These are self-signed certificates for DEVELOPMENT ONLY!" -ForegroundColor Red
    Write-Host "Browsers will show security warnings." -ForegroundColor Red
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "ERROR: OpenSSL not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install OpenSSL:" -ForegroundColor Yellow
    Write-Host "  Option 1: Download from https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Cyan
    Write-Host "  Option 2: Install via Chocolatey: choco install openssl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "After installing OpenSSL, run this script again." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "PFX file created at: $KeyPath" -ForegroundColor White
    Write-Host "Password: nexuspay-dev-2025" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
