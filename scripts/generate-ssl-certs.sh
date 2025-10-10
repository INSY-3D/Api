#!/bin/bash

# NexusPay SSL/TLS Certificate Generation Script
# This script generates self-signed certificates for development/testing
# For production, use Let's Encrypt (see generate-letsencrypt.sh)

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}NexusPay SSL Certificate Generator${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Create certs directory if it doesn't exist
CERTS_DIR="./certs"
mkdir -p $CERTS_DIR

echo -e "${YELLOW}Generating self-signed SSL certificates...${NC}"
echo ""

# Certificate details
COUNTRY="ZA"
STATE="Gauteng"
CITY="Johannesburg"
ORG="NexusPay International"
ORG_UNIT="IT Security"
COMMON_NAME="localhost"
EMAIL="security@nexuspay.bank"
DAYS_VALID=365

# Generate private key
echo -e "${YELLOW}[1/4] Generating private key...${NC}"
openssl genrsa -out $CERTS_DIR/server.key 4096

# Generate certificate signing request (CSR)
echo -e "${YELLOW}[2/4] Generating certificate signing request...${NC}"
openssl req -new -key $CERTS_DIR/server.key -out $CERTS_DIR/server.csr \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$ORG_UNIT/CN=$COMMON_NAME/emailAddress=$EMAIL"

# Generate self-signed certificate
echo -e "${YELLOW}[3/4] Generating self-signed certificate...${NC}"
openssl x509 -req -days $DAYS_VALID -in $CERTS_DIR/server.csr \
  -signkey $CERTS_DIR/server.key -out $CERTS_DIR/server.crt \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1")

# Generate certificate bundle (for client verification)
echo -e "${YELLOW}[4/4] Creating certificate bundle...${NC}"
cat $CERTS_DIR/server.crt > $CERTS_DIR/server-bundle.crt
cat $CERTS_DIR/server.key >> $CERTS_DIR/server-bundle.crt

# Set proper permissions
chmod 600 $CERTS_DIR/server.key
chmod 644 $CERTS_DIR/server.crt
chmod 644 $CERTS_DIR/server.csr
chmod 600 $CERTS_DIR/server-bundle.crt

# Display certificate information
echo ""
echo -e "${GREEN}✓ SSL certificates generated successfully!${NC}"
echo ""
echo -e "${GREEN}Certificate Details:${NC}"
openssl x509 -in $CERTS_DIR/server.crt -noout -text | grep -A 2 "Subject:"
echo ""
echo -e "${GREEN}Valid from:${NC}"
openssl x509 -in $CERTS_DIR/server.crt -noout -dates
echo ""

# Create .env configuration snippet
echo -e "${YELLOW}Add these to your .env file:${NC}"
echo ""
echo "# SSL/TLS Configuration (Development)"
echo "TLS_CERT_PATH=$(pwd)/$CERTS_DIR/server.crt"
echo "TLS_KEY_PATH=$(pwd)/$CERTS_DIR/server.key"
echo "TLS_CA_PATH=$(pwd)/$CERTS_DIR/server.crt"
echo ""

echo -e "${RED}⚠️  WARNING: These are self-signed certificates for DEVELOPMENT ONLY!${NC}"
echo -e "${RED}   For production, use Let's Encrypt (run generate-letsencrypt.sh)${NC}"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

