#!/bin/bash

# NexusPay Let's Encrypt SSL Certificate Setup (Production)
# This script sets up SSL certificates using Let's Encrypt (Certbot)
# Requires: certbot installed on the system

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}NexusPay Let's Encrypt Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo -e "${RED}Error: certbot is not installed${NC}"
    echo ""
    echo -e "${YELLOW}Install certbot:${NC}"
    echo -e "  Ubuntu/Debian: ${BLUE}sudo apt-get install certbot${NC}"
    echo -e "  CentOS/RHEL:   ${BLUE}sudo yum install certbot${NC}"
    echo -e "  macOS:         ${BLUE}brew install certbot${NC}"
    echo ""
    exit 1
fi

# Get domain name
echo -e "${YELLOW}Enter your domain name (e.g., api.nexuspay.com):${NC}"
read -r DOMAIN

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Error: Domain name is required${NC}"
    exit 1
fi

# Get email for notifications
echo -e "${YELLOW}Enter your email for certificate notifications:${NC}"
read -r EMAIL

if [ -z "$EMAIL" ]; then
    echo -e "${RED}Error: Email is required${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Certificate Setup Options:${NC}"
echo "1. Standalone (requires port 80/443 to be free)"
echo "2. Webroot (if you have a web server running)"
echo "3. DNS Challenge (manual DNS verification)"
echo ""
echo -e "${YELLOW}Select option [1-3]:${NC}"
read -r OPTION

case $OPTION in
    1)
        echo ""
        echo -e "${YELLOW}Running standalone authentication...${NC}"
        echo -e "${RED}⚠️  Make sure ports 80 and 443 are not in use!${NC}"
        echo ""
        sudo certbot certonly --standalone \
            --preferred-challenges http \
            --email "$EMAIL" \
            --agree-tos \
            --no-eff-email \
            -d "$DOMAIN"
        ;;
    2)
        echo -e "${YELLOW}Enter webroot path (e.g., /var/www/html):${NC}"
        read -r WEBROOT
        
        if [ -z "$WEBROOT" ]; then
            echo -e "${RED}Error: Webroot path is required${NC}"
            exit 1
        fi
        
        echo ""
        echo -e "${YELLOW}Running webroot authentication...${NC}"
        sudo certbot certonly --webroot \
            -w "$WEBROOT" \
            --email "$EMAIL" \
            --agree-tos \
            --no-eff-email \
            -d "$DOMAIN"
        ;;
    3)
        echo ""
        echo -e "${YELLOW}Running DNS challenge...${NC}"
        echo -e "${YELLOW}You will need to add a TXT record to your DNS${NC}"
        echo ""
        sudo certbot certonly --manual \
            --preferred-challenges dns \
            --email "$EMAIL" \
            --agree-tos \
            --no-eff-email \
            -d "$DOMAIN"
        ;;
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

# Check if certificate was generated successfully
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
CA_PATH="/etc/letsencrypt/live/$DOMAIN/chain.pem"

if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo ""
    echo -e "${GREEN}✓ SSL certificate generated successfully!${NC}"
    echo ""
    echo -e "${GREEN}Certificate Details:${NC}"
    sudo openssl x509 -in "$CERT_PATH" -noout -text | grep -A 2 "Subject:"
    echo ""
    echo -e "${GREEN}Valid from:${NC}"
    sudo openssl x509 -in "$CERT_PATH" -noout -dates
    echo ""
    
    # Create symlinks in project certs directory (optional)
    CERTS_DIR="./certs"
    mkdir -p "$CERTS_DIR"
    
    echo -e "${YELLOW}Creating symlinks to certificates...${NC}"
    sudo ln -sf "$CERT_PATH" "$CERTS_DIR/letsencrypt.crt"
    sudo ln -sf "$KEY_PATH" "$CERTS_DIR/letsencrypt.key"
    sudo ln -sf "$CA_PATH" "$CERTS_DIR/letsencrypt-ca.crt"
    
    echo ""
    echo -e "${YELLOW}Add these to your .env file:${NC}"
    echo ""
    echo "# SSL/TLS Configuration (Production - Let's Encrypt)"
    echo "TLS_CERT_PATH=$CERT_PATH"
    echo "TLS_KEY_PATH=$KEY_PATH"
    echo "TLS_CA_PATH=$CA_PATH"
    echo ""
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Auto-Renewal Setup${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Let's Encrypt certificates expire in 90 days.${NC}"
    echo -e "${YELLOW}Set up automatic renewal with cron:${NC}"
    echo ""
    echo "  sudo crontab -e"
    echo ""
    echo "Add this line to run renewal check twice daily:"
    echo ""
    echo "  0 0,12 * * * certbot renew --quiet --post-hook 'systemctl restart nexuspay-api'"
    echo ""
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Setup Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo ""
    echo -e "${RED}✗ Certificate generation failed${NC}"
    echo -e "${YELLOW}Check the error messages above${NC}"
    exit 1
fi

