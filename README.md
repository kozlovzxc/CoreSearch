# CoreSearch
Search for any goodies in core dump files

# Example

# Install
Just run

    npm install

# Run
    nodejs --use-strict --harmony coreSearch.js --host localhost --core core.dump --keyfile key.pem
To test found private key

    (openssl x509 -noout -modulus -in /etc/apache2/ssl/apache.crt; openssl rsa -noout -modulus -in key.pem ) | uniq
    

# Thanks
Private key search based on https://github.com/indutny/heartbleed
