#!/bin/bash

# Needed dependencies
sudo apt-get install -y g++ m4 zlib1g-dev make p7zip lzip

# Unpack and install GMP
lzip -d gmp-6.1.2.tar.lz
tar xf gmp-6.1.2.tar
cd gmp-6.1.2
./configure
make
make check
sudo make install

# Return to Desktop
cd ..

# unpack and install NTL
gunzip ntl-11.4.3.tar.gz
tar xf ntl-11.4.3.tar
cd ntl-11.4.3/src
./configure 
make
make check
sudo make install

# Remove the unzipped directories
rm -rf gmp-6.1.2/
rm -rf ntl-11.4.3/
