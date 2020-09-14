# Install PBC & gmp

## Install pbc library
From https://crypto.stanford.edu/pbc/download.html
Download: pbc-0.5.14.tar.gz

```bash
./configure
make
sudo make install
```

## Install gmp

Install brew

```bash
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install gmp
```

## LSSS Signtrue and Crypto with pbc library

* Language : Golang
