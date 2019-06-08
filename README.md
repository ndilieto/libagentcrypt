# libagentcrypt 

A library that allows using the keys in the SSH Agent to perform symmetric,
authenticated encryption and decryption securely without typing passwords.
It works with both RSA and ED25519 SSH keys including those made available
to a remote host by SSH Agent forwarding.

## Documentation

The library is documented [here](https://ndilieto.github.io/libagentcrypt)

The distribution also includes a command line utility which has a unix man
page. The HTML version is [here](https://ndilieto.github.io/libagentcrypt/agentcrypt.1.html)

## Installation

Please do not use the master branch. Pristine releases are in the upstream/latest
branch, tagged as upstream/x.x.x 

The following will install the latest release

```
export PKG_URL=https://github.com/ndilieto/libagentcrypt/archive/upstream/latest.tar.gz
mkdir -p libagentcrypt
wget -O - $PKG_URL | tar zx -C libagentcrypt --strip-components=1
cd libagentcrypt
./configure --disable-maintainer-mode
make install
```

## Bugs and suggestions

If you believe you have found a bug, please log it at
https://github.com/ndilieto/libagentcrypt/issues

If you have any suggestions for improvements, pull requests are welcome.

## Copyright

libagentcrypt - Copyright (c) 2019 Nicola Di Lieto

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyright notice and this permission notice appear
in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
