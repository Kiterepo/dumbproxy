dumbproxy
=========

[![dumbproxy](https://snapcraft.io//dumbproxy/badge.svg)](https://snapcraft.io/dumbproxy)

Dumbiest HTTP proxy ever.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Deployment with a single self-contained binary
* Zero-configuration
* Supports CONNECT method and forwarding of HTTPS connections
* Supports `Basic` proxy authentication
* Supports TLS operation mode (HTTP(S) proxy over TLS)
* Supports client authentication with client TLS certificates
* Supports HTTP/2
* Resilient to DPI (including active probing, see `hidden_domain` option for authentication providers)

## Installation

#### Binary download

Pre-built binaries available on [releases](https://github.com/Snawoot/dumbproxy/releases/latest) page.

#### From source

Alternatively, you may install dumbproxy from source. Run within source directory

```
go install
```

#### Docker

Docker image is available as well. Here is an example for running proxy as a background service:

```sh
docker run -d \
    --security-opt no-new-privileges \
    -p 8080:8080 \
    --restart unless-stopped \
    --name dumbproxy \
    yarmak/dumbproxy
```

#### Snap Store

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/dumbproxy)

```bash
sudo snap install dumbproxy
```

## Usage

Just run program and it'll start accepting connections on port 8080 (default).

Example: run proxy on port 1234 with `Basic` authentication with username `admin` and password `123456`:

```sh
dumbproxy -bind-address :1234 -auth 'static://?username=admin&password=123456'
```

## Using HTTP-over-TLS proxy

It's quite trivial to set up program which supports proxies to use dumbproxy in plain HTTP mode. However, using HTTP proxy over TLS connection with browsers is little bit tricky. Note that TLS must be enabled (`-cert` and `-key` options) for this to work.

### Routing all browsers on Windows via HTTPS proxy

Open proxy settings in system's network settings:

![win10-proxy-settings](https://user-images.githubusercontent.com/3524671/83258553-216f7700-a1bf-11ea-8af9-3d8aed5b2e71.png)

Turn on setup script option and set script address:

```
data:,function FindProxyForURL(u, h){return "HTTPS example.com:8080";}
```

where instead of `example.com:8080` you should use actual address of your HTTPS proxy.

Note: this method will not work with MS Edge Legacy.

### Firefox

Option 1: inline PAC file in settings. Open Firefox proxy settings, switch proxy mode to "Automatic proxy configuration URL". Specify URL:

```
data:,function FindProxyForURL(u, h){return "HTTPS example.com:8080";}
```

![ff_https_proxy](https://user-images.githubusercontent.com/3524671/82768442-afea9e00-9e37-11ea-80fd-1eccf55b89fa.png)

Option 2: use any proxy switching browser extension which supports HTTPS proxies like [this one](https://addons.mozilla.org/ru/firefox/addon/switchyomega/).

### Chrome

Option 1: specify proxy via command line:

```
chromium-browser --proxy-server='https://example.com:8080'
```

Option 2: use any proxy switching browser extension which supports HTTPS proxies like [this one](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif).

### Other applications

It is possible to expose remote HTTPS proxy as a local plaintext HTTP proxy with help of external application which performs remote communication via TLS and exposes local plaintext socket. [steady-tun](https://github.com/Snawoot/steady-tun) appears to be most suitable for this because it supports connection pooling to hide connection delay.

## Authentication

Authentication parameters are passed as URI via `-auth` parameter. Scheme of URI defines authentication metnod and query parameters define parameter values for authentication provider.

* `none` - no authentication. Example: `none://`. This is default.
* `static` - basic authentication for single login and password pair. Example: `static://?username=admin&password=123456`. Parameters:
  * `username` - login.
  * `password` - password.
  * `hidden_domain` - if specified and is not an empty string, proxy will respond with "407 Proxy Authentication Required" only on specified domain. All unauthenticated clients will receive "400 Bad Request" status. This option is useful to prevent DPI active probing from discovering that service is a proxy, hiding proxy authentication prompt when no valid auth header was provided. Hidden domain is used for generating 407 response code to trigger browser authorization request in cases when browser has no prior knowledge proxy authentication is required. In such cases user has to navigate to any hidden domain page via plaintext HTTP, authenticate themselves and then browser will remember authentication.
* `basicfile` - use htpasswd-like file with login and password pairs for authentication. Such file can be created/updated like this: `touch /etc/dumbproxy.htpasswd && htpasswd -bBC 10 /etc/dumbproxy.htpasswd username password`. `path` parameter in URL for this provider must point to a local file with login and bcrypt-hashed password lines. Example: `basicfile://?path=/etc/dumbproxy.htpasswd`.
  * `path` - location of file with login and password pairs. File format is similar to htpasswd files. Each line must be in form `<username>:<bcrypt hash of password>`. Empty lines and lines starting with `#` are ignored.
  * `hidden_domain` - same as in `static` provider
* `cert` - use mutual TLS authentication with client certificates. In order to use this auth provider server must listen sockert in TLS mode (`-cert` and `-key` options) and client CA file must be specified (`-cacert`). Example: `cert://`.

## Synopsis

```
$ ~/go/bin/dumbproxy -h
  -auth string
    	auth parameters (default "none://")
  -bind-address string
    	HTTP proxy listen address (default ":8080")
  -cafile string
    	CA file to authenticate clients with certificates
  -cert string
    	enable TLS and use certificate
  -key string
    	key for TLS certificate
  -timeout duration
    	timeout for network operations (default 10s)
  -verbosity int
    	logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical) (default 20)
```
