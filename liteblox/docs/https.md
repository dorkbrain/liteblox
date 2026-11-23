# HTTPS

LiteBlox serves plain HTTP on port **53530**. For HTTPS there are two ways, and either is fine:

- **Its own HTTPS**, on port **53443**, turned on under **Settings → HTTPS**. LiteBlox makes a self-signed certificate, or uses one you import or one your own tooling keeps renewed.
- **A reverse proxy in front** (Caddy, nginx, Traefik, Nginx Proxy Manager…) that does the HTTPS and forwards to port 53530: see [Installing: HTTPS](/help/install#https). Use this when a proxy already handles your other sites and their certificates.

LiteBlox doesn't fetch certificates itself (no ACME client inside). It picks up new certificate files within seconds, so the tool you already use for Let's Encrypt can keep them renewed: [an example with certbot](#lets-encrypt-with-certbot).

## Turning it on

**1.** Publish the port in `docker-compose.yaml` and recreate the container (`docker compose up -d`):

```yaml
    ports:
      - "53530:53530"
      - "53443:53443"
```

**2.** Under **Settings → HTTPS** (admins), tick **Enable HTTPS on port 53443** and **Save**. With no certificate yet, LiteBlox makes a self-signed one for the name or address you're browsing from. To give it other names, fill in **Self-signed** first, or import a certificate.

**3.** The port opens within a few seconds. Open `https://HOST:53443`. With a self-signed certificate the browser warns until you trust it ([below](#trusting-a-self-signed-certificate)).

Plain HTTP on 53530 keeps working beside it, unless you turn on [HTTPS only](#https-only).

The tab shows whether the port is listening, the certificate (its names, issuer, dates and SHA-256 fingerprint) and, if the files didn't load, why. The Dashboard lists a certificate that expires within 30 days, one that has expired, and files that don't load.

## The certificate

### Self-signed

**Make a self-signed certificate** (or **Make a new self-signed certificate**) takes the hostnames and IP addresses you open LiteBlox with, separated by commas, for example `liteblox.lan, 192.168.1.10`. It's an ECDSA P-256 certificate, valid for 825 days (the longest that Apple devices accept for a certificate you trust by hand).

It's signed by itself, not by the certificate authority LiteBlox uses for its agents: trusting that authority in a browser would let anyone with a copy of `./data` make certificates your browser trusts for any site.

Making a new one replaces the old one at once. Browsers that trusted the old one warn again.

#### Trusting a self-signed certificate

**Download the certificate** on the tab gives `liteblox-cert.pem`. Import it into the browser or the operating system as a trusted certificate (on most systems, double-clicking it starts that), or accept the browser's warning once per browser. For [lbcli](/help/api#the-command-line-lbcli), give it with `--ca liteblox-cert.pem` instead of `--insecure`. With curl: `curl --cacert liteblox-cert.pem https://HOST:53443/…`.

### Importing one

**Import** takes either:

- a certificate in PEM (`.pem`, `.crt`), with its chain after it in the same file, and its private key in PEM; or
- one `.pfx` / `.p12` file holding both;

plus the password, if the key or the `.pfx` has one. Each file can be at most 256 KB.

LiteBlox checks it before it's used: the key belongs to the certificate, it's valid now, and the chain is put in order (the certificate first). It then shows what it found (names, issuer, dates) and notes anything odd, such as a certificate that expires within 30 days or names that don't cover the address you're browsing from. **Use it** puts it in place; nothing changes before that. The key is kept without a password.

### The files, and live updates

The certificate lives in `./data/tls/` (`/data/tls/` in the container):

| File | Holds |
|---|---|
| `cert.pem` | the certificate, then its chain (a "full chain"), in PEM |
| `key.pem` | its private key, in PEM, without a password |

LiteBlox looks at the two files every 5 seconds. When they change, it loads the new pair, and every new connection gets it, with no restart; connections already open carry on. If the new pair doesn't load (a key that doesn't match the certificate, a renewal caught halfway, a file it can't read), LiteBlox keeps serving the previous pair, tries again every 5 seconds, and says why on the tab and the Dashboard.

So anything can write these files, from the host or from another container:

- Write the **key first, then the certificate**. In between, the pair doesn't match, and LiteBlox keeps the old one until both are in place.
- They must be readable by **uid 1000** (the user LiteBlox runs as, or the one in your `user:` line).
- The tab then says the certificate was **replaced outside LiteBlox**, which is what you'd expect after a renewal.

## Let's Encrypt with certbot

A free certificate from Let's Encrypt needs a name in a public domain you control, for example `liteblox.example.com`. It can point at a private address: with a **DNS-01** challenge, Let's Encrypt checks a TXT record in your domain's public DNS, so LiteBlox never has to be reachable from the Internet.

This example runs certbot on the docker host, with Cloudflare as the domain's DNS provider. Other providers have their own certbot plugins (`python3-certbot-dns-*`), used the same way; `certbot-dns-rfc2136` works with a public BIND server and a TSIG key. Change `liteblox.example.com` and `/srv/liteblox` to yours.

**1.** Install certbot and the plugin:

```bash
sudo apt install certbot python3-certbot-dns-cloudflare
```

**2.** In Cloudflare, make an API token that can edit DNS for that zone only (**Zone → DNS → Edit**), and save it where only root can read it:

```bash
sudo install -d -m 0700 /root/.secrets
sudo sh -c 'echo "dns_cloudflare_api_token = YOUR-TOKEN" > /root/.secrets/cloudflare.ini'
sudo chmod 0600 /root/.secrets/cloudflare.ini
```

**3.** Save the hook that copies a new certificate into LiteBlox's folder as `/usr/local/bin/liteblox-cert` and make it executable (`sudo chmod 0755 /usr/local/bin/liteblox-cert`):

```sh
#!/bin/sh
# certbot deploy hook: copy a new certificate into LiteBlox (key first, then the certificate)
set -e
TLS=/srv/liteblox/data/tls
install -d -o 1000 -g 1000 -m 0700 "$TLS"
install -o 1000 -g 1000 -m 0600 "$RENEWED_LINEAGE/privkey.pem" "$TLS/key.pem"
install -o 1000 -g 1000 -m 0600 "$RENEWED_LINEAGE/fullchain.pem" "$TLS/cert.pem"
```

**4.** Get the certificate:

```bash
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d liteblox.example.com --deploy-hook /usr/local/bin/liteblox-cert
```

certbot runs the hook once now, and remembers it for every renewal.

**5.** Under **Settings → HTTPS**, tick **Enable HTTPS** if it isn't on. Within a few seconds the tab shows the Let's Encrypt certificate, "replaced outside LiteBlox".

From then on, certbot's own timer (`systemctl list-timers certbot.timer`) renews it about a month before it expires, the hook copies it in, and LiteBlox serves the new one within seconds. `sudo certbot renew --dry-run` checks that renewing works (it skips the hook). To run the hook by hand: `sudo RENEWED_LINEAGE=/etc/letsencrypt/live/liteblox.example.com /usr/local/bin/liteblox-cert`.

### With acme.sh

acme.sh does the same with its `--install-cert` step, after `--issue --dns dns_cf -d liteblox.example.com` (with `CF_Token` set):

```bash
acme.sh --install-cert -d liteblox.example.com --key-file /srv/liteblox/data/tls/key.pem \
  --fullchain-file /srv/liteblox/data/tls/cert.pem --reloadcmd "chown 1000:1000 /srv/liteblox/data/tls/*.pem"
```

## HTTPS only

**HTTPS only** stops plain HTTP from serving LiteBlox. Every page on port 53530 then answers with a short page saying HTTP isn't supported here and to use HTTPS on port 53443, and the API answers with an error saying the same. It never redirects: whoever typed the `http://` address sees why it doesn't work.

- It can only be turned on from the tab opened over LiteBlox's own HTTPS (port 53443), so you know HTTPS works in your browser before plain HTTP stops.
- The container's healthcheck (`/healthz`) keeps answering on plain HTTP.
- A reverse proxy that forwards to port 53530 gets the "HTTP isn't supported" page too. Point it at `https://HOST:53443` instead, or leave HTTPS only off.
- Turning HTTPS off turns HTTPS only off with it.

### Getting back in

If HTTPS stops working for you (a certificate the browser refuses, a port that isn't published), allow plain HTTP again from the docker host:

```bash
docker compose exec liteblox liteblox https allow-http
```

Plain HTTP works again within a few seconds. `liteblox https off` turns HTTPS off altogether. Both are written to the audit log as `cli`.

## Logins

A login belongs to one scheme. Over HTTPS the session cookie is `__Host-liteblox_session`, marked Secure; over plain HTTP it's `liteblox_session`. Browsers share cookies between ports, so keeping them apart is what lets both work at once. Logged in over HTTP, you log in once more over HTTPS.

`secure_cookies = true` in `./data/config.toml` is only for a [reverse proxy](/help/install#https): it marks the plain-HTTP cookie Secure too, which a browser then only sends over the proxy's HTTPS.

## From the command line

In the container (`docker compose exec liteblox liteblox https …`):

| Command | Does |
|---|---|
| `liteblox https status` | on or off, the port, HTTPS only, the certificate and the last error (exits 1 on an error) |
| `liteblox https allow-http` | turn HTTPS only off: plain HTTP works again |
| `liteblox https off` | turn HTTPS off, and HTTPS only with it |
| `liteblox https on [--name NAME …]` | turn HTTPS on; with no certificate yet, a self-signed one for the names given |
| `liteblox https regenerate [--name NAME …]` | a new self-signed certificate (the names saved on the tab when none are given) |

The running LiteBlox picks each change up within a few seconds. The HTTPS port is 53443 inside the container; `LITEBLOX_HTTPS_PORT` or `liteblox serve --https-port` changes it, and the compose file's `ports:` line maps it to any port on the host.
