# ACME clients

Each issuer has its own directory: `https://ca.home.lab/acme/<slug>/directory`. The UI shows it on the issuer page with a copy button. Clients must trust Conrad's root, both to talk to the ACME endpoint and to use the certificates they get.

```sh
curl -k https://ca.home.lab/roots/current.pem -o conrad-root.pem
```

`/roots/current.crt` (DER), `.pem` and `.mobileconfig` (Apple devices) are also available.

## certbot

```sh
sudo REQUESTS_CA_BUNDLE=/path/conrad-root.pem certbot certonly --standalone \
  --server https://ca.home.lab/acme/default/directory -d nas.home.lab
```

Or install the root system-wide (`/usr/local/share/ca-certificates/` + `update-ca-certificates`) and drop `REQUESTS_CA_BUNDLE`. Renewal works with the usual `certbot renew` timer.

## acme.sh

```sh
acme.sh --issue --standalone -d nas.home.lab \
  --server https://ca.home.lab/acme/default/directory --ca-bundle /path/conrad-root.pem
```

## Caddy

```caddyfile
{
	acme_ca https://ca.home.lab/acme/default/directory
	acme_ca_root /etc/caddy/conrad-root.pem
}
nas.home.lab {
	reverse_proxy localhost:5000
}
```

## Traefik

```yaml
certificatesResolvers:
  conrad:
    acme:
      caServer: https://ca.home.lab/acme/default/directory
      email: you@home.lab
      storage: /data/acme.json
      tlsChallenge: {}
```

Set `LEGO_CA_CERTIFICATES=/path/conrad-root.pem` in Traefik's environment.

## cert-manager

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: conrad
spec:
  acme:
    server: https://ca.home.lab/acme/default/directory
    caBundle: <base64 of conrad-root.pem>
    privateKeySecretRef:
      name: conrad-account
    solvers:
      - http01:
          ingress:
            ingressClassName: traefik
```

## External Account Binding

If an issuer's policy requires EAB, create a key under **ACME → EAB keys** and pass it to the client:

```sh
certbot ... --eab-kid <kid> --eab-hmac-key <hmac>
```

## Challenges and policy

- **http-01:** Conrad fetches `http://<name>/.well-known/acme-challenge/…` on port 80.
- **tls-alpn-01:** Conrad connects to `<name>:443`.
- **dns-01:** Conrad looks up `_acme-challenge.<name>` TXT through `CONRAD_DNS_RESOLVERS` or the system resolver.

The default policy allows `*.home.lab`, `*.lan` and `*.internal`. Change allowed domains, wildcards, IP addresses, key types, validity and rate limits per issuer from its page.
