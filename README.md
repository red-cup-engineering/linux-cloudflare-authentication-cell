# Linux Cloudflare Authentication Cell

One action: exchange an explicitly scoped interactive Cloudflare OAuth grant for
a verified named Wrangler profile bound to one Linux settlement directory.

The action fails closed unless Wrangler can encrypt its credential file with a
key held by the Linux Secret Service. It strips ambient Cloudflare credentials,
never prints or returns a token, and does not deploy, change DNS, or create
Cloudflare resources.

The CLI reports its profile probe, reauthorization, exact verification, and
settlement-binding transitions on stderr. Existing-profile work remains
observable until it completes, is explicitly cancelled, or reports a real
transport or process failure; it never turns into a temporal failure.

On WSL the cell owns the browser boundary. It asks Wrangler for the one-time
URL without opening or displaying it, reads that URL from a private pipe,
redacts it from terminal output, and passes the exact string as one argument to
`/usr/bin/wslview`. Copy/paste authentication and silent delegated browser
opening are refused.

```sh
authenticate-linux-colony-with-cloudflare request.json
```

The request schema and normative action contract are in `content/`.

`inspectLinuxCloudflareAuthentication` separates the conditions that older
Wrangler probes conflated: an absent `libsecret-tools` package, an absent named
profile, an unbound settlement, and an existing profile whose OAuth grant is
unavailable. Inspection reads Wrangler's non-secret directory binding and invokes
`wrangler whoami`; it does not rewrite Wrangler's directory bindings. The cell ships
`libexec/secret-tool` because Ubuntu's real `secret-tool` correctly implements
Secret Service operations but exits 2 for the non-standard `--version` probe
used by Wrangler. The wrapper answers only that probe and delegates every
credential operation unchanged to `/usr/bin/secret-tool`.
