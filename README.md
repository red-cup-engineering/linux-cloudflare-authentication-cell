# Linux Cloudflare Authentication Cell

One action: exchange an explicitly scoped interactive Cloudflare OAuth grant for
a verified named Wrangler profile bound to one Linux settlement directory.

The action fails closed unless Wrangler can encrypt its credential file with a
key held by the Linux Secret Service. It strips ambient Cloudflare credentials,
never prints or returns a token, and does not deploy, change DNS, or create
Cloudflare resources.

```sh
authenticate-linux-colony-with-cloudflare request.json
```

The request schema and normative action contract are in `content/`.
