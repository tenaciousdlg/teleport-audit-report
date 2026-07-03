# tbot bootstrap

`tbot.yaml` (gitignored — contains the join token) is generated from
`tbot.yaml.tmpl` and your `.env`. From the repo root, after
`terraform apply` in `../terraform` and `terraform output -raw join_token`:

```sh
set -a; source .env; set +a
export BOT_JOIN_TOKEN=<value from `terraform output -raw join_token`>
sed -e "s#\${PROXY_ADDR}#$PROXY_ADDR#" -e "s#\${BOT_JOIN_TOKEN}#$BOT_JOIN_TOKEN#" \
  tbot/tbot.yaml.tmpl > tbot/tbot.yaml
```

The join token is single-use — tbot presents it once to join, then renews
its own certs from then on. If you ever need to re-join (e.g. `terraform
apply` recreated the token), regenerate `tbot.yaml` with the new value.
