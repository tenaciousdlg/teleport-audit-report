# tbot bootstrap

`tbot.yaml` (gitignored — contains the join token) is generated from
`tbot.yaml.tmpl` and your `.env`.

1. After `terraform apply` in `../terraform`, get the join token and paste
   it into `.env`'s `BOT_JOIN_TOKEN=` line:

   ```sh
   cd terraform && terraform output -raw join_token && cd ..
   ```

2. From the repo root, generate `tbot.yaml`:

   ```sh
   set -a; source .env; set +a
   sed -e "s#\${PROXY_ADDR}#$PROXY_ADDR#" -e "s#\${BOT_JOIN_TOKEN}#$BOT_JOIN_TOKEN#" \
     tbot/tbot.yaml.tmpl > tbot/tbot.yaml
   ```

The join token is single-use — tbot presents it once to join, then renews
its own certs from then on. If you ever need to re-join (e.g. `terraform
apply` recreated the token), update `.env` with the new value and regenerate
`tbot.yaml`.
