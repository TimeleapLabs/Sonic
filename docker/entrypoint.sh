#!/bin/sh

sonicd --datadir /app/data \
  --config /app/config.toml \
  --validator.id="$SONIC_VALIDATOR_ID" \
  --validator.pubkey="$SONIC_PUBKEY" \
  --validator.password="/app/key" \
  --http \
  --http.api=eth,debug,net,admin,web3,personal,txpool,ftm,dag,sfc
