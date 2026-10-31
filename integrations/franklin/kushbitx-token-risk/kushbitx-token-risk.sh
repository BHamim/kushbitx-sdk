#!/bin/sh
# Franklin PreSpend hook wrapper: runs the Node script next to this file.
exec node "$(dirname "$0")/kushbitx-token-risk.mjs"
