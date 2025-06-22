#!/bin/bash

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"method":"eth_chainId","params":[],"id":743196446,"jsonrpc":"2.0"}' \
     https://rpc.sepolia.org

curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"method":"eth_getTransactionCount","params":["0x...","latest"],"id":543603426,"jsonrpc":"2.0"}' \
	https://rpc.sepolia.org

#https://sepolia.drpc.org
#	https://eth-goerli.public.blastapi.io
