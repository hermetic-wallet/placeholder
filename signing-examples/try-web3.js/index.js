const Web3 = require("web3");
const web3 = new Web3('ws://localhost:8545');

web3.eth.accounts.signTransaction({
	nonce: '0',
	chainID: '1',
	to: '0x0475F0d4a405A79b58f302BD22ECbdAF35B1759e',
	value: '1000000000',
	gas: '21000',
	maxPriorityFeePerGas: '1000000000',
	maxFeePerGas: '15000000000',
}, '0x0100000000000000000000000000000000000000000000000000000000000000')
.then(console.log);

web3.eth.accounts.signTransaction({
    to: '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55',
    value: '1000000000',
    gas: 2000000
}, '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318')
.then(console.log);
