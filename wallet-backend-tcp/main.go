package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json" // signTypedData
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	//"github.com/ethereum/go-ethereum/common/hexutil"       // signTypedData
	"github.com/ethereum/go-ethereum/signer/core/apitypes" // signTypedData

	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"

	"log"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	//"os/exec"
)

var WalletAddress string

func setInterfaceIP() {
SETNET:
	ethName := "eth0"
	interfaces, err := net.Interfaces()
	for _, link := range interfaces {
		fmt.Println(link.Name)
		if link.Name[0] == 'e' {
			ethName = link.Name
		}
	}
	fmt.Println("starting eth =", ethName)

	lan, err := netlink.LinkByName(ethName)
	if err != nil {
		log.Print("LinkByName", err)
	}

	ipConfig := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.ParseIP("172.16.3.40"),
		Mask: net.CIDRMask(24, 32), // should be 255.255.255.0
	}}

	if err = netlink.AddrAdd(lan, ipConfig); err != nil {
		log.Print("AddrAdd", err)
	}

	if err = netlink.LinkSetUp(lan); err != nil {
		log.Print("LinkSetUp", err)
	}

	gatewayIP := net.ParseIP("172.16.3.1")

	if err = netlink.RouteAdd(&netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: lan.Attrs().Index,
		Dst:       &net.IPNet{IP: gatewayIP, Mask: net.CIDRMask(32, 32)},
	}); err != nil {
		log.Print("RouteAdd", err)
		time.Sleep(time.Second * 5)
		goto SETNET
	}
}

func main() {
	//setInterfaceIP()

	var cmd string
	scanner := bufio.NewScanner(os.Stdin)

	//cmd = "m/vivid rhythm indicate system grunt wedding champion sight invest skill detail hub"
	//goto DEVSTART

START:
	fmt.Printf("%% Create your wallet:\n> ")
	for scanner.Scan() {
		cmd = scanner.Text()
		break
	}

	//DEVSTART:

	if cmd == "restart" {
		goto START
	}

	signer, err := initiateWalletFromCmd(&cmd)
	if err != nil {
		fmt.Println("err:", err)
		goto START
	}
	fmt.Println("Opened Wallet:", signer.address)
	WalletAddress = fmt.Sprintf("%s", signer.address) // global

OPERATION:
	fmt.Printf("%% Operation:\n(nonce, gas, gasTipCap, gasFeeCap, chainID, to, amount, token)\n> ")
POST_OPERATION_PROMPT:
	for scanner.Scan() {
		cmd = scanner.Text()

		if cmd == "restart" {
			goto START
		}

		if cmd == "net" {
			goto NET
		}

		if cmd == "" {
			fmt.Printf("> ")
			goto POST_OPERATION_PROMPT
		}

		// catch eth_signTypedData_v4 (for non-net)
		if len(cmd) > 20 && cmd[:20] == "eth_signTypedData_v4" {
			raw, err := signTypedData(cmd[21:], signer)
			if err != nil {
				fmt.Println("err:", err)
				continue
			}

			//rawHex := hex.Dump(raw)
			fmt.Printf("\n0x%x\n\n", raw)

			//resp := fmt.Sprintf("0x%x", rawHex)

			continue
		} else {
			fmt.Println("|", cmd[:20], "|")

		}

		tx, err := cmdToTx(cmd, signer)
		if err != nil {
			fmt.Println("err:", err)
			goto OPERATION
		}

		raw, err := tx.MarshalBinary()
		if err != nil {
			fmt.Println("err:", err)
			goto OPERATION
		}

		fmt.Printf("\n0x%x\n\n", raw)
		goto OPERATION
	}

NET:

	listen, err := net.Listen("tcp", ":8881")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	//sigs := make(chan os.Signal, 1)
	//signal.Notify(sigs, syscall.SIGINT)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		// incoming request
		buffer := make([]byte, 4096) // TODO(dave): make varible, cuz of contracts!
		_, err = conn.Read(buffer)
		if err != nil {
			fmt.Println("Readerr:", err)
			log.Fatal(err)
		}

		// write data to response
		//time := time.Now().Format(time.ANSIC)
		//responseStr := fmt.Sprintf("Your message is: %v. Received time: %v", string(buffer[:]), time)
		//conn.Write([]byte(responseStr))

		//for i := 0; i < 20; i++ {
		//	fmt.Printf("buffer[%d] = %x\n", i, buffer[i])
		//}
		//cmd := strings.TrimSuffix(string(buffer), "\n")
		cmd := strings.TrimRight(string(buffer), "\n\x00")
		fmt.Printf("cmd(%d):|%s|\n", len(cmd), cmd)

		// catch `eth_accounts` (over net)
		if len(cmd) >= 12 && cmd[:12] == "eth_accounts" {
			conn.Write([]byte(WalletAddress))
			conn.Close()
			continue
		}

		// any action other than `eth_accounts` requires permission first
		fmt.Printf("> Allow (y/n): ")
		perm := ""
		for scanner.Scan() {
			perm = scanner.Text()
			break
		}

		if perm != "y" && perm != "Y" {
			conn.Write([]byte{})
			conn.Close()
			continue
		}
		fmt.Println("> PERMISSION GRANTED...")

		// catch `eth_signTypedData_v4` (over net)
		if len(cmd) > 20 && cmd[:20] == "eth_signTypedData_v4" {
			raw, err := signTypedData(cmd[21:], signer)
			if err != nil {
				fmt.Println("err:", err)
				continue
			}

			//rawHex := hex.EncodeToString(raw)
			//fmt.Printf("\n0x%x\n\n", rawHex)

			resp := fmt.Sprintf("0x%x", raw)
			conn.Write([]byte(resp))
			// close conn
			conn.Close()

			continue
		}

		// catch `eth_sign` (over net)
		if len(cmd) > 8 && cmd[:8] == "eth_sign" {
			raw, err := ethSign(cmd[9:], signer)
			if err != nil {
				fmt.Println("err:", err)
				continue
			}

			//rawHex := hex.EncodeToString(raw)
			//fmt.Printf("\n0x%x\n\n", rawHex)

			resp := fmt.Sprintf("0x%x", raw)
			conn.Write([]byte(resp))
			// close conn
			conn.Close()

			continue
		}

		tx, err := cmdToTx(cmd, signer)
		if err != nil {
			fmt.Println("err:", err)
			listen.Close()
			conn.Close()
			goto OPERATION
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			fmt.Println("err:", err)
			listen.Close()
			conn.Close()
			goto OPERATION
		}
		resp := fmt.Sprintf("0x%x", raw)
		conn.Write([]byte(resp))

		// close conn
		conn.Close()
	}

}

func initiateWalletFromCmd(cmd *string) (*signer, error) {
	var privateKey string

	if strings.HasPrefix(*cmd, "p/") {
		privateKey = strings.TrimPrefix(*cmd, "p/")
		privateKey = strings.TrimPrefix(privateKey, "0x")
	} else if strings.HasPrefix(*cmd, "f/") {
		privateKeyFile := strings.TrimPrefix(*cmd, "f/")
		privateKey_, err := ioutil.ReadFile(privateKeyFile)
		if err != nil {
			return nil, err
		}
		privateKey = strings.TrimSuffix(string(privateKey_), "\n")
	} else if strings.HasPrefix(*cmd, "m/") {
		mnemonic := strings.TrimPrefix(*cmd, "m/")
		index := 0
		pieces := strings.Split(mnemonic, "/")
		if len(pieces) == 2 {
			idx, err := strconv.Atoi(pieces[1])
			if err != nil {
				return nil, err
			}

			index = idx
			mnemonic = pieces[0]
		}

		wallet, err := hdwallet.NewFromMnemonic(mnemonic)
		if err != nil {
			return nil, err
		}

		path := hdwallet.MustParseDerivationPath(fmt.Sprintf("m/44'/60'/0'/0/%d", index))
		account, err := wallet.Derive(path, true)
		if err != nil {
			return nil, err
		}

		privateKey, err = wallet.PrivateKeyHex(account)
		if err != nil {
			return nil, err
		}

		_, isVerbose := os.LookupEnv("VERBOSE")
		if isVerbose {
			fmt.Println("Index:", index, " Private key:", privateKey)
		}
	}

	signer, err := signerFromKey(privateKey)
	return signer, err
}

func cmdToTx(cmd string, signer *signer) (*types.Transaction, error) {
	var nonce uint64
	var gas uint64
	var to common.Address
	var data []byte
	var fn string // parameter-less generic fn to call, for more complex fns, supply `data`

	gasTipCap := new(big.Int)
	gasFeeCap := new(big.Int)
	chainID := new(big.Int)
	amount := new(big.Int)

	var token string
	var tokenAddress common.Address

	for _, part := range strings.Split(cmd, " ") {
		var err error
		var ok bool

		keyValue := strings.Split(part, "=")
		if len(keyValue) != 2 {
			return nil, fmt.Errorf("use format key=value")
		}
		key := keyValue[0]
		value := keyValue[1]

		switch key {
		case "nonce":
			if len(value) > 2 && value[0:2] == "0x" {
				nonce, err = strconv.ParseUint(value[2:], 16, 64)
			} else {
				nonce, err = strconv.ParseUint(value, 10, 64)
			}
		case "gas":
			if len(value) > 2 && value[0:2] == "0x" {
				gas, err = strconv.ParseUint(value[2:], 16, 64)
			} else {
				gas, err = strconv.ParseUint(value, 10, 64)
			}
		case "gasTipCap":
			if len(value) > 2 && value[0:2] == "0x" {
				gasTipCap, ok = gasTipCap.SetString(value[2:], 16)
			} else {
				gasTipCap, ok = gasTipCap.SetString(value, 10)
			}
			if !ok {
				err = fmt.Errorf("invalid value for gasTipCap")
			}
		case "gasFeeCap":
			if len(value) > 2 && value[0:2] == "0x" {
				gasFeeCap, ok = gasFeeCap.SetString(value[2:], 16)
			} else {
				gasFeeCap, ok = gasFeeCap.SetString(value, 10)
			}
			if !ok {
				err = fmt.Errorf("invalid value for gasFeeCap")
			}
		case "chainID":
			if len(value) > 2 && value[0:2] == "0x" {
				chainID, ok = chainID.SetString(value[2:], 16)
			} else {
				chainID, ok = chainID.SetString(value, 10)
			}
			if !ok {
				err = fmt.Errorf("invalid value for chainID")
			}
		case "to":
			to = common.HexToAddress(value)
		case "amount":
			pieces := strings.Split(value, "_")
			if len(pieces) == 2 {
				suffix := strings.ToUpper(pieces[1])
				_decimals := 1
				if suffix == "USDC" {
					_decimals = 6
					token = "usdc"
				} else if suffix == "USDT" {
					_decimals = 6
					token = "usdt"
				} else if suffix == "DAI" {
					_decimals = 18
					token = "dai"
				} else if suffix == "ETH" {
					_decimals = 18
				} else {
					_decimals, err = strconv.Atoi(suffix)

					if err != nil {
						return nil, err
					}
				}
				decimals := big.NewInt(int64(_decimals))
				ten := big.NewInt(10)
				decimals.Exp(ten, decimals, nil)

				amountF, _, _ := big.ParseFloat(pieces[0], 10, 236, big.ToNearestEven)
				decimalsF := big.NewFloat(math.Pow(10, float64(_decimals)))
				amountF.Mul(amountF, decimalsF)
				amountStr := fmt.Sprintf("%f", amountF)

				amount, ok = amount.SetString(strings.Split(amountStr, ".")[0], 10)
			} else {
				if len(value) > 2 && value[0:2] == "0x" {
					amount, ok = amount.SetString(value[2:], 16)
				} else {
					amount, ok = amount.SetString(value, 10)
				}
			}
			if !ok {
				err = fmt.Errorf("invalid value for amount")
			}
		case "data":
			if value != "" && value != "0x" {
				data, err = hex.DecodeString(value)
			}
		case "token":
			token = value
		case "fn":
			fn = value
		}

		if err != nil {
			return nil, err
		}
	}

	if token != "" {
		if token == "dai" {
			tokenAddress = common.HexToAddress("0x6b175474e89094c44da98b954eedeac495271d0f")
		} else if token == "rdai" {
			tokenAddress = common.HexToAddress("0xad6d458402f60fd3bd25163575031acdce07538d")
		} else if token == "usdc" {
			tokenAddress = common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
		} else if token == "usdt" {
			tokenAddress = common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7")
		} else {
			tokenAddress = common.HexToAddress(token)
		}
	}

	hasEthTxFields := gas != 0 && gasTipCap != nil && gasFeeCap != nil && chainID != nil && len(to.Bytes()) != 0 && amount != nil
	if !hasEthTxFields {
		return nil, fmt.Errorf("need all fields: nonce, gas, gasTipCap, gasFeeCap, chainID, to, amount")
	}

	var tx *types.Transaction
	var err error

	if fn != "" {
		data = genericFn(fn)
		tx, err = signer.createDynamicFeeTx(nonce, gas, gasTipCap, gasFeeCap, chainID, amount, data, &to)
	} else if token != "" {
		data = transferERC20(tokenAddress, to, amount)
		amount = big.NewInt(0)
		tx, err = signer.createDynamicFeeTx(nonce, gas, gasTipCap, gasFeeCap, chainID, amount, data, &tokenAddress)
	} else {
		tx, err = signer.createDynamicFeeTx(nonce, gas, gasTipCap, gasFeeCap, chainID, amount, data, &to)
	}

	if err != nil {
		return nil, err
	}

	signedTx, err := types.SignTx(tx, types.NewLondonSigner(tx.ChainId()), signer.privateKey)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

func transferERC20(tokenAddress, toAddress common.Address, amount *big.Int) (data []byte) {
	fnSig := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(fnSig)
	methodID := hash.Sum(nil)[:4]

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	return
}

func genericFn(fn string) (data []byte) {
	fnSig := []byte(fn)
	hash := sha3.NewLegacyKeccak256()
	hash.Write(fnSig)
	methodID := hash.Sum(nil)[:4]

	data = append(data, methodID...)

	return
}

type signer struct {
	privateKey *ecdsa.PrivateKey
	address    *common.Address
}

func signerFromKey(privateHex string) (*signer, error) {
	var err error
	var privateKey *ecdsa.PrivateKey

	if privateKey, err = crypto.HexToECDSA(privateHex); err != nil {
		return nil, err
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return &signer{
		privateKey,
		&address,
	}, nil
}

func (s *signer) createDynamicFeeTx(nonce, gas uint64, gasTipCap, gasFeeCap, chainID, amount *big.Int, data []byte, toAddress *common.Address) (*types.Transaction, error) {
	txdata := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        toAddress,
		Value:     amount,
		Gas:       gas,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Data:      data,
	}

	return types.NewTx(txdata), nil
}

func signTypedData(cmd string, signer *signer) ([]byte, error) {
	// go-ethereum@v1.10.19/signer/core/signed_data_test.go -- func TestFormatter
	var typedData apitypes.TypedData

	//fmt.Printf("\ncmd=|%s|\n\n", cmd)

	err := json.Unmarshal([]byte(cmd), &typedData)
	if err != nil {
		fmt.Println("Unmarshal error")
		return nil, fmt.Errorf("unmarshalling failed '%v'", err)
	}

	//fmt.Printf("Domain: %+v\n", typedData.Domain.Map())
	//domain := typedData.Domain.Map()
	//domain.Version = "4"

	// go-ethereum@v1.10.19/signer/core/signed_data_test.go -- func sign
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	//domainSeparator, err := typedData.HashStruct("EIP712Domain", domain2.Map())
	//fmt.Println(domainSeparator)
	if err != nil {
		fmt.Printf("\n*** *** *** ***\n\n")
		return nil, err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, err
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	sighash := crypto.Keccak256(rawData)

	sig, err := crypto.Sign(sighash[:], signer.privateKey)
	if err != nil {
		return nil, err
	}

	// from https://github.com/ethereum/go-ethereum/issues/23335
	if sig[64] < 27 {
		sig[64] += 27
	}

	//sig[64] -= 27 // not matching rust

	//fmt.Println("SIG     :", (sig))
	//fmt.Println("SIG HASH:", hexutil.Encode(sig))

	return sig, nil
}

func ethSign(cmd string, signer *signer) ([]byte, error) {
	// sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)))

	//raw := []byte(fmt.Sprintf("\x19\x01%s%s", string(len(cmd)), string(cmd)))
	raw := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%s%s", string(len(cmd)), string(cmd)))
	hash := crypto.Keccak256(raw)

	sig, err := crypto.Sign(hash, signer.privateKey)

	if err != nil {
		return nil, err
	}

	// from https://github.com/ethereum/go-ethereum/issues/23335
	if sig[64] < 27 {
		sig[64] += 27
	}

	return sig, nil

}
