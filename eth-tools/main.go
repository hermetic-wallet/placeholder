package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	userPrivateKey := flag.String("private-key", "", "--private-key <hex> (has higher priority)")
	userPrivateKeyFile := flag.String("private-key-file", "", "--private-key-file <address> (looks for /key/<address>.key)")
	userPassword := flag.String("password", "very-secure-pass", "--password <string>")
	flag.Parse()

	var keyFn func() (*ecdsa.PrivateKey, error)
	if *userPrivateKey == "" && *userPrivateKeyFile == "" {
		fmt.Println("✓ generating new private-key")
		keyFn = func() (*ecdsa.PrivateKey, error) { return crypto.GenerateKey() }
	} else if *userPrivateKey != "" {
		fmt.Println("✓ received private-key")
		keyFn = func() (*ecdsa.PrivateKey, error) { return crypto.HexToECDSA(*userPrivateKey) }
	} else if *userPrivateKeyFile != "" {
		fmt.Println("✓ received private-key-file")
		privateKey, err := readKeyFile(*userPrivateKeyFile, *userPassword)
		if err != nil {
			log.Fatalln("✗ cannot read private-key-file:", err)
		}
		keyFn = func() (*ecdsa.PrivateKey, error) { return crypto.HexToECDSA(strings.Trim(string(privateKey), "\n")) }
	}

	privateKey, err := keyFn()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println("   private-key:    ", hexutil.Encode(privateKeyBytes)[2:])

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println("   public-address: ", address)


	if *userPrivateKey == "" && *userPrivateKeyFile == "" {
		if err := writeKeyFile(address, hexutil.Encode(privateKeyBytes)[2:], *userPassword); err != nil {
			log.Fatalln("couldn't write key file", err)
		}

		if _, err := readKeyFile(address, *userPassword); err != nil {
			log.Fatalln("failed reading key", err)
		}
	}
}

// ref: https://bruinsslot.jp/post/golang-crypto/
func writeKeyFile(public string, private string, password string) error {
	if err := os.Mkdir("keys", os.ModePerm); err != nil {
		if !os.IsExist(err) {
			return err
		}
	}

	of, err := os.Create("keys/" + public + ".key")
	if err != nil {
		return err
	}
	defer of.Close()

	key := sha256.Sum256([]byte(password))
	blockCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(private), nil)
	fmt.Printf("   encrypted:       %x\n", ciphertext)

	if err = binary.Write(of, binary.LittleEndian, ciphertext); err != nil {
		return err
	}

	return nil
}

func readKeyFile(public string, password string) (string, error) {
	filecipher, err := ioutil.ReadFile("keys/" + public + ".key")
	if err != nil {
		log.Fatalln("✗ cannot read private-key-file:", err)
	}
	data := []byte(filecipher)

	key := sha256.Sum256([]byte(password))
	blockCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	fmt.Printf("   decryped:        %s\n", plaintext)

	return string(plaintext), nil
}
