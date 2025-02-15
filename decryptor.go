package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

const etcdValueFile string = "secretvalue"

func main() {
	fmt.Println("Tool to decrypt AES-CBC-encrypted objects from etcd")

	var secretString string
	if _, err := os.Stat(etcdValueFile); errors.Is(err, os.ErrNotExist) {
		// There is no file with the secret value, read from stdin
		fmt.Print("Enter base64-encoded etcd value: ")
		reader := bufio.NewReader(os.Stdin)
		secretString, err = reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v", err)
			os.Exit(1)
		}
		// Check if we possibly hit the terminal input buffer size limit
		// https://groups.google.com/g/golang-nuts/c/ndh-1wdsWYs/m/Watbhx8JAwAJ
		if len(secretString) > 4095 {
			fmt.Println("The string you entered is longer than 4095 bytes.")
			fmt.Println("When running this in a terminal, you are likely hitting the terminal input buffer size limit.")
			fmt.Printf("Please write your encrypted etcd value in a file called '%s' and run this program again.", etcdValueFile)
			os.Exit(1)
		}
	} else {
		fmt.Println("Found file with secret value, reading from the file...")
		// File exists, read from file
		b, err := os.ReadFile(etcdValueFile)
		if err != nil {
			fmt.Printf("Error reading input from file: %v", err)
			os.Exit(1)
		}
		secretString = string(b)
	}

	v, err := base64.StdEncoding.DecodeString(secretString)
	if err != nil {
		fmt.Printf("Failed to decode etcd value: %v\n", err)
		os.Exit(1)
	}

	// Decoded string looks like this: "k8s:enc:aescbc:v1:<provider-name>:<binary-aes-encrypted-data>"
	// "<binary-aes-encrypted-data>" := "<32-bit IV><rest-of-data>"
	s := strings.SplitN(string(v), ":", 6)

	if len(s) != 6 {
		fmt.Printf("Value does not have the right format: %v", s)
		fmt.Println("Length of array is", len(s))
		os.Exit(1)
	}
	if s[2] != "aescbc" {
		fmt.Printf("Secret is not CBC-encrypted: %v\n", s[2])
		fmt.Println("This tool currently only supports AES-CBC encrypted secrets")
		os.Exit(1)
	}

	// Get binary data as bytes
	secret := []byte(s[5])

	fmt.Print("Enter base64-encoded encryption key from EncryptionConfig: ")
	reader := bufio.NewReader(os.Stdin)
	key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading key: %v\n", err)
		os.Exit(1)
	}

	block, err := newAESCipher(key)
	if err != nil {
		fmt.Printf("Error creating AESCipher: %v", err)
		os.Exit(1)
	}

	cbcTransformer := aestransformer.NewCBCTransformer(block)
	clearText, _, err := cbcTransformer.TransformFromStorage(secret, value.DefaultContext{})
	if err != nil {
		fmt.Printf("Failed to transform secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(clearText)) // Print the protobuf object
}

func newAESCipher(key string) (cipher.Block, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config secret: %v", err)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	return block, nil
}
