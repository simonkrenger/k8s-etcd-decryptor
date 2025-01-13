package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func main() {
	fmt.Println("Tool to decrypt AES-CBC-encrypted objects from etcd")

	fmt.Print("Enter base64-encoded etcd value: ")
	reader := bufio.NewReader(os.Stdin)
	b, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v", err)
		os.Exit(1)
	}
	v, err := base64.StdEncoding.DecodeString(b)
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
		os.Exit(1)
	}

	// Get binary data as bytes
	secret := []byte(s[5])

	fmt.Print("Enter base64-encoded encryption key from EncryptionConfig: ")
	reader = bufio.NewReader(os.Stdin)
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
