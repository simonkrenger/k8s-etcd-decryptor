package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
	secretboxtransformer "k8s.io/apiserver/pkg/storage/value/encrypt/secretbox"
)

const etcdValueFile string = "secretvalue"

func main() {
	fmt.Println("Tool to decrypt AES-CBC and secretbox encrypted objects from etcd")

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

	allowedProviders := []string{"secretbox", "aescbc"}

	if !slices.Contains(allowedProviders, s[2]) {
		fmt.Printf("Unknown encryption provider: %v\n", s[2])
		fmt.Println("This tool currently only supports AES-CBC and secretbox encrypted secrets")
		os.Exit(1)
	}

	// Get binary data as bytes
	secret := []byte(s[5])

	fmt.Print("Enter base64-encoded encryption key from EncryptionConfig: ")
	reader := bufio.NewReader(os.Stdin)
	b64Key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading key: %v\n", err)
		os.Exit(1)
	}

	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		fmt.Printf("Failed to decode key: %v\n", err)
		os.Exit(1)
	}

	var clearText []byte

	switch s[2] {
	case "aescbc":
		clearText, err = transformCbc(secret, key)
	case "secretbox":
		clearText, err = transformSecretbox(secret, key)
	default:
		fmt.Printf("Unsupported encryption type: %v\n", s[2])
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Failed to transform secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(clearText)) // Print the protobuf object
}

func transformCbc(secret []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AESCipher: %w", err)
	}

	cbcTransformer := aestransformer.NewCBCTransformer(cipher)
	clearText, _, err := cbcTransformer.TransformFromStorage(secret, value.DefaultContext{})
	if err != nil {
		return nil, fmt.Errorf("failed to transform secret: %w", err)
	}

	return clearText, nil
}

func transformSecretbox(secret []byte, key []byte) ([]byte, error) {
	var key32 [32]byte
	copy(key32[:], key)

	secretboxTransformer := secretboxtransformer.NewSecretboxTransformer(key32)
	clearText, _, err := secretboxTransformer.TransformFromStorage(secret, value.DefaultContext{})
	if err != nil {
		return nil, fmt.Errorf("failed to transform secret: %w", err)
	}

	return clearText, nil
}
