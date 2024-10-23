package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"strings"
	"syscall/js"
	"time"
)

func main() {
	// Transition in
	js.Global().Get("document").Get("documentElement").Get("style").Set("display", "initial")
	js.Global().Get("swipe-out").Get("classList").Call("add", "swipe-out-animate")

	var sleepTime = 200 * time.Millisecond
	if js.Global().Get("window").Call("matchMedia", "(prefers-reduced-motion: reduce)").Get("matches").Bool() {
		sleepTime = 500 * time.Millisecond
	}

	time.Sleep(sleepTime)

	// Redirect to log-in if not signed in
	localStorage := js.Global().Get("localStorage")
	if localStorage.Call("getItem", "DONOTSHARE-secretKey").IsNull() {
		js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
		time.Sleep(sleepTime)
		js.Global().Get("window").Get("location").Call("replace", "/login"+js.Global().Get("window").Get("location").Get("search").String())
	}

	statusBox := js.Global().Get("document").Call("getElementById", "statusBox")

	// Parse the query string
	query, err := url.ParseQuery(strings.TrimPrefix(js.Global().Get("window").Get("location").Get("search").String(), "?"))
	if err != nil {
		statusBox.Set("innerText", "Error parsing query: "+err.Error())
		return
	}

	// Get the ECDH public key from the query string
	clientKeyBytes, err := base64.URLEncoding.DecodeString(query.Get("ecdhPublicKey"))
	if err != nil {
		statusBox.Set("innerText", "Error decoding ECDH public key: "+err.Error())
		return
	}

	// Encode the ECDH public key
	key, err := ecdh.X25519().NewPublicKey(clientKeyBytes)
	if err != nil {
		statusBox.Set("innerText", "Error encoding ECDH public key: "+err.Error())
		return
	}

	// Generate a new ECDH key pair
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		statusBox.Set("innerText", "Error generating ECDH key pair: "+err.Error())
		return
	}

	// Generate the shared secret
	sharedSecret, err := privateKey.ECDH(key)
	if err != nil {
		statusBox.Set("innerText", "Error generating shared secret: "+err.Error())
		return
	}

	// AES-GCM encrypt the DONOTSHARE-clientKey
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		statusBox.Set("innerText", "Error creating AES cipher: "+err.Error())
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		statusBox.Set("innerText", "Error creating GCM cipher: "+err.Error())
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		statusBox.Set("innerText", "Error generating nonce: "+err.Error())
		return
	}

	// Un-base64 the client key
	decodedClientKey, err := base64.StdEncoding.DecodeString(localStorage.Call("getItem", "DONOTSHARE-clientKey").String())
	if err != nil {
		statusBox.Set("innerText", "Error decoding client key: "+err.Error())
		return
	}

	encryptedClientKey := gcm.Seal(nil, nonce, decodedClientKey, nil)

	// Redirect back to the referrer with the encrypted client key
	redirectUri := strings.Split(js.Global().Get("document").Get("referrer").String(), "?")[0]
	js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
	time.Sleep(sleepTime)
	js.Global().Get("window").Get("location").Call("replace", redirectUri+"?ecdhPublicKey="+base64.URLEncoding.EncodeToString(privateKey.PublicKey().Bytes())+"&nonce="+base64.URLEncoding.EncodeToString(nonce)+"&cipherText="+base64.URLEncoding.EncodeToString(encryptedClientKey))
}
