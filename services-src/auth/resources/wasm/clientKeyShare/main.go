package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall/js"
)

func main() {
	// Redirect to log-in if not signed in
	localStorage := js.Global().Get("localStorage")
	if localStorage.Call("getItem", "DONOTSHARE-secretKey").IsNull() {
		js.Global().Get("window").Get("location").Call("replace", "/login"+js.Global().Get("window").Get("location").Get("search").String())
	}

	statusBox := js.Global().Get("document").Call("getElementById", "statusBox")

	// Check if the token is valid
	requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/loggedIn")
	if err != nil {
		statusBox.Set("innerText", "Error joining URL: "+err.Error())
		return
	}

	loggedInBody := map[string]interface{}{
		"token": localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
	}

	// Marshal the body
	body, err := json.Marshal(loggedInBody)
	if err != nil {
		statusBox.Set("innerText", "Error marshaling signup body: "+err.Error())
		return
	}

	response, err := http.Post(requestUri, "application/json", bytes.NewReader(body))
	if err != nil {
		statusBox.Set("innerText", "Error contacting server: "+err.Error())
		return
	}

	// Check if the response is 200
	if response.StatusCode == 401 {
		// Close the response body
		err = response.Body.Close()
		if err != nil {
			fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
		}

		// Redirect to log-out if not signed in
		js.Global().Get("window").Get("location").Call("replace", "/logout"+js.Global().Get("window").Get("location").Get("search").String())
		return
	} else if response.StatusCode == 500 {
		// Read the response
		var responseMap map[string]interface{}
		decoder := json.NewDecoder(response.Body)
		err = decoder.Decode(&responseMap)
		if err != nil {
			js.Global().Call("alert", "Error decoding server response: "+err.Error())
			return
		}

		// Close the response body
		err = response.Body.Close()
		if err != nil {
			fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
		}

		// Alert the user if the server is down
		js.Global().Call("alert", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
		return
	}

	// Close the response body
	err = response.Body.Close()
	if err != nil {
		fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
	}

	query, err := url.ParseQuery(strings.TrimPrefix(js.Global().Get("window").Get("location").Get("search").String(), "?"))
	if err != nil {
		statusBox.Set("innerText", "Error parsing query: "+err.Error())
		return
	}

	// Check if the access token we were given is valid and that the scope is correct
	requestUri, err = url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/oauth/clientKeyShare")
	if err != nil {
		statusBox.Set("innerText", "Error joining URL: "+err.Error())
		return
	}

	request, err := http.NewRequest("GET", requestUri, nil)
	if err != nil {
		statusBox.Set("innerText", "Error creating request: "+err.Error())
		return
	}

	request.Header.Set("Authorization", "Bearer "+query.Get("accessToken"))

	response, err = http.DefaultClient.Do(request)
	if err != nil {
		statusBox.Set("innerText", "Error contacting server: "+err.Error())
		return
	}

	// Close the response body
	err = response.Body.Close()
	if err != nil {
		fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
	}

	if response.StatusCode == 200 {
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
		js.Global().Get("window").Get("location").Call("replace", redirectUri+"?ecdhPublicKey="+base64.URLEncoding.EncodeToString(privateKey.PublicKey().Bytes())+"&nonce="+base64.URLEncoding.EncodeToString(nonce)+"&cipherText="+base64.URLEncoding.EncodeToString(encryptedClientKey))
	}
}
