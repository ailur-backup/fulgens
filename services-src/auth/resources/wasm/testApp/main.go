package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cespare/xxhash/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall/js"
	"time"
)

func sha256Base64(s string) string {
	hashed := sha256.Sum256([]byte(s))
	encoded := base64.URLEncoding.EncodeToString(hashed[:])
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func randomChars(length int) (string, error) {
	var saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		return "", errors.New("salt length must be greater than 0")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	for i := range salt {
		salt[i] = saltChars[int(randomBytes[i])%len(saltChars)]
	}
	return string(salt), nil
}

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
	authorizeButton := js.Global().Get("document").Call("getElementById", "authorizeButton")

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
		js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
		time.Sleep(sleepTime)
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

	// Check if the URL has a code
	urlParams, err := url.ParseQuery(strings.TrimPrefix(js.Global().Get("window").Get("location").Get("search").String(), "?"))
	if err != nil {
		statusBox.Set("innerText", "Error parsing URL: "+err.Error())
		return
	}

	if urlParams.Has("code") {
		// Set the status box
		statusBox.Set("innerText", "Authenticating...")

		// Create the form data
		var formData = url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", urlParams.Get("code"))
		formData.Set("client_id", "TestApp-DoNotUse")
		formData.Set("redirect_uri", js.Global().Get("window").Get("location").Get("origin").String()+"/testApp")
		formData.Set("code_verifier", localStorage.Call("getItem", "TESTER-verifier").String())

		// Create the request
		requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/oauth/token")
		if err != nil {
			statusBox.Set("innerText", "Error joining URL: "+err.Error())
			return
		}

		response, err := http.Post(requestUri, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
		if err != nil {
			statusBox.Set("innerText", "Error contacting server: "+err.Error())
			return
		}

		// Read the response
		var responseMap map[string]interface{}
		decoder := json.NewDecoder(response.Body)
		err = decoder.Decode(&responseMap)
		if err != nil {
			statusBox.Set("innerText", "Error decoding server response: "+err.Error())
			return
		}

		// Close the response body
		err = response.Body.Close()
		if err != nil {
			fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
		}

		if response.StatusCode == 200 {
			// Fetch userinfo
			requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/oauth/userinfo")
			if err != nil {
				statusBox.Set("innerText", "Error joining URL: "+err.Error())
				return
			}

			// Create the request
			request, err := http.NewRequest("GET", requestUri, nil)
			if err != nil {
				statusBox.Set("innerText", "Error creating request: "+err.Error())
				return
			}

			// Set the authorization header
			request.Header.Set("Authorization", "Bearer "+responseMap["id_token"].(string))

			// Send the request
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				statusBox.Set("innerText", "Error contacting server: "+err.Error())
				return
			}

			// Read the response
			decoder = json.NewDecoder(response.Body)
			err = decoder.Decode(&responseMap)
			if err != nil {
				statusBox.Set("innerText", "Error decoding server response: "+err.Error())
				return
			}

			// Close the response body
			err = response.Body.Close()
			if err != nil {
				fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
			}

			// Set the username
			localStorage.Call("setItem", "TESTER-username", responseMap["username"].(string))

			// Generate the keypair
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				statusBox.Set("innerText", "Error generating private key: "+err.Error())
				return
			}

			// Save the private key
			localStorage.Call("setItem", "TESTER-privateKey", base64.StdEncoding.EncodeToString(privateKey.Bytes()))

			// Redirect to the client key exchange endpoint
			js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
			time.Sleep(sleepTime)
			js.Global().Get("window").Get("location").Call("replace", "/clientKeyShare?ecdhPublicKey="+base64.URLEncoding.EncodeToString(privateKey.PublicKey().Bytes())+"&accessToken="+responseMap["access_token"].(string))
			return
		} else if response.StatusCode != 500 {
			statusBox.Set("innerText", responseMap["error"].(string))
		} else {
			statusBox.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
		}
	} else if urlParams.Has("error") {
		if urlParams.Get("error") == "access_denied" {
			statusBox.Set("innerText", "Access denied")
		} else {
			statusBox.Set("innerText", "Authentication failed (error code: "+urlParams.Get("error")+")")
		}
	} else if urlParams.Has("ecdhPublicKey") {
		publicKeyByte, err := base64.URLEncoding.DecodeString(urlParams.Get("ecdhPublicKey"))
		if err != nil {
			statusBox.Set("innerText", "Error decoding public key: "+err.Error())
			return
		}

		publicKey, err := ecdh.X25519().NewPublicKey(publicKeyByte)
		if err != nil {
			statusBox.Set("innerText", "Error encoding public key: "+err.Error())
			return
		}

		privateKeyBytes, err := base64.StdEncoding.DecodeString(localStorage.Call("getItem", "TESTER-privateKey").String())
		if err != nil {
			statusBox.Set("innerText", "Error decoding private key: "+err.Error())
			return
		}

		privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
		if err != nil {
			statusBox.Set("innerText", "Error encoding private key: "+err.Error())
			return
		}

		nonce, err := base64.URLEncoding.DecodeString(urlParams.Get("nonce"))
		if err != nil {
			statusBox.Set("innerText", "Error decoding nonce: "+err.Error())
			return
		}

		ciphertext, err := base64.URLEncoding.DecodeString(urlParams.Get("cipherText"))
		if err != nil {
			statusBox.Set("innerText", "Error decoding ciphertext: "+err.Error())
			return
		}

		// Generate the shared secret
		sharedSecret, err := privateKey.ECDH(publicKey)
		if err != nil {
			statusBox.Set("innerText", "Error generating shared secret: "+err.Error())
			return
		}

		// Decrypt the ciphertext
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

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			statusBox.Set("innerText", "Error decrypting ciphertext: "+err.Error())
			return
		}

		statusBox.Set("innerText", "Authentication complete! Authenticated as "+localStorage.Call("getItem", "TESTER-username").String()+" with client key "+strconv.FormatUint(xxhash.Sum64(plaintext), 10))

		// Remove all our temporary data
		localStorage.Call("removeItem", "TESTER-verifier")
		localStorage.Call("removeItem", "TESTER-username")
		localStorage.Call("removeItem", "TESTER-privateKey")
	}

	// Add event listener for authorize button
	authorizeButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, p []js.Value) interface{} {
		go func() {
			verifier, err := randomChars(128)
			if err != nil {
				statusBox.Set("innerText", "Error generating verifier: "+err.Error())
				return
			}

			// Generate the challenge
			verifierChallenge := sha256Base64(verifier)

			// Save the verifier
			localStorage.Call("setItem", "TESTER-verifier", verifier)

			// Redirect to the authorization page
			js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
			time.Sleep(sleepTime)
			js.Global().Get("window").Get("location").Call("replace", "/authorize?response_type=code&client_id=TestApp-DoNotUse&redirect_uri="+url.QueryEscape(js.Global().Get("window").Get("location").Get("origin").String()+"/testApp")+"&code_challenge="+verifierChallenge+"&code_challenge_method=S256")
		}()
		return nil
	}))

	// Wait for events
	select {}
}
