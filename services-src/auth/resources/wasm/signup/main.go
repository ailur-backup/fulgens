package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"encoding/json"
	"net/http"
	"net/url"

	"git.ailur.dev/ailur/pow-argon2/library"
	"golang.org/x/crypto/argon2"

	"syscall/js"
)

func showElements(show bool, elements ...js.Value) {
	for _, element := range elements {
		if show {
			element.Get("classList").Call("remove", "hidden")
		} else {
			element.Get("classList").Call("add", "hidden")
		}
	}
}

func hashPassword(password string, salt []byte) string {
	return base64.StdEncoding.EncodeToString(
		argon2.IDKey(
			[]byte(password),
			salt,
			32,
			19264,
			1,
			32,
		),
	)
}

func main() {
	// Redirect to app if already signed in
	localStorage := js.Global().Get("localStorage")
	if !localStorage.Call("getItem", "DONOTSHARE-secretKey").IsNull() {
		js.Global().Get("window").Get("location").Call("replace", "/authorize"+js.Global().Get("window").Get("location").Get("search").String())
	}

	var usernameBox = js.Global().Get("document").Call("getElementById", "usernameBox")
	var passwordBox = js.Global().Get("document").Call("getElementById", "passwordBox")
	var statusBox = js.Global().Get("document").Call("getElementById", "statusBox")
	var signupButton = js.Global().Get("document").Call("getElementById", "signupButton")
	var loginButton = js.Global().Get("document").Call("getElementById", "loginButton")
	var inputContainer = js.Global().Get("document").Call("getElementById", "inputContainer")

	signupButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			var username = usernameBox.Get("value").String()
			var password = passwordBox.Get("value").String()

			if username == "" {
				statusBox.Set("innerText", "A username is required!")
				return
			} else if len(username) > 20 {
				statusBox.Set("innerText", "Username cannot be more than 20 characters!")
				return
			} else if password == "" {
				statusBox.Set("innerText", "A password is required!")
				return
			} else if len(password) < 8 {
				statusBox.Set("innerText", "Password must be at least 8 characters!")
				return
			}

			// Start the signup process
			fmt.Println("Starting signup process for user: " + username)
			showElements(false, inputContainer, signupButton, loginButton)
			// Wait about 10ms to allow the UI to update
			var pow string
			if localStorage.Call("getItem", "DEBUG-customPoW").IsNull() {
				var err error
				statusBox.Set("innerText", "Computing PoW Challenge...\nThe UI may be unresponsive during this time, as we are performing a lot of work! Please wait a few minutes for the process to complete.")
				time.Sleep(time.Millisecond * 10)
				pow, err = library.PoW(3, "fg-auth-signup")
				if err != nil {
					showElements(true, inputContainer, signupButton, loginButton)
					statusBox.Set("innerText", "Error computing PoW challenge: "+err.Error())
					return
				}
			} else {
				pow = localStorage.Call("getItem", "DEBUG-customPoW").String()
			}

			// PoW challenge computed, hash password
			statusBox.Set("innerText", "Hashing password...")

			// Generate a random salt
			salt := make([]byte, 32)
			_, err := rand.Read(salt)
			if err != nil {
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Error generating salt: "+err.Error())
				return
			}

			// Hash the password
			hashedPassword := hashPassword(password, salt)

			// Hashed password computed, contact server
			statusBox.Set("innerText", "Contacting server...")
			signupBody := map[string]interface{}{
				"username":    username,
				"password":    hashedPassword,
				"salt":        base64.StdEncoding.EncodeToString(salt),
				"proofOfWork": pow,
			}

			// Marshal the body
			body, err := json.Marshal(signupBody)
			if err != nil {
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Error marshaling signup body: "+err.Error())
				return
			}

			// Send the request
			requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/signup")
			if err != nil {
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Error joining URL: "+err.Error())
				return
			}

			response, err := http.Post(requestUri, "application/json", bytes.NewReader(body))
			if err != nil {
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Error contacting server: "+err.Error())
				return
			}

			// Get all our ducks in a row
			var responseMap map[string]interface{}

			// Read the response
			decoder := json.NewDecoder(response.Body)
			err = decoder.Decode(&responseMap)
			if err != nil {
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Error decoding server response: "+err.Error())
				return
			}

			// Close the response body
			err = response.Body.Close()
			if err != nil {
				fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
			}

			if response.StatusCode == 200 {
				// Signup successful
				statusBox.Set("innerText", "Setting up encryption keys...")
				localStorage.Call("setItem", "DONOTSHARE-secretKey", responseMap["key"].(string))
				localStorage.Call("setItem", "DONOTSHARE-clientKey", hashPassword(password, []byte("fg-auth-client")))

				// Redirect to app
				statusBox.Set("innerText", "Welcome!")
				time.Sleep(time.Second)
				js.Global().Get("window").Get("location").Call("replace", "/authorize"+js.Global().Get("window").Get("location").Get("search").String())
			} else if response.StatusCode == 409 {
				// Username taken
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Username or password taken!")
			} else if response.StatusCode != 500 {
				// Other error
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", responseMap["error"].(string))
			} else {
				// Other error
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
			}
		}()

		return nil
	}))

	loginButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		js.Global().Get("window").Get("location").Call("replace", "/login"+js.Global().Get("window").Get("location").Get("search").String())
		return nil
	}))

	// Wait for events
	select {}
}
