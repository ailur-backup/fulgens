package main

import (
	"bytes"
	"strings"
	"time"

	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"syscall/js"

	"golang.org/x/crypto/argon2"

	"git.ailur.dev/ailur/jsFetch"
)

var currentInputType = 0

func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		32,
		19264,
		1,
		32,
	)
}

func showInput(inputType int, inputContainer js.Value, usernameBox js.Value, signupButton js.Value, passwordBox js.Value, backButton js.Value, inputNameBox js.Value, statusBox js.Value, nextButton js.Value) {
	if inputType == 0 {
		// Show login
		inputContainer.Get("classList").Call("remove", "hidden")
		usernameBox.Get("classList").Call("remove", "hidden")
		signupButton.Get("classList").Call("remove", "hidden")
		passwordBox.Get("classList").Call("add", "hidden")
		backButton.Get("classList").Call("add", "hidden")
		inputNameBox.Set("innerText", "Username:")
		// Get the current service name
		serviceName := js.Global().Get("document").Call("getElementById", "passThrough").Get("innerText").String()

		// Set the service name
		statusBox.Set("innerText", "Login to your "+serviceName+" account!")

		// Set the current input type
		currentInputType = 0
	} else if inputType == 1 {
		inputContainer.Get("classList").Call("remove", "hidden")
		signupButton.Get("classList").Call("add", "hidden")
		usernameBox.Get("classList").Call("add", "hidden")
		passwordBox.Get("classList").Call("remove", "hidden")
		backButton.Get("classList").Call("remove", "hidden")
		inputNameBox.Get("classList").Call("remove", "hidden")
		nextButton.Get("classList").Call("remove", "hidden")
		inputNameBox.Get("classList").Call("remove", "hidden")
		inputNameBox.Set("innerText", "Password:")
		currentInputType = 1
	} else if inputType == 2 {
		signupButton.Get("classList").Call("add", "hidden")
		nextButton.Get("classList").Call("add", "hidden")
		backButton.Get("classList").Call("add", "hidden")
		inputContainer.Get("classList").Call("add", "hidden")
		inputNameBox.Get("classList").Call("add", "hidden")
		passwordBox.Get("classList").Call("add", "hidden")
		usernameBox.Get("classList").Call("add", "hidden")
		currentInputType = 2
	}
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

	// Parse the url parameters using url.ParseQuery
	dashboard := false
	_, err := url.ParseQuery(strings.TrimPrefix(js.Global().Get("window").Get("location").Get("search").String(), "?"))
	if err != nil {
		dashboard = true
	}

	// Redirect to app if already signed in
	localStorage := js.Global().Get("localStorage")
	if !localStorage.Call("getItem", "DONOTSHARE-secretKey").IsNull() {
		js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
		time.Sleep(sleepTime)
		if !dashboard {
			js.Global().Get("window").Get("location").Call("replace", "/authorize"+js.Global().Get("window").Get("location").Get("search").String())
		} else {
			js.Global().Get("window").Get("location").Call("replace", "/dashboard")
		}
	}

	var usernameBox = js.Global().Get("document").Call("getElementById", "usernameBox")
	var passwordBox = js.Global().Get("document").Call("getElementById", "passwordBox")
	var statusBox = js.Global().Get("document").Call("getElementById", "statusBox")
	var nextButton = js.Global().Get("document").Call("getElementById", "nextButton")
	var backButton = js.Global().Get("document").Call("getElementById", "backButton")
	var signupButton = js.Global().Get("document").Call("getElementById", "signupButton")
	var inputNameBox = js.Global().Get("document").Call("getElementById", "inputNameBox")
	var inputContainer = js.Global().Get("document").Call("getElementById", "inputContainer")

	// Show the login screen
	showInput(0, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)

	nextButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			if currentInputType == 0 {
				if usernameBox.Get("value").IsNull() {
					statusBox.Set("innerText", "A username is required!")
					return
				} else {
					statusBox.Set("innerText", "Welcome back, "+usernameBox.Get("value").String()+"!")
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
				}
			} else if currentInputType == 1 {
				password := passwordBox.Get("value").String()
				username := usernameBox.Get("value").String()

				if passwordBox.Get("value").IsNull() {
					statusBox.Set("innerText", "A password is required!")
					return
				}

				showInput(2, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)

				// Hash the password
				statusBox.Set("innerText", "Hashing password...")
				println("Hashing password...")

				// Fetch the challenge from the server
				body, err := json.Marshal(map[string]interface{}{
					"username": username,
				})

				if err != nil {
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
					statusBox.Set("innerText", "Error marshaling salt body: "+err.Error())
					return
				}

				requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/loginChallenge")
				if err != nil {
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
					statusBox.Set("innerText", "Error joining URL: "+err.Error())
					return
				}

				response, err := jsFetch.Post(requestUri, "application/json", bytes.NewReader(body))
				if err != nil {
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
					statusBox.Set("innerText", "Error contacting server: "+err.Error())
					return
				}

				// Get all our ducks in a row
				var responseMap map[string]interface{}

				// Read the response
				decoder := json.NewDecoder(response.Body)
				err = decoder.Decode(&responseMap)
				if err != nil {
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
					statusBox.Set("innerText", "Error decoding server response: "+err.Error())
					return
				}

				// Close the response body
				err = response.Body.Close()
				if err != nil {
					println("Could not close response body: " + err.Error() + ", memory leaks may occur")
				}

				if response.StatusCode == 200 {
					// Hash the password
					hashedPassword := hashPassword(password, []byte(username))

					// Sign the challenge
					signature := ed25519.Sign(ed25519.NewKeyFromSeed(hashedPassword), []byte(responseMap["challenge"].(string)))

					// Hashed password computed, contact server
					statusBox.Set("innerText", "Contacting server...")
					signupBody := map[string]interface{}{
						"username":  username,
						"signature": base64.StdEncoding.EncodeToString(signature),
						"verifier":  responseMap["verifier"].(string),
					}

					// Marshal the body
					body, err = json.Marshal(signupBody)
					if err != nil {
						showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
						statusBox.Set("innerText", "Error marshaling signup body: "+err.Error())
						return
					}

					// Send the request
					requestUri, err = url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/login")
					if err != nil {
						showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
						statusBox.Set("innerText", "Error joining URL: "+err.Error())
						return
					}

					// Send the request
					println("Sending request to", requestUri)
					response, err = jsFetch.Post(requestUri, "application/json", bytes.NewReader(body))
					if err != nil {
						showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
						statusBox.Set("innerText", "Error contacting server: "+err.Error())
						return
					}

					// Read the response
					println("Reading response...")
					decoder = json.NewDecoder(response.Body)
					err = decoder.Decode(&responseMap)
					if err != nil {
						showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
						statusBox.Set("innerText", "Error decoding server response: "+err.Error())
						return
					}

					// Close the response body
					err = response.Body.Close()
					if err != nil {
						println("Could not close response body: " + err.Error() + ", memory leaks may occur")
					}

					if response.StatusCode == 200 {
						// Logged in
						println("Logged in!")
						statusBox.Set("innerText", "Setting up encryption keys...")
						localStorage.Call("setItem", "DONOTSHARE-secretKey", responseMap["key"].(string))
						localStorage.Call("setItem", "DONOTSHARE-clientKey", base64.StdEncoding.EncodeToString(hashPassword(password, []byte("fg-auth-client"))))

						// Redirect to app
						statusBox.Set("innerText", "Welcome!")
						time.Sleep(time.Second)
						js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
						time.Sleep(sleepTime)
						if !dashboard {
							js.Global().Get("window").Get("location").Call("replace", "/authorize"+js.Global().Get("window").Get("location").Get("search").String())
						} else {
							js.Global().Get("window").Get("location").Call("replace", "/dashboard")
						}
					} else if response.StatusCode == 401 {
						// Login failed
						showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
						statusBox.Set("innerText", "Username or password incorrect!")
					} else {
						// Unknown error
						showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
						statusBox.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
					}
				} else if response.StatusCode != 500 {
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
					statusBox.Set("innerText", responseMap["error"].(string))
				} else {
					showInput(1, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
					statusBox.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
				}
			}
		}()

		return nil
	}))

	backButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			showInput(0, inputContainer, usernameBox, signupButton, passwordBox, backButton, inputNameBox, statusBox, nextButton)
			return
		}()

		return nil
	}))

	signupButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
			time.Sleep(sleepTime)
			js.Global().Get("window").Get("location").Call("replace", "/signup"+js.Global().Get("window").Get("location").Get("search").String())
		}()
		return nil
	}))

	// Wait for events
	select {}
}
