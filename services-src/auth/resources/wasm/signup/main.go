package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"encoding/json"
	"net/http"
	"net/url"

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

// This is my code: I can re-license it I all like, despite it being MIT licensed
func pow(resource string) (string, string, error) {
	initialTime := time.Now().Unix()
	var timestamp [8]byte
	binary.LittleEndian.PutUint64(timestamp[:], uint64(initialTime))

	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return "", "", err
	}

	return strconv.FormatInt(initialTime, 10) + ":" + hex.EncodeToString(nonce[:]) + ":" + resource + ":", hex.EncodeToString(argon2.IDKey(nonce[:], bytes.Join([][]byte{timestamp[:], []byte(resource)}, []byte{}), 1, 64*1024, 4, 32)), nil
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
	var signupButton = js.Global().Get("document").Call("getElementById", "signupButton")
	var loginButton = js.Global().Get("document").Call("getElementById", "loginButton")
	var inputContainer = js.Global().Get("document").Call("getElementById", "inputContainer")
	var captchaButton = js.Global().Get("document").Call("getElementById", "captchaButton")
	var captchaStatus = js.Global().Get("document").Call("getElementById", "captchaStatus")

	captchaButton.Set("disabled", false)
	usernameBox.Set("disabled", true)
	passwordBox.Set("disabled", true)
	signupButton.Set("disabled", true)
	if localStorage.Call("getItem", "DEBUG-customCaptcha").IsNull() {
		if localStorage.Call("getItem", "CONFIG-captchaStarted").IsNull() {
			captchaStatus.Set("innerText", "CAPTCHA not started - start CAPTCHA to signup.")
		} else {
			captchaStatus.Set("innerText", "Captcha calculation paused.")
		}
	}

	var captcha string

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
			if captcha == "" {
				statusBox.Set("innerText", "You must have a valid captcha! Press the \"Start\" button to start calculating a captcha.")
			}

			// PoW challenge computed, hash password
			statusBox.Set("innerText", "Hashing password...")

			// Hash the password
			hashedPassword := hashPassword(password, []byte(username))

			// Create a keypair from the password
			publicKey := ed25519.NewKeyFromSeed(hashedPassword).Public().(ed25519.PublicKey)

			// Hashed password computed, contact server
			statusBox.Set("innerText", "Contacting server...")
			signupBody := map[string]interface{}{
				"username":    username,
				"publicKey":   base64.StdEncoding.EncodeToString(publicKey),
				"proofOfWork": captcha,
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
			} else if response.StatusCode == 409 {
				// Username taken
				showElements(true, inputContainer, signupButton, loginButton)
				statusBox.Set("innerText", "Username already taken!")
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
		go func() {
			js.Global().Get("swipe").Get("classList").Call("add", "swipe-animate")
			time.Sleep(sleepTime)
			js.Global().Get("window").Get("location").Call("replace", "/login"+js.Global().Get("window").Get("location").Get("search").String())
		}()
		return nil
	}))

	captchaInProgress := false
	captchaButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if localStorage.Call("getItem", "DEBUG-customCaptcha").IsNull() {
			if !captchaInProgress {
				captchaInProgress = true
				captchaButton.Set("innerText", "Pause")
				localStorage.Call("setItem", "CONFIG-captchaStarted", "true")
				go func() {
					go func() {
						time.Sleep(time.Minute * 5)
						if captchaInProgress {
							captchaStatus.Set("innerText", "Taking a long time? Try the desktop version.")
						}
					}()
					for {
						if !captchaInProgress {
							captchaStatus.Set("innerText", "Captcha calculation paused.")
							captchaButton.Set("innerText", "Start")
							break
						} else {
							captchaStatus.Set("innerText", "Calculating captcha... Stopping or refreshing will not lose progress.")
							powParams, powResult, err := pow("fg-auth-signup")
							if err != nil {
								captchaStatus.Set("innerText", "Error calculating captcha: "+err.Error())
								captchaInProgress = false
								break
							}
							if powResult[:2] == "00" {
								localStorage.Call("removeItem", "CONFIG-captchaStarted")
								captcha = "2:" + powParams
								captchaStatus.Set("innerText", "Captcha calculated!")
								captchaButton.Set("disabled", true)
								captchaButton.Set("innerText", "Start")
								usernameBox.Set("disabled", false)
								passwordBox.Set("disabled", false)
								signupButton.Set("disabled", false)
								captchaInProgress = false
								break
							}
							time.Sleep(time.Millisecond)
						}
					}
				}()
			} else {
				captchaInProgress = false
			}
		} else {
			captcha = localStorage.Call("getItem", "DEBUG-customCaptcha").String()
			captchaStatus.Set("innerText", "Captcha calculated!")
			captchaButton.Set("disabled", true)
			captchaButton.Set("innerText", "Start")
			usernameBox.Set("disabled", false)
			passwordBox.Set("disabled", false)
			signupButton.Set("disabled", false)
		}

		return nil
	}))

	// Wait for events
	select {}
}
