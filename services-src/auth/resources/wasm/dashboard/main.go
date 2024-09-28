package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall/js"
	"time"
)

func fetchOauthClients(oauthList js.Value, localStorage js.Value, body []byte) {
	// Fetch the OAuth clients
	requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/oauth/list")
	if err != nil {
		var statusText = js.Global().Get("document").Call("createElement", "p")
		statusText.Set("innerText", "Error joining URL: "+err.Error())
		oauthList.Call("appendChild", statusText)
		return
	}

	response, err := http.Post(requestUri, "application/json", bytes.NewReader(body))
	if err != nil {
		var statusText = js.Global().Get("document").Call("createElement", "p")
		statusText.Set("innerText", "Error contacting server: "+err.Error())
		oauthList.Call("appendChild", statusText)
		return
	}

	// Get all our ducks in a row
	var responseMap map[string]interface{}

	// Read the response
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&responseMap)
	if err != nil {
		var statusText = js.Global().Get("document").Call("createElement", "p")
		statusText.Set("innerText", "Error decoding server response: "+err.Error())
		oauthList.Call("appendChild", statusText)
		return
	}

	// Close the response body
	err = response.Body.Close()
	if err != nil {
		fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
	}

	if response.StatusCode == 200 {
		for i := 0; i < oauthList.Get("childNodes").Length(); i++ {
			this := oauthList.Get("childNodes").Index(i)
			if this.Get("tagName").String() != "H2" {
				this.Call("remove")
			}
		}

		clients, ok := responseMap["apps"].([]interface{})
		if !ok {
			var statusText = js.Global().Get("document").Call("createElement", "p")
			statusText.Set("innerText", "Hi there! You don't have any OAuth2 clients yet. Create one above!")
			oauthList.Call("appendChild", statusText)
		} else {
			for _, app := range clients {
				var oauthElement = js.Global().Get("document").Call("createElement", "div")
				var oauthText = js.Global().Get("document").Call("createElement", "p")
				var oauthName = js.Global().Get("document").Call("createElement", "p")
				var oauthUrl = js.Global().Get("document").Call("createElement", "p")
				var oauthRemoveButton = js.Global().Get("document").Call("createElement", "button")
				oauthText.Set("innerText", app.(map[string]interface{})["appId"].(string))
				oauthName.Set("innerText", app.(map[string]interface{})["name"].(string))
				oauthUrl.Set("innerText", app.(map[string]interface{})["redirectUri"].(string))
				oauthRemoveButton.Set("innerText", "Delete permanently")
				oauthRemoveButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
					go func() {
						if js.Global().Call("confirm", "Are you sure you want to delete this client? This action cannot be undone.").Bool() {
							// Create the request body
							requestBody := map[string]interface{}{
								"token": localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
								"appId": app.(map[string]interface{})["appId"].(string),
							}

							// Marshal the body
							bodyBytes, err := json.Marshal(requestBody)
							if err != nil {
								js.Global().Call("alert", "Error marshaling body: "+err.Error())
								return
							}

							// Send the request
							requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/oauth/remove")
							if err != nil {
								js.Global().Call("alert", "Error joining URL: "+err.Error())
								return
							}

							response, err := http.Post(requestUri, "application/json", bytes.NewReader(bodyBytes))
							if err != nil {
								js.Global().Call("alert", "Error contacting server: "+err.Error())
								return
							}

							// Get all our ducks in a row
							var responseMap map[string]interface{}

							// Read the response
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

							if response.StatusCode == 200 {
								oauthElement.Call("remove")
								if oauthList.Get("childNodes").Length() == 1 {
									var statusText = js.Global().Get("document").Call("createElement", "p")
									statusText.Set("innerText", "Hi there! You don't have any OAuth2 clients yet. Create one above!")
									oauthList.Call("appendChild", statusText)
								}
							} else if response.StatusCode != 500 {
								js.Global().Call("alert", responseMap["error"].(string))
							} else {
								js.Global().Call("alert", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
							}
						}
					}()
					return nil
				}))

				oauthElement.Call("append", oauthName)
				oauthElement.Call("append", oauthText)
				oauthElement.Call("append", oauthUrl)

				openId := false
				clientKeyShare := false
				scopes, ok := app.(map[string]interface{})["scopes"].([]interface{})
				if ok {
					for _, scope := range scopes {
						if scope.(string) == "openid" {
							openId = true
						} else if scope.(string) == "clientKeyShare" {
							if app.(map[string]interface{})["keyShareUri"].(string) != "" {
								clientKeyShare = true
								keyShareUri := js.Global().Get("document").Call("createElement", "p")
								keyShareUri.Set("innerText", "Key Share URI: "+app.(map[string]interface{})["keyShareUri"].(string))
								oauthElement.Call("append", keyShareUri)
							}
						}
					}

					oauthScopes := js.Global().Get("document").Call("createElement", "p")
					var scopeText strings.Builder
					if openId {
						scopeText.WriteString("OpenID")
					}

					if clientKeyShare {
						if openId {
							scopeText.WriteString(", ")
						}
						scopeText.WriteString("clientKeyShare")
					}

					oauthScopes.Set("innerText", "Scopes: "+scopeText.String())
					oauthElement.Call("append", oauthScopes)
				}

				oauthElement.Call("append", oauthRemoveButton)
				oauthElement.Get("classList").Call("add", "oauthEntry")

				oauthList.Call("appendChild", oauthElement)
			}
		}
	} else if response.StatusCode != 500 {
		statusText := js.Global().Get("document").Call("createElement", "p")
		statusText.Set("innerText", responseMap["error"].(string))
		oauthList.Call("appendChild", statusText)
	} else {
		statusText := js.Global().Get("document").Call("createElement", "p")
		statusText.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
		oauthList.Call("appendChild", statusText)
	}
}

func main() {
	// Redirect to log-in if not signed in
	localStorage := js.Global().Get("localStorage")
	if localStorage.Call("getItem", "DONOTSHARE-secretKey").IsNull() {
		js.Global().Get("window").Get("location").Call("replace", "/login"+js.Global().Get("window").Get("location").Get("search").String())
	}

	var submitButton = js.Global().Get("document").Call("getElementById", "submitButton")
	var nameBox = js.Global().Get("document").Call("getElementById", "nameBox")
	var usernameBox = js.Global().Get("document").Call("getElementById", "usernameBox")
	var dateBox = js.Global().Get("document").Call("getElementById", "dateBox")
	var clientKeyShareBox = js.Global().Get("document").Call("getElementById", "clientKeyShareBox")
	var redirectUriBox = js.Global().Get("document").Call("getElementById", "redirectUriBox")
	var openIdBox = js.Global().Get("document").Call("getElementById", "openIdBox")
	var statusBox = js.Global().Get("document").Call("getElementById", "statusBox")
	var oauthList = js.Global().Get("document").Call("getElementById", "oauthList")
	var sessionList = js.Global().Get("document").Call("getElementById", "sessionList")
	var deleteAccountButton = js.Global().Get("document").Call("getElementById", "deleteAccountButton")
	var logoutButton = js.Global().Get("document").Call("getElementById", "logoutButton")
	var devAccountSwitcher = js.Global().Get("document").Call("getElementById", "devAccountSwitcher")
	var developers = js.Global().Get("document").Call("getElementById", "developers")
	var account = js.Global().Get("document").Call("getElementById", "account")

	// Fetch the OAuth clients and sessions
	go func() {
		// Check if the token is valid
		requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/loggedIn")
		if err != nil {
			js.Global().Call("alert", "Error joining URL: "+err.Error())
			return
		}

		loggedInBody := map[string]interface{}{
			"token": localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
		}

		// Marshal the body
		body, err := json.Marshal(loggedInBody)
		if err != nil {
			js.Global().Call("alert", "Error marshaling signup body: "+err.Error())
			return
		}

		response, err := http.Post(requestUri, "application/json", bytes.NewReader(body))
		if err != nil {
			js.Global().Call("alert", "Error contacting server: "+err.Error())
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
			js.Global().Get("window").Get("location").Call("replace", "/logout")
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

		// Fetch the OAuth clients
		fetchOauthClients(oauthList, localStorage, body)

		// Fetch the sessions
		requestUri, err = url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/session/list")
		if err != nil {
			var statusText = js.Global().Get("document").Call("createElement", "p")
			statusText.Set("innerText", "Error joining URL: "+err.Error())
			sessionList.Call("appendChild", statusText)
			return
		}

		response, err = http.Post(requestUri, "application/json", bytes.NewReader(body))
		if err != nil {
			var statusText = js.Global().Get("document").Call("createElement", "p")
			statusText.Set("innerText", "Error contacting server: "+err.Error())
			sessionList.Call("appendChild", statusText)
			return
		}

		// Get all our ducks in a row
		var responseMap map[string]interface{}

		// Read the response
		decoder := json.NewDecoder(response.Body)
		err = decoder.Decode(&responseMap)
		if err != nil {
			var statusText = js.Global().Get("document").Call("createElement", "p")
			statusText.Set("innerText", "Error decoding server response: "+err.Error())
			sessionList.Call("appendChild", statusText)
			return
		}

		// Close the response body
		err = response.Body.Close()
		if err != nil {
			fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
		}

		if response.StatusCode == 200 {
			if len(responseMap["sessions"].([]interface{})) == 0 {
				var statusText = js.Global().Get("document").Call("createElement", "p")
				statusText.Set("innerText", "Hi there! You don't have any sessions logged in, somehow. Congrats on breaking the laws of physics!")
				sessionList.Call("appendChild", statusText)
			} else {
				for i := 0; i < sessionList.Get("childNodes").Length(); i++ {
					this := sessionList.Get("childNodes").Index(i)
					if this.Get("tagName").String() != "H2" {
						this.Call("remove")
					}
				}

				for _, session := range responseMap["sessions"].([]interface{}) {
					var sessionElement = js.Global().Get("document").Call("createElement", "div")
					var sessionDevice = js.Global().Get("document").Call("createElement", "p")
					var sessionImage = js.Global().Get("document").Call("createElement", "img")
					var sessionRemoveButton = js.Global().Get("document").Call("createElement", "button")
					if session.(map[string]interface{})["session"].(string) == localStorage.Call("getItem", "DONOTSHARE-secretKey").String() {
						sessionDevice.Set("innerText", "(current) "+session.(map[string]interface{})["device"].(string))
					} else {
						sessionDevice.Set("innerText", session.(map[string]interface{})["device"].(string))
					}

					if strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "nt") || strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "macintosh") {
						sessionImage.Set("src", "/static/svg/device_computer.svg")
					} else if strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "iphone") || strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "android") || strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "ipod") {
						sessionImage.Set("src", "/static/svg/device_smartphone.svg")
					} else if strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "curl") || strings.Contains(strings.ToLower(session.(map[string]interface{})["device"].(string)), "go-http-client") {
						sessionImage.Set("src", "/static/svg/device_terminal.svg")
					} else {
						sessionImage.Set("src", "/static/svg/device_other.svg")
					}

					sessionRemoveButton.Set("innerText", "Force log out")
					sessionRemoveButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
						go func() {
							// Create the request body
							body := map[string]interface{}{
								"token":   localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
								"session": session.(map[string]interface{})["session"].(string),
							}

							// Marshal the body
							bodyBytes, err := json.Marshal(body)
							if err != nil {
								js.Global().Call("alert", "Error marshaling body: "+err.Error())
								return
							}

							// Send the request
							requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/session/remove")
							if err != nil {
								js.Global().Call("alert", "Error joining URL: "+err.Error())
								return
							}

							response, err := http.Post(requestUri, "application/json", bytes.NewReader(bodyBytes))
							if err != nil {
								js.Global().Call("alert", "Error contacting server: "+err.Error())
								return
							}

							// Get all our ducks in a row
							var responseMap map[string]interface{}

							// Read the response
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

							if response.StatusCode == 200 {
								sessionElement.Call("remove")
								if session.(map[string]interface{})["session"].(string) == localStorage.Call("getItem", "DONOTSHARE-secretKey").String() {
									js.Global().Get("window").Get("location").Call("replace", "/logout")
								}
							} else if response.StatusCode != 500 {
								js.Global().Call("alert", responseMap["error"].(string))
							} else {
								js.Global().Call("alert", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
							}
						}()
						return nil
					}))

					sessionElement.Call("append", sessionImage)
					sessionElement.Call("append", sessionDevice)
					sessionElement.Call("append", sessionRemoveButton)
					sessionElement.Get("classList").Call("add", "sessionEntry")

					sessionList.Call("appendChild", sessionElement)
				}
			}
		} else if response.StatusCode != 500 {
			statusText := js.Global().Get("document").Call("createElement", "p")
			statusText.Set("innerText", responseMap["error"].(string))
			sessionList.Call("appendChild", statusText)
		} else {
			statusText := js.Global().Get("document").Call("createElement", "p")
			statusText.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
			sessionList.Call("appendChild", statusText)
		}

		// Fetch user information
		requestUri, err = url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/userinfo")
		if err != nil {
			js.Global().Call("alert", "Error joining URL: "+err.Error())
			return
		}

		// Re-use the body variable for this request
		response, err = http.Post(requestUri, "application/json", bytes.NewReader(body))
		if err != nil {
			js.Global().Call("alert", "Error contacting server: "+err.Error())
			return
		}

		// Read the response
		decoder = json.NewDecoder(response.Body)
		err = decoder.Decode(&responseMap)
		if err != nil {
			js.Global().Call("alert", "Error decoding server response: "+err.Error())
			return
		}

		// Close the response body
		err = response.Body.Close()
		if err != nil {
			js.Global().Call("alert", "Could not close response body: "+err.Error()+", memory leaks may occur")
		}

		if response.StatusCode == 200 {
			usernameBox.Set("innerText", "Username: "+responseMap["username"].(string))
			dateBox.Set("innerText", "Account created: "+time.Unix(int64(responseMap["created"].(float64)), 0).Format("2006-01-02 15:04:05"))
		} else if response.StatusCode != 500 {
			js.Global().Call("alert", responseMap["error"].(string))
		} else {
			js.Global().Call("alert", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
		}
	}()

	submitButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			// Validate the input
			if nameBox.Get("value").String() == "" {
				statusBox.Set("innerText", "An App Name is required!")
				return
			} else if redirectUriBox.Get("value").String() == "" {
				statusBox.Set("innerText", "A Redirect URI is required!")
				return
			}

			// Check for scopes
			var scopes []string
			if openIdBox.Get("checked").Bool() {
				scopes = append(scopes, "openid")
			}
			if clientKeyShareBox.Get("value").String() != "" {
				scopes = append(scopes, "clientKeyShare")
			}

			// Create the request body
			body := map[string]interface{}{
				"name":        nameBox.Get("value").String(),
				"redirectUri": redirectUriBox.Get("value").String(),
				"token":       localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
				"scopes":      scopes,
				"keyShareUri": redirectUriBox.Get("value").String(),
			}

			// Marshal the body
			bodyBytes, err := json.Marshal(body)
			if err != nil {
				statusBox.Set("innerText", "Error marshaling body: "+err.Error())
				return
			}

			// Send the request
			requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/oauth/add")
			if err != nil {
				statusBox.Set("innerText", "Error joining URL: "+err.Error())
				return
			}

			response, err := http.Post(requestUri, "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				statusBox.Set("innerText", "Error contacting server: "+err.Error())
				return
			}

			// Get all our ducks in a row
			var responseMap map[string]interface{}

			// Read the response
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
				statusBox.Set("innerText", "Your secret key is: "+responseMap["key"].(string)+" and your client ID is: "+responseMap["appId"].(string)+". This will only ever be shown once!")

				// Update the OAuth clients
				bodyMap := map[string]interface{}{
					"token": localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
				}

				// Marshal the body
				body, err := json.Marshal(bodyMap)
				if err != nil {
					fmt.Println("Error marshaling body: " + err.Error() + ", this is non-fatal.")
					return
				}

				// Perform the request
				fetchOauthClients(oauthList, localStorage, body)
			} else if response.StatusCode != 500 {
				statusBox.Set("innerText", responseMap["error"].(string))
			} else {
				statusBox.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
			}
		}()
		return nil
	}))

	deleteAccountButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			if js.Global().Call("confirm", "Are you sure you would like to delete your account forever? This cannot be undone.").Bool() {
				// Create the request body
				body := map[string]interface{}{
					"token": localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
				}

				// Marshal the body
				bodyBytes, err := json.Marshal(body)
				if err != nil {
					statusBox.Set("innerText", "Error marshaling body: "+err.Error())
					return
				}

				// Send the request
				requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/deleteAccount")
				if err != nil {
					statusBox.Set("innerText", "Error joining URL: "+err.Error())
					return
				}

				response, err := http.Post(requestUri, "application/json", bytes.NewReader(bodyBytes))
				if err != nil {
					statusBox.Set("innerText", "Error contacting server: "+err.Error())
					return
				}

				// Get all our ducks in a row
				var responseMap map[string]interface{}

				// Read the response
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
					js.Global().Get("window").Get("location").Call("replace", "/logout")
				} else if response.StatusCode != 500 {
					js.Global().Call("alert", responseMap["error"].(string))
				} else {
					js.Global().Call("alert", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
				}
			}
		}()
		return nil
	}))

	devAccountSwitcher.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		developers.Get("classList").Call("toggle", "hidden")
		account.Get("classList").Call("toggle", "hidden")
		if devAccountSwitcher.Get("innerText").String() == "Switch to developer view" {
			devAccountSwitcher.Set("innerText", "Switch to account view")
		} else {
			devAccountSwitcher.Set("innerText", "Switch to developer view")
		}
		return nil
	}))

	logoutButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			// Try to remove the session
			requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/session/remove")
			if err != nil {
				js.Global().Call("alert", "Error joining URL: "+err.Error())
				return
			}

			// Create the request body
			body := map[string]interface{}{
				"token":   localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
				"session": localStorage.Call("getItem", "DONOTSHARE-secretKey").String(),
			}

			// Marshal the body
			bodyBytes, err := json.Marshal(body)
			if err != nil {
				js.Global().Call("alert", "Error marshaling body: "+err.Error())
				return
			}

			// Send the request
			response, err := http.Post(requestUri, "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				js.Global().Call("alert", "Error contacting server: "+err.Error())
				return
			}

			// Get all our ducks in a row
			var responseMap map[string]interface{}

			// Read the response
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

			// We don't care about the response, we're logging out anyway
			js.Global().Get("window").Get("location").Call("replace", "/logout")
		}()
		return nil
	}))

	// Wait for events
	select {}
}
