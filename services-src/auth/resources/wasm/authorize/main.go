package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall/js"
)

func authorize(deny bool, query url.Values) {
	// Get the token from local storage
	localStorage := js.Global().Get("localStorage")
	token := localStorage.Call("getItem", "DONOTSHARE-secretKey").String()

	// Fetch /api/authorize
	requestUri, err := url.JoinPath(js.Global().Get("window").Get("location").Get("origin").String(), "/api/authorize")
	if err != nil {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "Error joining URL: "+err.Error())
		return
	}

	authorizeBody := map[string]interface{}{
		"token":       token,
		"deny":        deny,
		"appId":       query.Get("client_id"),
		"redirectUri": query.Get("redirect_uri"),
	}

	// Append the nonce if it exists
	if query.Has("nonce") {
		authorizeBody["nonce"] = query.Get("nonce")
	}

	// Append the PKCE code challenge if it exists
	if query.Has("code_challenge") {
		authorizeBody["PKCECode"] = query.Get("code_challenge")
		authorizeBody["PKCEMethod"] = query.Get("code_challenge_method")
	}

	// Marshal the body
	body, err := json.Marshal(authorizeBody)
	if err != nil {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "Error marshaling authorize body: "+err.Error())
		return
	}

	// Send the request
	response, err := http.Post(requestUri, "application/json", bytes.NewReader(body))
	if err != nil {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "Error contacting server: "+err.Error())
		return
	}

	// Get all our ducks in a row
	var responseMap map[string]interface{}

	// Read the response
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&responseMap)
	if err != nil {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "Error decoding server response: "+err.Error())
		return
	}

	// Close the response body
	err = response.Body.Close()
	if err != nil {
		fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
	}

	if response.StatusCode == 200 {
		if deny {
			// Redirect to the redirect_uri with an error
			denyUri := query.Get("redirect_uri") + "?error=access_denied"
			if query.Has("state") {
				denyUri += "&state=" + query.Get("state")
			}

			js.Global().Get("window").Get("location").Call("replace", denyUri)
		} else {
			// Redirect to the redirect_uri with the code
			allowUri := query.Get("redirect_uri") + "?code=" + responseMap["exchangeCode"].(string)
			if query.Has("state") {
				allowUri += "&state=" + query.Get("state")
			}

			js.Global().Get("window").Get("location").Call("replace", allowUri)
		}
	} else if response.StatusCode == 401 {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "OAuth screening failed! We could have just saved you from a bad actor!")
	} else if response.StatusCode != 500 {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", responseMap["error"].(string))
	} else {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
	}
}

func main() {
	// Redirect to log-in if not signed in
	localStorage := js.Global().Get("localStorage")
	if localStorage.Call("getItem", "DONOTSHARE-secretKey").IsNull() {
		js.Global().Get("window").Get("location").Call("replace", "/login"+js.Global().Get("window").Get("location").Get("search").String())
	}

	var query url.Values

	// Parse the url parameters using url.ParseQuery
	var err error
	query, err = url.ParseQuery(strings.TrimPrefix(js.Global().Get("window").Get("location").Get("search").String(), "?"))
	if err != nil {
		js.Global().Get("document").Call("getElementById", "statusBox").Set("innerText", "Error parsing URL query: "+err.Error())
		return
	}

	var statusBox = js.Global().Get("document").Call("getElementById", "statusBox")
	var autoAccept = js.Global().Get("document").Call("getElementById", "autoAccept")

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

	if autoAccept.Get("innerText").String() == "0" {
		// Change the status box to the authorization dialog
		statusBox.Set("innerText", "Would you like to allow "+js.Global().Get("document").Call("getElementById", "passThrough").Get("innerText").String()+" to access your user information? You will be redirected to "+query.Get("redirect_uri")+" after you make your decision.")

		// Add an event listener to the Deny button
		js.Global().Get("document").Call("getElementById", "denyButton").Call("addEventListener", "click", js.FuncOf(func(this js.Value, p []js.Value) interface{} {
			// We still partially authorize the user to prevent open redirects
			go authorize(true, query)
			return nil
		}))

		// Add an event listener to the Allow button
		js.Global().Get("document").Call("getElementById", "allowButton").Call("addEventListener", "click", js.FuncOf(func(this js.Value, p []js.Value) interface{} {
			go authorize(false, query)
			return nil
		}))
	} else {
		// Auto-accept the request, as it's from an internal service
		go authorize(false, query)
	}

	// Wait for events
	select {}
}
