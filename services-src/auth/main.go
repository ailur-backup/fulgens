package main

import (
	// Fulgens libraries
	library "git.ailur.dev/ailur/fg-library/v2"
	authLibrary "git.ailur.dev/ailur/fg-nucleus-library"
	"git.ailur.dev/ailur/pow"

	// Standard libraries
	"bytes"
	"errors"
	"strconv"
	"strings"
	"time"

	// Secondary libraries
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"

	// External libraries
	"github.com/cespare/xxhash/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

var ServiceInformation = library.Service{
	Name: "Authentication",
	Permissions: library.Permissions{
		Authenticate:              false, // This service *is* the authentication service
		Database:                  true,  // This service does require database access
		BlobStorage:               false, // This service does not require blob storage
		InterServiceCommunication: true,  // This service does require inter-service communication
		Resources:                 true,  // This service does require its HTTP templates and static files to be served
	},
	ServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000004"),
}

func logFunc(message string, messageType uint64, information library.ServiceInitializationInformation) {
	// Log the message to the logger service
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000002"), // Logger service
		MessageType:  messageType,
		SentAt:       time.Now(),
		Message:      message,
	}
}

func ensureTrailingSlash(url string) string {
	if !strings.HasSuffix(url, "/") {
		return url + "/"
	}
	return url
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

func sha256Base64(s string) string {
	hashed := sha256.Sum256([]byte(s))
	encoded := base64.URLEncoding.EncodeToString(hashed[:])
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func renderTemplate(statusCode int, w http.ResponseWriter, data map[string]interface{}, templatePath string, information library.ServiceInitializationInformation) {
	var err error
	var requestedTemplate *template.Template
	// Output ls of the resource directory
	requestedTemplate, err = template.ParseFS(information.ResourceDir, "templates/"+templatePath)
	if err != nil {
		logFunc(err.Error(), 2, information)
		http.Error(w, err.Error(), 500)
	} else {
		if strings.HasSuffix(templatePath, ".html") {
			w.Header().Set("Content-Type", "text/html")
		} else if strings.HasSuffix(templatePath, ".json") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/plain")
		}
		w.WriteHeader(statusCode)
		err = requestedTemplate.Execute(w, data)
		if err != nil {
			logFunc(err.Error(), 2, information)
			http.Error(w, err.Error(), 500)
		}
	}
}

func renderString(statusCode int, w http.ResponseWriter, data string, information library.ServiceInitializationInformation) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(data))
	if err != nil {
		logFunc(err.Error(), 2, information)
	}
}

func renderJSON(statusCode int, w http.ResponseWriter, data map[string]interface{}, information library.ServiceInitializationInformation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		logFunc(err.Error(), 2, information)
	}
}

func verifyJwt(token string, publicKey ed25519.PublicKey, mem *sql.DB) ([]byte, jwt.MapClaims, bool) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, nil, false
	}

	if !parsedToken.Valid {
		return nil, nil, false
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, false
	}

	// Check if the token expired
	date, err := claims.GetExpirationTime()
	if err != nil {
		return nil, claims, false
	}

	if date.Before(time.Now()) {
		return nil, claims, false
	}

	// Check if the session exists
	var userId []byte
	err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", claims["session"]).Scan(&userId)
	if err != nil {
		return nil, claims, false
	}

	return userId, claims, true
}

func Main(information library.ServiceInitializationInformation) {
	var conn library.Database
	var mem *sql.DB
	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey
	// Load the configuration
	privacyPolicy := information.Configuration["privacyPolicy"].(string)
	hostName := information.Configuration["url"].(string)
	testAppIsAvailable := information.Configuration["testAppEnabled"].(bool)
	testAppIsInternalApp, ok := information.Configuration["testAppIsInternalApp"].(bool)
	if !ok {
		testAppIsAvailable = false
	}
	identifier := information.Configuration["identifier"].(string)
	adminKey := information.Configuration["adminKey"].(string)

	// Initiate a connection to the database
	// Call service ID 1 to get the database connection information
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), // Service initialization service
		MessageType:  1,                                                      // Request connection information
		SentAt:       time.Now(),
		Message:      nil,
	}

	// Wait for the response
	response := <-information.Inbox
	if response.MessageType == 2 {
		// This is the connection information
		// Set up the database connection
		conn = response.Message.(library.Database)
		if conn.DBType == library.Sqlite {
			// Create the global table
			// Uniqueness check is a hack to ensure we only have one global row
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS global (key BLOB NOT NULL, uniquenessCheck BOOLEAN NOT NULL UNIQUE CHECK (uniquenessCheck = true) DEFAULT true)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the users table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BLOB PRIMARY KEY NOT NULL UNIQUE, created INTEGER NOT NULL, username TEXT NOT NULL UNIQUE, publicKey BLOB NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the oauth table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS oauth (appId TEXT NOT NULL UNIQUE, secret TEXT, creator BLOB NOT NULL, redirectUri TEXT NOT NULL, name TEXT NOT NULL, keyShareUri TEXT NOT NULL DEFAULT '', scopes TEXT NOT NULL DEFAULT '[\"openid\"]')")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		} else {
			// Create the global table
			// Uniqueness check is a hack to ensure we only have one global row
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS global (key BYTEA NOT NULL, uniquenessCheck BOOLEAN NOT NULL UNIQUE CHECK (uniquenessCheck = true) DEFAULT true)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the users table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BYTEA PRIMARY KEY NOT NULL UNIQUE, created INTEGER NOT NULL, username TEXT NOT NULL UNIQUE, publicKey BYTEA NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the oauth table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS oauth (appId TEXT NOT NULL UNIQUE, secret TEXT, creator BYTEA NOT NULL, redirectUri TEXT NOT NULL, name TEXT NOT NULL, keyShareUri TEXT NOT NULL DEFAULT '', scopes TEXT NOT NULL DEFAULT '[\"openid\"]')")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		}
		// Set up the in-memory cache
		mem, err := sql.Open("sqlite3", "file:"+ServiceInformation.ServiceID.String()+"?mode=memory&cache=shared")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		// Drop the tables if they exist
		_, err = mem.Exec("DROP TABLE IF EXISTS sessions")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		_, err = mem.Exec("DROP TABLE IF EXISTS logins")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		_, err = mem.Exec("DROP TABLE IF EXISTS spent")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		_, err = mem.Exec("DROP TABLE IF EXISTS challengeResponse")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		// Create the sessions table
		_, err = mem.Exec("CREATE TABLE sessions (id BLOB NOT NULL, session TEXT NOT NULL, device TEXT NOT NULL DEFAULT '?')")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		// Create the logins table
		_, err = mem.Exec("CREATE TABLE logins (appId TEXT NOT NULL, exchangeCode TEXT NOT NULL UNIQUE, pkce TEXT, pkceMethod TEXT, openid BOOLEAN NOT NULL, userId BLOB NOT NULL UNIQUE, nonce TEXT NOT NULL DEFAULT '', token TEXT NOT NULL)")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		// Create the spent PoW table
		_, err = mem.Exec("CREATE TABLE spent (hash BLOB NOT NULL UNIQUE, expires INTEGER NOT NULL)")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
		// Create the challenge-response table
		_, err = mem.Exec("CREATE TABLE challengeResponse (challenge TEXT NOT NULL UNIQUE, userId BLOB NOT NULL, expires INTEGER NOT NULL)")
		if err != nil {
			logFunc(err.Error(), 3, information)
		}
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Set up the signing keys
	// Check if the global table has the keys
	err := conn.DB.QueryRow("SELECT key FROM global LIMIT 1").Scan(&privateKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Generate a new key
			var err error
			publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Insert the key into the global table
			_, err = conn.DB.Exec("INSERT INTO global (key) VALUES ($1)", privateKey)
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		} else {
			logFunc(err.Error(), 3, information)
		}
	} else {
		publicKey = privateKey.Public().(ed25519.PublicKey)
	}

	// Set up the test app
	_, err = conn.DB.Exec("DELETE FROM oauth WHERE appId = 'TestApp-DoNotUse'")
	if err != nil {
		testAppIsAvailable = false
		logFunc(err.Error(), 2, information)
	}

	if testAppIsInternalApp {
		_, err = conn.DB.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes, keyShareUri) VALUES ('TestApp-DoNotUse', 'none', $1, 'Test App', $2, '[\"openid\", \"clientKeyShare\"]', $3)", ServiceInformation.ServiceID, ensureTrailingSlash(hostName)+"testApp", ensureTrailingSlash(hostName)+"keyExchangeTester")
	} else {
		testAppCreator := uuid.New()

		_, err = conn.DB.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes, keyShareUri) VALUES ('TestApp-DoNotUse', 'none', $1, 'Test App', $2, '[\"openid\", \"clientKeyShare\"]', $3)", testAppCreator, ensureTrailingSlash(hostName)+"testApp", ensureTrailingSlash(hostName)+"keyExchangeTester")
	}
	if err != nil {
		testAppIsAvailable = false
		logFunc(err.Error(), 2, information)
	}

	// Set up the router
	router := information.Router

	// Add the CORS middleware
	disableCors := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type")
			w.Header().Set("Access-Control-Allow-Methods", "*")
			next.ServeHTTP(w, r)
		})
	}

	router.Use(disableCors)

	disableCorsHandleFunc := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
	}

	// Set up the static routes
	staticDir, err := fs.Sub(information.ResourceDir, "static")
	if err != nil {
		logFunc(err.Error(), 3, information)
	} else {
		router.Handle("/static/*", http.StripPrefix("/static/", http.FileServerFS(staticDir)))
	}

	router.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{
			"identifier": identifier,
		}, "login.html", information)
	})

	router.Get("/signup", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{
			"identifier": identifier,
		}, "signup.html", information)
	})

	router.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{
			"identifier": identifier,
		}, "logout.html", information)
	})

	router.Get("/privacy", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, privacyPolicy, 301)
	})

	router.Get("/testApp", func(w http.ResponseWriter, r *http.Request) {
		if testAppIsAvailable {
			renderTemplate(200, w, map[string]interface{}{
				"identifier": identifier,
			}, "testApp.html", information)
		} else {
			renderTemplate(200, w, map[string]interface{}{
				"identifier": identifier,
			}, "testAppNotAvailable.html", information)
		}
	})

	router.Get("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("client_id") != "" {
			if conn.DBType == library.Sqlite {
				var name string
				var creator []byte
				err := conn.DB.QueryRow("SELECT name, creator FROM oauth WHERE appId = $1", r.URL.Query().Get("client_id")).Scan(&name, &creator)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						renderString(404, w, "App not found", information)
					} else {
						logFunc(err.Error(), 2, information)
						renderString(500, w, "Sorry, something went wrong on our end. Error code: 02. Please report to the administrator.", information)
					}
					return
				}

				if !bytes.Equal(creator, ServiceInformation.ServiceID[:]) {
					renderTemplate(200, w, map[string]interface{}{
						"identifier": identifier,
						"name":       name,
					}, "authorize.html", information)
				} else {
					renderTemplate(200, w, map[string]interface{}{
						"identifier": identifier,
						"name":       name,
					}, "autoAccept.html", information)
				}
			} else {
				var name string
				var creator uuid.UUID
				err := conn.DB.QueryRow("SELECT name, creator FROM oauth WHERE appId = $1", r.URL.Query().Get("client_id")).Scan(&name, &creator)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						renderString(404, w, "App not found", information)
					} else {
						logFunc(err.Error(), 2, information)
						renderString(500, w, "Sorry, something went wrong on our end. Error code: 03. Please report to the administrator.", information)
					}
					return
				}

				if creator != ServiceInformation.ServiceID {
					renderTemplate(200, w, map[string]interface{}{
						"identifier": identifier,
						"name":       name,
					}, "authorize.html", information)
				} else {
					renderTemplate(200, w, map[string]interface{}{
						"identifier": identifier,
						"name":       name,
					}, "autoAccept.html", information)
				}
			}
		} else {
			http.Redirect(w, r, "/dashboard", 301)
		}
	})

	router.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{
			"identifier": identifier,
		}, "dashboard.html", information)
	})

	router.Get("/clientKeyShare", func(w http.ResponseWriter, r *http.Request) {
		// Parse the JWT from the query string
		if r.URL.Query().Get("accessToken") == "" {
			renderString(400, w, "No token provided", information)
			return
		}

		// Verify the JWT
		_, claims, ok := verifyJwt(r.URL.Query().Get("accessToken"), publicKey, mem)
		if !ok {
			renderString(401, w, "Invalid token", information)
			return
		}

		// Check if they have the clientKeyShare scope
		var scopes string
		err = conn.DB.QueryRow("SELECT scopes FROM oauth WHERE appId = $1", claims["aud"]).Scan(&scopes)
		if err != nil {
			renderString(500, w, "Sorry, something went wrong on our end. Error code: 20. Please report to the administrator.", information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Unmarshal the scopes
		var scopesArray []string
		err = json.Unmarshal([]byte(scopes), &scopesArray)
		if err != nil {
			renderString(500, w, "Sorry, something went wrong on our end. Error code: 21. Please report to the administrator.", information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Check if the clientKeyShare scope is present
		var hasClientKeyShare bool
		for _, scope := range scopesArray {
			if scope == "clientKeyShare" {
				hasClientKeyShare = true
				break
			}
		}
		if !hasClientKeyShare {
			renderString(403, w, "Missing scope", information)
			return
		}

		// Check it's not an openid token
		if claims["isOpenID"] == true {
			renderString(400, w, "Invalid token", information)
		} else {
			renderTemplate(200, w, map[string]interface{}{
				"identifier": identifier,
			}, "clientKeyShare.html", information)
		}
	})

	router.Get("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{
			"hostName": hostName,
		}, "openid.json", information)
	})

	router.Post("/api/changePassword", func(w http.ResponseWriter, r *http.Request) {
		type changePassword struct {
			Session      string `json:"session"`
			NewPublicKey string `json:"newPublicKey"`
		}
		var data changePassword
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Session).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Update the public key
		_, err = conn.DB.Exec("UPDATE users SET publicKey = $1 WHERE id = $2", data.NewPublicKey, userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "04"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Invalidate all sessions
		_, err = mem.Exec("DELETE FROM sessions WHERE id = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "06"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return success
		renderJSON(200, w, map[string]interface{}{"success": true}, information)
	})

	router.Post("/api/signup", func(w http.ResponseWriter, r *http.Request) {
		type signup struct {
			Username    string `json:"username"`
			PublicKey   string `json:"publicKey"`
			ProofOfWork string `json:"proofOfWork"`
		}
		var data signup
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the difficulty, timestamp and resource are correct
		powSlice := strings.Split(data.ProofOfWork, ":")
		if powSlice[0] != "2" || powSlice[3] != "fg-auth-signup" {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid PoW"}, information)
			return
		}

		timestamp, err := strconv.ParseInt(powSlice[1], 10, 64)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid PoW"}, information)
			return
		}

		if time.Unix(timestamp, 0).Add(time.Minute*10).Compare(time.Now()) < 0 {
			renderJSON(400, w, map[string]interface{}{"error": "PoW expired"}, information)
			return
		}

		// Verify the PoW
		if !ailur_pow.VerifyPoW(data.ProofOfWork) {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid PoW"}, information)
			return
		}

		// Check if the PoW is spent
		hash := make([]byte, 8)
		binary.LittleEndian.PutUint64(hash, xxhash.Sum64String(data.ProofOfWork))
		_, err = mem.Exec("INSERT INTO spent (hash, expires) VALUES (?, ?)", hash, time.Now().Unix()+60)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				renderJSON(400, w, map[string]interface{}{"error": "Proof of work already spent"}, information)
				return
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "07"}, information)
				logFunc(err.Error(), 2, information)
				return
			}
		}

		// Decode the public key
		publicKey, err := base64.StdEncoding.DecodeString(data.PublicKey)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Try to insert the user
		userID := uuid.New()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "08"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		_, err = conn.DB.Exec("INSERT INTO users (id, created, username, publicKey) VALUES ($1, $2, $3, $4)", userID, time.Now().Unix(), data.Username, publicKey)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				renderJSON(409, w, map[string]interface{}{"error": "Username already taken"}, information)
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "09"}, information)
				logFunc(err.Error(), 2, information)
			}
			return
		}

		// Create a new session
		// We want the session token to be somewhat legible, so we use randomChars
		// As a trade-off for this, we use a longer session token
		session, err := randomChars(512)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "10"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Insert the session
		_, err = mem.Exec("INSERT INTO sessions (id, session, device) VALUES (?, ?, ?)", userID, session, r.Header.Get("User-Agent"))

		// Return success, as well as the session token
		renderJSON(200, w, map[string]interface{}{"key": session}, information)
	})

	router.Post("/api/loginChallenge", func(w http.ResponseWriter, r *http.Request) {
		type login struct {
			Username string `json:"username"`
		}

		var data login
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Get the id for the user
		var userId []byte
		err = conn.DB.QueryRow("SELECT id FROM users WHERE username = $1", data.Username).Scan(&userId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(401, w, map[string]interface{}{"error": "Invalid username"}, information)
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "12"}, information)
				logFunc(err.Error(), 2, information)
			}
			return
		}

		// Generate a new challenge
		challenge, err := randomChars(512)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "53"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Insert the challenge with one minute expiration
		_, err = mem.Exec("INSERT INTO challengeResponse (challenge, userId, expires) VALUES (?, ?, ?)", challenge, userId, time.Now().Unix()+60)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "53"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return the challenge
		renderJSON(200, w, map[string]interface{}{"challenge": challenge}, information)
	})

	router.Post("/api/login", func(w http.ResponseWriter, r *http.Request) {
		type login struct {
			Username  string `json:"username"`
			Signature string `json:"signature"`
		}

		var data login
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Try to select the user
		var userId []byte
		var publicKey []byte
		err = conn.DB.QueryRow("SELECT id, publicKey FROM users WHERE username = $1", data.Username).Scan(&userId, &publicKey)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(401, w, map[string]interface{}{"error": "Invalid username"}, information)
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "12"}, information)
				logFunc(err.Error(), 2, information)
			}
			return
		}

		// Decode the challenge
		signature, err := base64.StdEncoding.DecodeString(data.Signature)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Verify the challenge
		// Select the current challenge from the database
		var challenge string
		err = mem.QueryRow("SELECT challenge FROM challengeResponse WHERE userId = ?", userId).Scan(&challenge)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(401, w, map[string]interface{}{"error": "Invalid challenge"}, information)
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "52"}, information)
				logFunc(err.Error(), 2, information)
			}
			return
		}

		// Check if the challenge is correct by verifying the signature
		if !ed25519.Verify(publicKey, []byte(challenge), signature) {
			renderJSON(401, w, map[string]interface{}{"error": "Invalid signature"}, information)
			return
		}

		// Delete the challenge
		_, err = mem.Exec("DELETE FROM challengeResponse WHERE userId = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "53"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Create a new session
		// We want the session token to be somewhat legible, so we use randomChars
		// As a trade-off for this, we use a longer session token
		session, err := randomChars(512)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "13"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Insert the session
		_, err = mem.Exec("INSERT INTO sessions (id, session, device) VALUES (?, ?, ?)", userId, session, r.Header.Get("User-Agent"))
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "14"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return success, as well as the session token
		renderJSON(200, w, map[string]interface{}{"key": session}, information)
	})

	router.Post("/api/userinfo", func(w http.ResponseWriter, r *http.Request) {
		type userinfo struct {
			Token string `json:"token"`
		}

		var data userinfo
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Get the username and the creation date
		var username string
		var created int64
		err = conn.DB.QueryRow("SELECT username, created FROM users WHERE id = $1", userId).Scan(&username, &created)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "15"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return the username and the creation date
		renderJSON(200, w, map[string]interface{}{"username": username, "created": created}, information)
	})

	// This exists to make sure you get logged out immediately with an invalidated session
	router.Post("/api/loggedIn", func(w http.ResponseWriter, r *http.Request) {
		type loggedIn struct {
			Token string `json:"token"`
		}

		var data loggedIn
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var session string
		err = mem.QueryRow("SELECT session FROM sessions WHERE session = ?", data.Token).Scan(&session)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(401, w, map[string]interface{}{"error": "Invalid session"}, information)
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "16"}, information)
				logFunc(err.Error(), 2, information)
			}
		} else {
			if session == data.Token {
				// Return success
				renderJSON(200, w, map[string]interface{}{"success": true}, information)
			} else {
				// I don't know why this happens, but it does
				renderJSON(401, w, map[string]interface{}{"error": "Invalid session"}, information)
			}
		}
	})

	// Via the magic of JWTs, this support **both** access tokens and OpenID tokens. I love signing things.
	// Just a shame in 15 years when Y2Q happens. That'll be a pain.
	router.Get("/api/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		// Parse the JWT
		if r.Header.Get("Authorization") == "" {
			renderJSON(401, w, map[string]interface{}{"error": "No token provided"}, information)
			return
		}

		// Verify the JWT
		userId, claims, ok := verifyJwt(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), publicKey, mem)
		if !ok {
			renderJSON(401, w, map[string]interface{}{"error": "Invalid token"}, information)
			return
		}

		// Check if they have the openid scope
		var scopes string
		err = conn.DB.QueryRow("SELECT scopes FROM oauth WHERE appId = $1", claims["aud"]).Scan(&scopes)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "17"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Unmarshal the scopes
		var scopesArray []string
		err = json.Unmarshal([]byte(scopes), &scopesArray)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "18"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Check if the openid scope is present
		var hasOpenid bool
		for _, scope := range scopesArray {
			if scope == "openid" {
				hasOpenid = true
				break
			}
		}
		if !hasOpenid {
			renderJSON(403, w, map[string]interface{}{"error": "Missing scope"}, information)
			return
		}

		// Get the username
		var username string
		err := conn.DB.QueryRow("SELECT username FROM users WHERE id = $1", userId).Scan(&username)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "19"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return the username and id as sub
		renderJSON(200, w, map[string]interface{}{"username": username, "sub": uuid.Must(uuid.FromBytes(userId)).String()}, information)
	})

	router.Options("/api/oauth/userinfo", disableCorsHandleFunc)

	router.Post("/api/authorize", func(w http.ResponseWriter, r *http.Request) {
		type authorize struct {
			AppId       string `json:"appId"`
			PKCECode    string `json:"PKCECode"`
			PKCEMethod  string `json:"PKCEMethod"`
			RedirectUri string `json:"redirectUri"`
			Nonce       string `json:"nonce"`
			Deny        bool   `json:"deny"`
			Token       string `json:"token"`
		}

		var data authorize
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Verify the AppID, redirectUri and scopes
		var appId, redirectUri, scopes string
		err = conn.DB.QueryRow("SELECT appId, redirectUri, scopes FROM oauth WHERE appId = $1", data.AppId).Scan(&appId, &redirectUri, &scopes)
		if err != nil {
			renderJSON(404, w, map[string]interface{}{"error": "App not found"}, information)
			return
		}

		if ensureTrailingSlash(redirectUri) != ensureTrailingSlash(data.RedirectUri) || appId != data.AppId {
			renderJSON(401, w, map[string]interface{}{"error": "OAuth screening failed"}, information)
			return
		}

		// If denied, return success
		if data.Deny {
			renderJSON(200, w, map[string]interface{}{"success": true}, information)
			return
		}

		// Unmarshal the scopes
		var scopesArray []string
		err = json.Unmarshal([]byte(scopes), &scopesArray)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "22"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Check if the OpenID scope is present
		var hasOpenid bool
		for _, scope := range scopesArray {
			if scope == "openid" {
				hasOpenid = true
				break
			}
		}

		// Check for the session
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Delete all ongoing logins for this user
		_, err = mem.Exec("DELETE FROM logins WHERE userId = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "23"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Check for nonce
		if data.Nonce == "" {
			// The nonce must actually be in a URL, so we can't have pure-binary data
			data.Nonce, err = randomChars(512)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "24"}, information)
				logFunc(err.Error(), 2, information)
				return
			}
		}

		// Create the exchange code
		exchangeCode, err := randomChars(512)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "25"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Insert the login
		if data.Nonce != "" {
			_, err = mem.Exec("INSERT INTO logins (appId, exchangeCode, pkce, pkceMethod, openid, userId, token, nonce) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", data.AppId, exchangeCode, data.PKCECode, data.PKCEMethod, hasOpenid, userId, data.Token, data.Nonce)
		} else {
			_, err = mem.Exec("INSERT INTO logins (appId, exchangeCode, pkce, pkceMethod, openid, userId, token) VALUES (?, ?, ?, ?, ?, ?, ?)", data.AppId, exchangeCode, data.PKCECode, data.PKCEMethod, hasOpenid, userId, data.Token)
		}
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "26"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return success
		renderJSON(200, w, map[string]interface{}{"exchangeCode": exchangeCode}, information)
	})

	router.Post("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		// Parse the form data
		err := r.ParseForm()
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid form data"}, information)
			return
		}

		// Declare the variables
		var appId, nonce, code string
		var userId []byte
		var openid bool

		// Check if the PKCE is present
		if r.Form.Get("code_verifier") != "" {
			// It is - get the PKCE code and method
			var pkceCode, pkceMethod string
			err = mem.QueryRow("SELECT pkce, pkceMethod, appId, userId, nonce, openid, token FROM logins WHERE exchangeCode = ?", r.Form.Get("code")).Scan(&pkceCode, &pkceMethod, &appId, &userId, &nonce, &openid, &code)
			if err != nil {
				renderJSON(404, w, map[string]interface{}{"error": "Code not found"}, information)
				return
			}

			// Check the appId matches
			if appId != r.Form.Get("client_id") {
				renderJSON(401, w, map[string]interface{}{"error": "OAuth screening failed"}, information)
				return
			}

			// Check the PKCE
			if pkceMethod == "S256" {
				if sha256Base64(r.Form.Get("code_verifier")) != pkceCode {
					renderJSON(403, w, map[string]interface{}{"error": "Invalid PKCE code"}, information)
					return
				}
			} else if pkceMethod == "plain" {
				if r.Form.Get("code_verifier") != pkceCode {
					renderJSON(403, w, map[string]interface{}{"error": "Invalid PKCE code"}, information)
					return
				}
			} else {
				renderJSON(400, w, map[string]interface{}{"error": "Invalid PKCE method"}, information)
				return
			}
		} else {
			// It isn't - don't get the PKCE code and method
			err = mem.QueryRow("SELECT appId, userId, nonce, openid, token FROM logins WHERE exchangeCode = ?", r.Form.Get("code")).Scan(&appId, &userId, &nonce, &openid, &code)
			if err != nil {
				renderJSON(404, w, map[string]interface{}{"error": "Code not found"}, information)
				return
			}

			// Check the appId matches
			if appId != r.Form.Get("client_id") {
				renderJSON(401, w, map[string]interface{}{"error": "OAuth screening failed"}, information)
				return
			}

			// Verify the secret
			var secret string
			err = conn.DB.QueryRow("SELECT \"secret\" FROM oauth WHERE appId = $1", r.Form.Get("client_id")).Scan(&secret)
			if err != nil {
				renderJSON(404, w, map[string]interface{}{"error": "App not found"}, information)
				return
			}

			if secret != r.Form.Get("client_secret") {
				renderJSON(401, w, map[string]interface{}{"error": "Invalid client secret"}, information)
				return
			}
		}

		// Delete the login
		_, err = mem.Exec("DELETE FROM logins WHERE userId = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "27"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Generate a new nonce if it doesn't exist
		if nonce == "" {
			nonce, err = randomChars(512)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "28"}, information)
				logFunc(err.Error(), 2, information)
				return
			}
		}

		// Create the JWTs
		var openIDTokenString string
		if openid {
			var username string
			err := conn.DB.QueryRow("SELECT username FROM users WHERE id = $1", userId).Scan(&username)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "29"}, information)
				logFunc(err.Error(), 2, information)
				return
			}

			openIDTemplate := jwt.MapClaims{
				"sub":       uuid.Must(uuid.FromBytes(userId)).String(),
				"iss":       hostName,
				"name":      username,
				"aud":       appId,
				"exp":       time.Now().Add(time.Hour * 24 * 7).Unix(),
				"iat":       time.Now().Unix(),
				"auth_time": time.Now().Unix(),
				"session":   code,
				"nonce":     nonce,
				"isOpenID":  true,
			}

			openIDToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, openIDTemplate)
			openIDToken.Header["kid"] = base64.StdEncoding.EncodeToString(publicKey[:8])
			openIDTokenString, err = openIDToken.SignedString(privateKey)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "30"}, information)
				logFunc(err.Error(), 2, information)
				return
			}
		}

		accessTokenTemplate := jwt.MapClaims{
			"exp":      time.Now().Add(time.Hour * 24 * 7).Unix(),
			"iat":      time.Now().Unix(),
			"session":  code,
			"nonce":    nonce,
			"aud":      appId,
			"isOpenID": false,
			"sub":      uuid.Must(uuid.FromBytes(userId)).String(),
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessTokenTemplate)
		accessToken.Header["kid"] = base64.StdEncoding.EncodeToString(publicKey[:8])
		accessTokenString, err := accessToken.SignedString(privateKey)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "31"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Delete all ongoing logins for this user
		_, err = mem.Exec("DELETE FROM logins WHERE userId = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "32"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return the tokens
		if openid {
			renderJSON(200, w, map[string]interface{}{"access_token": accessTokenString, "id_token": openIDTokenString, "token_type": "Bearer", "expires_in": 604800}, information)
		} else {
			renderJSON(200, w, map[string]interface{}{"access_token": accessTokenString, "token_type": "Bearer", "expires_in": 604800}, information)
		}
	})

	router.Options("/api/oauth/token", disableCorsHandleFunc)

	router.Post("/api/oauth/remove", func(w http.ResponseWriter, r *http.Request) {
		type remove struct {
			Token string `json:"token"`
			AppID string `json:"appId"`
		}

		var data remove
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Delete the oauth entry
		_, err = conn.DB.Exec("DELETE FROM oauth WHERE appId = $1 AND creator = $2", data.AppID, userId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(404, w, map[string]interface{}{"error": "App not found"}, information)
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "33"}, information)
				logFunc(err.Error(), 2, information)
			}
		} else {
			renderJSON(200, w, map[string]interface{}{"success": true}, information)
		}
	})

	router.Post("/api/oauth/add", func(w http.ResponseWriter, r *http.Request) {

		// Conveniently, we use this one for ISB as well, so we can re-use the struct
		var data authLibrary.OAuthInformation
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Generate a new secret
		// It must be able to be sent via JSON, so we can't have pure-binary data
		secret, err := randomChars(512)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "34"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Generate a new appId
		// It must be able to be sent via JSON, so we can't have pure-binary data
		appId, err := randomChars(32)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "35"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Validate the scopes
		var clientKeyShare bool
		for _, scope := range data.Scopes {
			if scope != "openid" && scope != "clientKeyShare" {
				renderJSON(400, w, map[string]interface{}{"error": "Invalid scope"}, information)
				return
			} else {
				if scope == "clientKeyShare" {
					clientKeyShare = true
				} else if scope != "openid" {
					logFunc("An impossible logic error has occurred, please move away from radiation or use ECC RAM", 1, information)
					renderJSON(400, w, map[string]interface{}{"error": "Invalid scope"}, information)
					return
				}
			}
		}

		// Marshal the scopes
		scopes, err := json.Marshal(data.Scopes)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "36"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Insert the oauth entry
		if clientKeyShare {
			_, err = conn.DB.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes, keyShareUri) VALUES ($1, $2, $3, $4, $5, $6, $7)", appId, secret, userId, data.Name, data.RedirectUri, scopes, data.KeyShareUri)
		} else {
			_, err = conn.DB.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes) VALUES ($1, $2, $3, $4, $5, $6)", appId, secret, userId, data.Name, data.RedirectUri, scopes)
		}
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "37"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return the appId and secret
		renderJSON(200, w, map[string]interface{}{"appId": appId, "key": secret}, information)
	})

	router.Post("/api/oauth/list", func(w http.ResponseWriter, r *http.Request) {
		type list struct {
			Token string `json:"token"`
		}

		var data list
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Get the apps
		rows, err := conn.DB.Query("SELECT appId, name, redirectUri, scopes, keyShareUri FROM oauth WHERE creator = $1", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "38"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		var dataOut []map[string]interface{}
		for rows.Next() {
			var appId, name, redirectUri, scopes, keyShareUri string
			err = rows.Scan(&appId, &name, &redirectUri, &scopes, &keyShareUri)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "39"}, information)
				logFunc(err.Error(), 2, information)
				return
			}

			// Marshal the scopes
			var scopesArray []string
			err = json.Unmarshal([]byte(scopes), &scopesArray)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "40"}, information)
				logFunc(err.Error(), 2, information)
				return
			}

			dataOut = append(dataOut, map[string]interface{}{
				"appId":       appId,
				"name":        name,
				"redirectUri": redirectUri,
				"scopes":      scopesArray,
				"keyShareUri": keyShareUri,
			})
		}
		err = rows.Err()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "41"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Close the rows
		err = rows.Close()
		if err != nil {
			// Memory leak, but we can't do anything about it
			logFunc(err.Error(), 1, information)
		}

		// Return the apps
		renderJSON(200, w, map[string]interface{}{
			"apps": dataOut,
		}, information)
	})

	router.Post("/api/deleteAccount", func(w http.ResponseWriter, r *http.Request) {
		type deleteAccount struct {
			Token string `json:"token"`
		}

		var data deleteAccount
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Delete the user
		_, err = conn.DB.Exec("DELETE FROM users WHERE id = $1", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "42"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Delete the user's sessions
		_, err = mem.Exec("DELETE FROM sessions WHERE id = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "43"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Delete the user's oauth entries
		_, err = conn.DB.Exec("DELETE FROM oauth WHERE creator = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "44"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Delete the user's active logins
		_, err = mem.Exec("DELETE FROM logins WHERE userId = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "45"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return success
		renderJSON(200, w, map[string]interface{}{"success": true}, information)
	})

	router.Post("/api/session/list", func(w http.ResponseWriter, r *http.Request) {
		type list struct {
			Token string `json:"token"`
		}

		var data list
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Get the sessions
		rows, err := mem.Query("SELECT session, device FROM sessions WHERE id = ?", userId)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "46"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		var dataOut []map[string]interface{}
		for rows.Next() {
			var session, device string
			err = rows.Scan(&session, &device)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "47"}, information)
				logFunc(err.Error(), 2, information)
				return
			}
			dataOut = append(dataOut, map[string]interface{}{
				"session": session,
				"device":  device,
			})
		}
		err = rows.Err()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "48"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Close the rows
		err = rows.Close()
		if err != nil {
			// Memory leak, but we can't do anything about it
			logFunc(err.Error(), 1, information)
		}

		// Return the sessions
		renderJSON(200, w, map[string]interface{}{
			"sessions": dataOut,
		}, information)
	})

	router.Post("/api/session/remove", func(w http.ResponseWriter, r *http.Request) {
		type remove struct {
			Token   string `json:"token"`
			Session string `json:"session"`
		}

		var data remove
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the session exists
		var userId []byte
		err = mem.QueryRow("SELECT id FROM sessions WHERE session = ?", data.Token).Scan(&userId)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid session"}, information)
			return
		}

		// Delete the session
		_, err = mem.Exec("DELETE FROM sessions WHERE id = $1 AND session = ?", userId, data.Session)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "49"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Return success
		renderJSON(200, w, map[string]interface{}{"success": true}, information)
	})

	router.Post("/api/listUsers", func(w http.ResponseWriter, r *http.Request) {
		type listUsers struct {
			AdminKey string `json:"adminKey"`
		}

		var data listUsers
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Check if the admin key is correct
		// Finally, I get to use the admin key
		// In previous versions, the admin key was very important - it handled server cookie-based secrets
		// as well as JWTs - but now it's just a glorified password
		if data.AdminKey != adminKey {
			renderJSON(401, w, map[string]interface{}{"error": "Invalid admin key"}, information)
			return
		}

		// Get the users
		rows, err := conn.DB.Query("SELECT id, username, created FROM users")
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "50"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		var dataOut []map[string]interface{}
		for rows.Next() {
			var id []byte
			var username string
			var created int64
			err = rows.Scan(&id, &username, &created)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "51"}, information)
				logFunc(err.Error(), 2, information)
				return
			}
			dataOut = append(dataOut, map[string]interface{}{
				// Also finally get a chance to represent UUIDs as strings. Everywhere else I just use them as bytes.
				"id":       uuid.Must(uuid.FromBytes(id)).String(),
				"username": username,
				"created":  created,
			})
		}
		err = rows.Err()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "52"}, information)
			logFunc(err.Error(), 2, information)
			return
		}

		// Close the rows
		err = rows.Close()
		if err != nil {
			// Memory leak, but we can't do anything about it
			logFunc(err.Error(), 1, information)
		}

		// Return the users
		renderJSON(200, w, map[string]interface{}{
			"users": dataOut,
		}, information)
	})

	router.Get("/.well-known/keys.json", func(w http.ResponseWriter, r *http.Request) {
		// Return the public key
		renderJSON(200, w, map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "OKP",
					"alg": "EdDSA",
					"use": "sig",
					"kid": base64.StdEncoding.EncodeToString(publicKey[:8]),
					"x":   base64.RawURLEncoding.EncodeToString(publicKey),
					"crv": "Ed25519",
				},
			},
		}, information)
	})

	go func() {
		for {
			// Sleep for half an hour
			time.Sleep(time.Minute * 30)

			// Delete everything in the spent and challenge-response tables that has expired
			affected, err := mem.Exec("DELETE FROM spent WHERE expires < ?", time.Now().Unix())
			if err != nil {
				logFunc(err.Error(), 1, information)
			} else {
				affectedCount, err := affected.RowsAffected()
				if err != nil {
					logFunc(err.Error(), 1, information)
				} else {
					affected, err := mem.Exec("DELETE FROM challengeResponse WHERE expires < ?", time.Now().Unix())
					if err != nil {
						logFunc(err.Error(), 1, information)
					} else {
						affectedCount2, err := affected.RowsAffected()
						if err != nil {
							logFunc(err.Error(), 1, information)
						} else {
							logFunc("Cleanup complete, deleted "+strconv.FormatInt(affectedCount+affectedCount2, 10)+" entries", 0, information)
						}
					}
				}
			}
		}
	}()

	go func() {
		for {
			// Wait for a message
			message := <-information.Inbox

			if message.ServiceID != uuid.MustParse("00000000-0000-0000-0000-000000000001") {
				// Check the message type
				switch message.MessageType {
				case 0:
					// A service would like to know our hostname
					// Send it to them
					information.Outbox <- library.InterServiceMessage{
						MessageType:  0,
						ServiceID:    ServiceInformation.ServiceID,
						ForServiceID: message.ServiceID,
						Message:      hostName,
						SentAt:       time.Now(),
					}
				case 1:
					// A service would like to register a new OAuth entry
					// Check if the service already has an OAuth entry
					var appId, secret string
					err := conn.DB.QueryRow("SELECT appId, secret FROM oauth WHERE appId = $1", message.ServiceID.String()).Scan(&appId, &secret)
					if err == nil && appId == message.ServiceID.String() {
						// Don't complain, it's fine
						information.Outbox <- library.InterServiceMessage{
							MessageType:  0,
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							Message: authLibrary.OAuthResponse{
								AppID:     appId,
								SecretKey: secret,
							},
							SentAt: time.Now(),
						}
						return
					}

					// Generate a new secret
					// It must be able to be sent via JSON, so we can't have pure-binary data
					secret, err = randomChars(512)
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							MessageType:  1,
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							Message:      "36",
							SentAt:       time.Now(),
						}
						logFunc(err.Error(), 2, information)
						return
					}

					// Validate the scopes
					var clientKeyShare bool
					for _, scope := range message.Message.(authLibrary.OAuthInformation).Scopes {
						if scope != "openid" && scope != "clientKeyShare" {
							information.Outbox <- library.InterServiceMessage{
								MessageType:  2,
								ServiceID:    ServiceInformation.ServiceID,
								ForServiceID: message.ServiceID,
								Message:      "Invalid scope",
								SentAt:       time.Now(),
							}
							return
						} else {
							if scope == "clientKeyShare" {
								clientKeyShare = true
							} else if scope != "openid" {
								logFunc("An impossible logic error has occurred, please move away from radiation or use ECC RAM", 1, information)
								information.Outbox <- library.InterServiceMessage{
									MessageType:  2,
									ServiceID:    ServiceInformation.ServiceID,
									ForServiceID: message.ServiceID,
									Message:      "Invalid scope",
									SentAt:       time.Now(),
								}
								return
							}
						}
					}

					// Marshal the scopes
					scopes, err := json.Marshal(message.Message.(authLibrary.OAuthInformation).Scopes)
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							MessageType:  1,
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							Message:      "38",
							SentAt:       time.Now(),
						}
						logFunc(err.Error(), 2, information)
						return
					}

					// Insert the oauth entry
					if clientKeyShare {
						_, err = conn.DB.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes, keyShareUri) VALUES ($1, $2, $3, $4, $5, $6, $7)", message.ServiceID.String(), secret, ServiceInformation.ServiceID, message.Message.(authLibrary.OAuthInformation).Name, message.Message.(authLibrary.OAuthInformation).RedirectUri, scopes, message.Message.(authLibrary.OAuthInformation).KeyShareUri)
					} else {
						_, err = conn.DB.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes) VALUES ($1, $2, $3, $4, $5, $6)", message.ServiceID.String(), secret, ServiceInformation.ServiceID, message.Message.(authLibrary.OAuthInformation).Name, message.Message.(authLibrary.OAuthInformation).RedirectUri, scopes)
					}
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							MessageType:  1,
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							Message:      "39",
							SentAt:       time.Now(),
						}
						logFunc(err.Error(), 2, information)
						return
					}

					// Return the appId and secret
					information.Outbox <- library.InterServiceMessage{
						MessageType:  0,
						ServiceID:    ServiceInformation.ServiceID,
						ForServiceID: message.ServiceID,
						Message: authLibrary.OAuthResponse{
							AppID:     appId,
							SecretKey: secret,
						},
						SentAt: time.Now(),
					}
				case 2:
					// A service would like to have the public key
					// Send it to them
					information.Outbox <- library.InterServiceMessage{
						MessageType:  2,
						ServiceID:    ServiceInformation.ServiceID,
						ForServiceID: message.ServiceID,
						Message:      publicKey,
						SentAt:       time.Now(),
					}
				}
			}
		}
	}()
}
