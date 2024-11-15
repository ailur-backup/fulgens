package main

import (
	library "git.ailur.dev/ailur/fg-library/v2"
	"os/signal"
	"syscall"

	"errors"
	"io"
	"log"
	"mime"
	"os"
	"plugin"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/CAFxX/httpcompression"
	"github.com/CAFxX/httpcompression/contrib/andybalholm/brotli"
	"github.com/CAFxX/httpcompression/contrib/klauspost/gzip"
	"github.com/CAFxX/httpcompression/contrib/klauspost/zstd"
	kpzstd "github.com/klauspost/compress/zstd"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	Global struct {
		IP                string              `yaml:"ip" validate:"required,ip_addr"`
		ServiceDirectory  string              `yaml:"serviceDirectory" validate:"required"`
		ResourceDirectory string              `yaml:"resourceDirectory" validate:"required"`
		Compression       CompressionSettings `yaml:"compression"`
		Logging           struct {
			Enabled bool   `yaml:"enabled"`
			File    string `yaml:"file" validate:"required_if=Enabled true"`
		} `yaml:"logging"`
		Database struct {
			Type             string `yaml:"type" validate:"required,oneof=sqlite postgres"`
			ConnectionString string `yaml:"connectionString" validate:"required_if=Type postgres"`
			Path             string `yaml:"path" validate:"required_if=Type sqlite"`
		} `yaml:"database" validate:"required"`
		Stealth struct {
			Enabled bool   `yaml:"enabled"`
			Server  string `yaml:"server" validate:"required_if=Enabled true"`
			PHP     struct {
				Enabled bool   `yaml:"enabled"`
				Version string `yaml:"version" validate:"required_if=Enabled true"`
			} `yaml:"php"`
			ASPNet bool `yaml:"aspNet"`
		}
	} `yaml:"global" validate:"required"`
	Routes []struct {
		Port      string   `yaml:"port" validate:"required"`
		Subdomain string   `yaml:"subdomain" validate:"required"`
		Services  []string `yaml:"services"`
		Paths     []struct {
			Paths []string `yaml:"paths" validate:"required"`
			Proxy struct {
				URL         string         `yaml:"url" validate:"required"`
				StripPrefix bool           `yaml:"stripPrefix"`
				Headers     HeaderSettings `yaml:"headers"`
			} `yaml:"proxy" validate:"required_without=Static Redirect"`
			Static struct {
				Root             string `yaml:"root" validate:"required,isDirectory"`
				DirectoryListing bool   `yaml:"directoryListing"`
			} `yaml:"static" validate:"required_without_all=Proxy Redirect"`
			Redirect struct {
				URL       string `yaml:"url" validate:"required"`
				Permanent bool   `yaml:"permanent"`
			} `yaml:"redirect" validate:"required_without_all=Proxy Static"`
		} `yaml:"paths"`
		HTTPS struct {
			CertificatePath string `yaml:"certificate" validate:"required"`
			KeyPath         string `yaml:"key" validate:"required"`
		} `yaml:"https"`
		Compression CompressionSettings `yaml:"compression"`
	} `yaml:"routes"`
	Services map[string]interface{} `yaml:"services"`
}

type HeaderSettings struct {
	Forbid             []string `yaml:"forbid"`
	PreserveServer     bool     `yaml:"preserveServer"`
	PreserveXPoweredBy bool     `yaml:"preserveXPoweredBy"`
	PreserveAltSvc     bool     `yaml:"preserveAltSvc"`
	PassHost           bool     `yaml:"passHost"`
	XForward           bool     `yaml:"xForward"`
}

type Service struct {
	ServiceID       uuid.UUID
	ServiceMetadata library.Service
	ServiceMainFunc func(library.ServiceInitializationInformation)
	Inbox           chan library.InterServiceMessage
}

type CompressionSettings struct {
	Algorithm string `yaml:"algorithm" validate:"omitempty,oneof=gzip brotli zstd"`
	Level     int    `yaml:"level" validate:"omitempty,min=1,max=22"`
}

type RouterAndCompression struct {
	Router      *chi.Mux
	Compression CompressionSettings
}

type PortRouter struct {
	https struct {
		enabled      bool
		httpSettings map[string]*tls.Certificate
	}
	routers map[string]RouterAndCompression
}

func NewPortRouter() *PortRouter {
	return &PortRouter{
		routers: make(map[string]RouterAndCompression),
		https: struct {
			enabled      bool
			httpSettings map[string]*tls.Certificate
		}{enabled: false, httpSettings: make(map[string]*tls.Certificate)},
	}
}

func (pr *PortRouter) Register(router *chi.Mux, compression CompressionSettings, subdomain string, certificate ...*tls.Certificate) {
	pr.routers[subdomain] = RouterAndCompression{Router: router, Compression: compression}
	if len(certificate) > 0 {
		pr.https.enabled = true
		pr.https.httpSettings[subdomain] = certificate[0]
	}
}

func (pr *PortRouter) Router(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	router, ok := pr.routers[host]
	if !ok {
		router, ok = pr.routers["none"]
	}

	if router.Compression.Algorithm != "none" {
		compressRouter(router.Compression, router.Router).ServeHTTP(w, r)
	} else {
		router.Router.ServeHTTP(w, r)
	}
}

func (pr *PortRouter) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := pr.https.httpSettings[hello.ServerName]
	if !ok {
		return nil, errors.New("certificate not found")
	} else {
		return cert, nil
	}
}

func (pr *PortRouter) HTTPSEnabled() bool {
	return pr.https.enabled
}

func compressRouter(settings CompressionSettings, handler http.Handler) http.Handler {
	switch settings.Algorithm {
	case "gzip":
		encoder, err := gzip.New(gzip.Options{Level: int(settings.Level)})
		if err != nil {
			slog.Error("Error creating gzip encoder: " + err.Error())
			return handler
		}
		gzipHandler, err := httpcompression.Adapter(httpcompression.Compressor(gzip.Encoding, 0, encoder))
		if err != nil {
			slog.Error("Error creating gzip handler: " + err.Error())
			return handler
		}
		return gzipHandler(handler)
	case "brotli":
		encoder, err := brotli.New(brotli.Options{Quality: int(settings.Level)})
		if err != nil {
			slog.Error("Error creating brotli encoder: " + err.Error())
			return handler
		}
		brotliHandler, err := httpcompression.Adapter(httpcompression.Compressor(brotli.Encoding, 0, encoder))
		if err != nil {
			slog.Error("Error creating brotli handler: " + err.Error())
			return handler
		}
		return brotliHandler(handler)
	case "zstd":
		encoder, err := zstd.New(kpzstd.WithEncoderLevel(kpzstd.EncoderLevelFromZstd(int(settings.Level))))
		if err != nil {
			slog.Error("Error creating zstd encoder: " + err.Error())
			return handler
		}
		zstdHandler, err := httpcompression.Adapter(httpcompression.Compressor(zstd.Encoding, 0, encoder))
		if err != nil {
			slog.Error("Error creating zstd handler: " + err.Error())
			return handler
		}
		return zstdHandler(handler)
	default:
		return handler
	}
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		slog.Info(r.Method + " " + r.URL.Path)
	})
}

func serverChanger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.Global.Stealth.Enabled {
			if !strings.Contains("Server", w.Header().Get(":X-Preserve-Headers")) {
				w.Header().Set("Server", "Fulgens HTTP Server")
			}
			if !strings.Contains("X-Powered-By", w.Header().Get(":X-Preserve-Headers")) {
				w.Header().Set("X-Powered-By", "Go net/http")
			}
			if !strings.Contains("Alt-Svc", w.Header().Get(":X-Preserve-Headers")) {
				w.Header().Set("Alt-Svc", "h2=\":443\"; ma=3600")
			}
		} else {
			switch config.Global.Stealth.Server {
			case "nginx":
				w.Header().Set("Server", "nginx")
			}

			var poweredBy strings.Builder
			if config.Global.Stealth.PHP.Enabled {
				poweredBy.WriteString("PHP/" + config.Global.Stealth.PHP.Version)
			}

			if config.Global.Stealth.ASPNet {
				if poweredBy.Len() > 0 {
					poweredBy.WriteString(", ")
				}

				poweredBy.WriteString("ASP.NET")
			}

			if poweredBy.Len() > 0 {
				w.Header().Set("X-Powered-By", poweredBy.String())
			}
		}
		next.ServeHTTP(w, r)
	})
}

func listDirectory(w http.ResponseWriter, r *http.Request, root string, path string) {
	// Provide a directory listing
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/html")
	_, err := w.Write([]byte("<html><body><h2>Directory listing</h2><ul>"))
	if err != nil {
		serverError(w, 500)
		slog.Error("Error writing directory listing: " + err.Error())
		return
	}
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(r.URL.Path)))
	if err != nil {
		serverError(w, 500)
		slog.Error("Error listing directory: " + err.Error())
		return
	}
	for _, entry := range entries {
		relPath, err := filepath.Rel(root, filepath.Join(root, filepath.FromSlash(r.URL.Path), entry.Name()))
		if err != nil {
			serverError(w, 500)
			slog.Error("Error getting relative path: " + err.Error())
			return
		}
		_, err = w.Write([]byte("<li><a href=\"" + path + strings.TrimPrefix(relPath, "./") + "\">" + entry.Name() + "</a></li>"))
		if err != nil {
			serverError(w, 500)
			slog.Error("Error writing directory listing: " + err.Error())
			return
		}
	}
	_, err = w.Write([]byte("</ul></body></html>"))
	if err != nil {
		serverError(w, 500)
		slog.Error("Error writing directory listing: " + err.Error())
		return
	}
}

func parseEndRange(w http.ResponseWriter, file *os.File, end string) {
	endI64, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error parsing range: " + err.Error())
		return
	}
	_, err = file.Seek(-endI64, io.SeekEnd)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error seeking file: " + err.Error())
		return
	}
	_, err = io.Copy(w, file)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error writing file: " + err.Error())
		return
	}
}

func parseBeginningRange(w http.ResponseWriter, file *os.File, beginning string) {
	beginningI64, err := strconv.ParseInt(beginning, 10, 64)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error parsing range: " + err.Error())
		return
	}
	_, err = file.Seek(beginningI64, io.SeekStart)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error seeking file: " + err.Error())
		return
	}
	_, err = io.Copy(w, file)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error writing file: " + err.Error())
		return
	}
}

func parsePartRange(w http.ResponseWriter, file *os.File, beginning, end string) {
	beginningI64, err := strconv.ParseInt(beginning, 10, 64)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error parsing range: " + err.Error())
		return
	}
	endI64, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error parsing range: " + err.Error())
		return
	}
	_, err = file.Seek(beginningI64, io.SeekStart)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error seeking file: " + err.Error())
		return
	}
	_, err = io.CopyN(w, file, endI64-beginningI64)
	if err != nil {
		serverError(w, 500)
		slog.Error("Error writing file: " + err.Error())
		return
	}
}

func newFileServer(root string, directoryListing bool, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stat, err := os.Stat(filepath.Join(root, filepath.FromSlash(r.URL.Path)))
		if err != nil {
			serverError(w, 404)
			return
		}

		if stat.IsDir() {
			// See if index.html exists
			_, err := os.Stat(filepath.Join(root, filepath.FromSlash(r.URL.Path), "index.html"))
			if err != nil {
				if directoryListing {
					listDirectory(w, r, root, path)
				} else {
					serverError(w, 403)
				}
				return
			} else {
				// Serve the index.html file
				r.URL.Path = filepath.Join(r.URL.Path, "index.html")
			}
		}

		file, err := os.Open(filepath.Join(root, filepath.FromSlash(r.URL.Path)))
		if err != nil {
			serverError(w, 500)
			return
		}

		w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(r.URL.Path)))

		if strings.HasPrefix(r.Header.Get("Range"), "bytes=") {
			// Parse the range header. If there is an int-int, seek to the first int then return a limitedReader.
			// If there is an int-, seek to the first int and return the rest of the file.
			// If there is an -int, seek to the end of the file minus int and return the last int bytes.
			for _, item := range strings.Split(strings.TrimPrefix(r.Header.Get("Range"), "bytes="), ", ") {
				if strings.Contains(item, "-") {
					beginning := strings.Split(item, "-")[0]
					end := strings.Split(item, "-")[1]
					if beginning == "" {
						parseEndRange(w, file, end)
					} else if end == "" {
						parseBeginningRange(w, file, beginning)
					} else {
						parsePartRange(w, file, beginning, end)
					}
				} else {
					serverError(w, 416)
					return
				}
			}
		} else {
			_, err = io.Copy(w, file)
			if err != nil {
				serverError(w, 500)
				slog.Error("Error writing file: " + err.Error())
				return
			}

			err = file.Close()
			if err != nil {
				slog.Error("Error closing file: " + err.Error())
			}
		}
	})
}

func newReverseProxy(uri *url.URL, headerSettings HeaderSettings) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(uri)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the headers
		for _, header := range headerSettings.Forbid {
			r.Header.Del(header)
		}
		if !headerSettings.PassHost {
			r.Host = uri.Host
		}
		if !headerSettings.XForward {
			r.Header["X-Forwarded-For"] = nil
		} else {
			r.Header.Set("X-Forwarded-Host", r.Host)
			if r.URL.Scheme != "" {
				r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
		}

		// Set the preserve headers which will be stripped by the server changer
		var xPreserveHeaders strings.Builder

		if headerSettings.PreserveServer {
			xPreserveHeaders.WriteString("Server")
		}

		if headerSettings.PreserveXPoweredBy {
			if xPreserveHeaders.Len() > 0 {
				xPreserveHeaders.WriteString(", ")
			}
			xPreserveHeaders.WriteString("X-Powered-By")
		}

		if headerSettings.PreserveAltSvc {
			if xPreserveHeaders.Len() > 0 {
				xPreserveHeaders.WriteString(", ")
			}
			xPreserveHeaders.WriteString("Alt-Svc")
		}

		w.Header().Set(":X-Preserve-Headers", xPreserveHeaders.String())

		proxy.ServeHTTP(w, r)
	})
}

func serverError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	if !config.Global.Stealth.Enabled {
		_, err := w.Write([]byte("<html><body><h2>" + strconv.Itoa(status) + " " + http.StatusText(status) + "</h2><span>Fulgens HTTP Server</span></body></html>"))
		if err != nil {
			slog.Error("Error writing " + strconv.Itoa(status) + ": " + err.Error())
			return
		}
	} else {
		switch config.Global.Stealth.Server {
		case "nginx":
			_, err := w.Write([]byte("<html><head><title>" + strconv.Itoa(status) + " " + http.StatusText(status) + "</title></head>\n<body>\n<center><h1>" + strconv.Itoa(status) + " " + http.StatusText(status) + "</h1></center>\n<hr><center>nginx/1.27.2</center>\n\n\n</body></html>"))
			if err != nil {
				slog.Error("Error writing " + strconv.Itoa(status) + ": " + err.Error())
				return
			}
		case "net/http":
			_, err := w.Write([]byte(strconv.Itoa(status) + " " + http.StatusText(status)))
			if err != nil {
				slog.Error("Error writing " + strconv.Itoa(status) + ": " + err.Error())
				return
			}
		}
	}
}

var (
	validate           *validator.Validate
	lock               sync.RWMutex
	config             Config
	registeredServices = make(map[string]Service)
	activeServices     = make(map[uuid.UUID]Service)
	portRouters        = make(map[string]*PortRouter)
)

func loadTLSCertificate(certificatePath, keyPath string) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, err
	} else {
		return &certificate, nil
	}
}

func svInit(message library.InterServiceMessage) {
	// Service database initialization message
	// Check if the service has the necessary permissions
	if activeServices[message.ServiceID].ServiceMetadata.Permissions.Database {
		// Check if we are using sqlite or postgres
		if config.Global.Database.Type == "sqlite" {
			// Open the database and return the connection
			pluginConn, err := sql.Open("sqlite3", filepath.Join(config.Global.Database.Path, message.ServiceID.String()+".db"))
			if err != nil {
				// Report an error
				activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  1,
					SentAt:       time.Now(),
					Message:      err,
				}
			} else {
				// Report a successful activation
				activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  2,
					SentAt:       time.Now(),
					Message: library.Database{
						DB:     pluginConn,
						DBType: library.Sqlite,
					},
				}
			}
		} else if config.Global.Database.Type == "postgres" {
			// Connect to the database
			conn, err := sql.Open("postgres", config.Global.Database.ConnectionString)
			if err != nil {
				// Report an error
				activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  1,
					SentAt:       time.Now(),
					Message:      err,
				}
			} else {
				// Try to create the schema
				_, err = conn.Exec("CREATE SCHEMA IF NOT EXISTS \"" + message.ServiceID.String() + "\"")
				if err != nil {
					// Report an error
					activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
						ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
						ForServiceID: message.ServiceID,
						MessageType:  1,
						SentAt:       time.Now(),
						Message:      err,
					}
				} else {
					// Create a new connection to the database
					var connectionString string
					if strings.Contains(config.Global.Database.ConnectionString, "?") {
						connectionString = config.Global.Database.ConnectionString + "&search_path=\"" + message.ServiceID.String() + "\""
					} else {
						connectionString = config.Global.Database.ConnectionString + "?search_path=\"" + message.ServiceID.String() + "\""
					}
					pluginConn, err := sql.Open("postgres", connectionString)
					if err != nil {
						// Report an error
						activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
							ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
							ForServiceID: message.ServiceID,
							MessageType:  1,
							SentAt:       time.Now(),
							Message:      err,
						}
					} else {
						// Test the connection
						err = pluginConn.Ping()
						if err != nil {
							// Report an error
							activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
								ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
								ForServiceID: message.ServiceID,
								MessageType:  1,
								SentAt:       time.Now(),
								Message:      err,
							}
						} else {
							// Report a successful activation
							activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
								ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
								ForServiceID: message.ServiceID,
								MessageType:  2,
								SentAt:       time.Now(),
								Message: library.Database{
									DB:     pluginConn,
									DBType: library.Postgres,
								},
							}
						}
					}
				}
			}
		}
	} else {
		// Report an error
		activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
			ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			ForServiceID: message.ServiceID,
			MessageType:  1,
			SentAt:       time.Now(),
			Message:      errors.New("database access not permitted"),
		}
	}
}

func tryAuthAccess(message library.InterServiceMessage) {
	// We need to check if the service is allowed to access the Authentication service
	serviceMetadata, ok := activeServices[message.ServiceID]
	if ok && serviceMetadata.ServiceMetadata.Permissions.Authenticate {
		// Send message to Authentication service
		service, ok := activeServices[uuid.MustParse("00000000-0000-0000-0000-000000000004")]
		if ok {
			service.Inbox <- message
		} else {
			// Send error message
			service, ok := activeServices[message.ServiceID]
			if ok {
				service.Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  1,
					SentAt:       time.Now(),
					Message:      errors.New("authentication service not found"),
				}
			} else {
				// This should never happen
				slog.Error("Bit flip error: Impossible service ID. Move away from radiation or use ECC memory.")
				os.Exit(1)
			}
		}
	} else {
		// Send error message
		service, ok := activeServices[message.ServiceID]
		if ok {
			service.Inbox <- library.InterServiceMessage{
				ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				ForServiceID: message.ServiceID,
				MessageType:  1,
				SentAt:       time.Now(),
				Message:      errors.New("authentication not permitted"),
			}
		} else {
			// This should never happen
			slog.Error("Bit flip error: Impossible service ID. Move away from radiation or use ECC memory.")
			os.Exit(1)
		}
	}
}

func tryStorageAccess(message library.InterServiceMessage) {
	// We need to check if the service is allowed to access the Blob Storage service
	serviceMetadata, ok := activeServices[message.ServiceID]
	if ok && serviceMetadata.ServiceMetadata.Permissions.BlobStorage {
		// Send message to Blob Storage service
		service, ok := activeServices[uuid.MustParse("00000000-0000-0000-0000-000000000003")]
		if ok {
			service.Inbox <- message
		} else {
			// Send error message
			service, ok := activeServices[message.ServiceID]
			if ok {
				service.Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  1,
					SentAt:       time.Now(),
					Message:      errors.New("blob storage service not found"),
				}
			} else {
				// This should never happen
				slog.Error("Bit flip error: Impossible service ID. Move away from radiation or use ECC memory.")
				os.Exit(1)
			}
		}
	} else {
		// Send error message
		service, ok := activeServices[message.ServiceID]
		if ok {
			service.Inbox <- library.InterServiceMessage{
				ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				ForServiceID: message.ServiceID,
				MessageType:  1,
				SentAt:       time.Now(),
				Message:      errors.New("blob storage is not permitted"),
			}
		} else {
			// This should never happen
			slog.Error("Bit flip error: Impossible service ID. Move away from radiation or use ECC memory.")
			os.Exit(1)
		}
	}
}

func tryLogger(message library.InterServiceMessage) {
	// Logger service
	service, ok := activeServices[message.ServiceID]
	if ok {
		switch message.MessageType {
		case 0:
			// Log message
			slog.Info(strings.ToLower(service.ServiceMetadata.Name) + " says: " + message.Message.(string))
		case 1:
			// Warn message
			slog.Warn(strings.ToLower(service.ServiceMetadata.Name) + " warns: " + message.Message.(string))
		case 2:
			// Error message
			slog.Error(strings.ToLower(service.ServiceMetadata.Name) + " complains: " + message.Message.(string))
		case 3:
			// Fatal message
			slog.Error(strings.ToLower(service.ServiceMetadata.Name) + "'s dying wish: " + message.Message.(string))
			os.Exit(1)
		}
	}
}

func processInterServiceMessage(channel chan library.InterServiceMessage) {
	for {
		message := <-channel
		if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000000") {
			// Broadcast message
			for _, service := range activeServices {
				service.Inbox <- message
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000001") {
			// Service initialization service
			switch message.MessageType {
			case 0:
				// This has been deprecated, ignore it
				// Send "true" back
				activeServices[message.ServiceID].Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  0,
					SentAt:       time.Now(),
					Message:      true,
				}
			case 1:
				svInit(message)
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000002") {
			tryLogger(message)
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000003") {
			tryStorageAccess(message)
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000004") {
			tryAuthAccess(message)
		} else {
			serviceMetadata, ok := activeServices[message.ServiceID]
			if ok && serviceMetadata.ServiceMetadata.Permissions.InterServiceCommunication {
				// Send message to specific service
				service, ok := activeServices[message.ForServiceID]
				if !ok {
					// Send error message
					service, ok := activeServices[message.ServiceID]
					if ok {
						service.Inbox <- library.InterServiceMessage{
							ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
							ForServiceID: message.ServiceID,
							MessageType:  1,
							SentAt:       time.Now(),
							Message:      errors.New("requested service not found"),
						}
					} else {
						// This should never happen
						slog.Error("Bit flip error: Impossible service ID. Move away from radiation or use ECC memory.")
						os.Exit(1)
					}
				}
				service.Inbox <- message
			} else {
				// Send error message
				service, ok := activeServices[message.ServiceID]
				if ok {
					service.Inbox <- library.InterServiceMessage{
						ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
						ForServiceID: message.ServiceID,
						MessageType:  1,
						SentAt:       time.Now(),
						Message:      errors.New("inter-service communication not permitted"),
					}
				} else {
					// This should never happen
					slog.Error("Bit flip error: Impossible service ID. Move away from radiation or use ECC memory.")
					os.Exit(1)
				}
			}
		}
	}
}

func parseConfig(path string) Config {
	// Register the custom validators
	validate = validator.New()

	// Register the custom isDirectory validator
	err := validate.RegisterValidation("isDirectory", func(fl validator.FieldLevel) bool {
		// Check if it exists
		fileInfo, err := os.Stat(fl.Field().String())
		if err != nil {
			return false
		}

		// Check if it is a directory
		return fileInfo.IsDir()
	})

	if err != nil {
		slog.Error("Error registering custom validator: " + err.Error())
		os.Exit(1)
	}

	// Parse the configuration file
	configFile, err := os.Open(path)
	if err != nil {
		slog.Error("Error reading configuration file: " + err.Error())
		os.Exit(1)
	}

	// Parse the configuration file
	decoder := yaml.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		slog.Error("Error parsing configuration file: " + err.Error())
		os.Exit(1)
	}

	// Validate the configuration
	err = validate.Struct(config)
	if err != nil {
		slog.Error("Invalid configuration: " + err.Error())
		os.Exit(1)
	}

	// Check if we are logging to a file
	if config.Global.Logging != (Config{}.Global.Logging) && config.Global.Logging.Enabled {
		// Check if the log file is set
		logFilePath := config.Global.Logging.File

		// Set the log file
		logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			slog.Error("Error opening log file: " + err.Error())
			os.Exit(1)
		}

		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	}

	return config
}

func iterateThroughSubdomains(globalOutbox chan library.InterServiceMessage) {
	for _, route := range config.Routes {
		var compressionSettings CompressionSettings
		if route.Compression != (CompressionSettings{}) {
			compressionSettings = route.Compression
		} else {
			compressionSettings = config.Global.Compression
		}

		// Create the subdomain router
		subdomainRouter := chi.NewRouter()
		subdomainRouter.NotFound(func(w http.ResponseWriter, r *http.Request) {
			serverError(w, 404)
		})

		_, ok := portRouters[route.Port]
		if !ok {
			portRouters[route.Port] = NewPortRouter()
		}

		// Check if HTTPS is enabled
		if route.HTTPS.KeyPath != "" && route.HTTPS.CertificatePath != "" {
			certificate, err := loadTLSCertificate(route.HTTPS.CertificatePath, route.HTTPS.KeyPath)
			if err != nil {
				slog.Error("Error loading TLS certificate: " + err.Error())
				os.Exit(1)
			}
			portRouters[route.Port].Register(subdomainRouter, compressionSettings, route.Subdomain, certificate)
		} else {
			portRouters[route.Port].Register(subdomainRouter, compressionSettings, route.Subdomain)
		}

		// Check the services
		if route.Services != nil {
			// Iterate through the services
			for _, service := range route.Services {
				// Check if the service is registered
				registeredService, ok := registeredServices[service]
				if ok {
					// Check if the service is already active
					_, ok := activeServices[registeredService.ServiceMetadata.ServiceID]
					if ok {
						slog.Error("Service with ID " + service + " is already active, will not activate again")
						os.Exit(1)
					}
					// Initialize the service
					initializeService(registeredService, globalOutbox, subdomainRouter)
				} else {
					slog.Warn("Service with ID " + service + " is not registered")
				}
			}
		}

		// Iterate through the paths
		for _, pathBlock := range route.Paths {
			for _, path := range pathBlock.Paths {
				if pathBlock.Static.Root != "" {
					// Serve the static directory
					rawPath := strings.TrimSuffix(path, "*")
					subdomainRouter.Handle(path, http.StripPrefix(rawPath, newFileServer(pathBlock.Static.Root, pathBlock.Static.DirectoryListing, rawPath)))
					slog.Info("Serving static directory " + pathBlock.Static.Root + " on subdomain " + route.Subdomain + " with pattern " + path)
				} else if pathBlock.Proxy.URL != "" {
					// Create the proxy
					parsedURL, err := url.Parse(pathBlock.Proxy.URL)
					if err != nil {
						slog.Error("Error parsing URL: " + err.Error())
						os.Exit(1)
					}
					if pathBlock.Proxy.StripPrefix {
						subdomainRouter.Handle(path, http.StripPrefix(strings.TrimSuffix(path, "*"), newReverseProxy(parsedURL, pathBlock.Proxy.Headers)))
					} else {
						subdomainRouter.Handle(path, newReverseProxy(parsedURL, pathBlock.Proxy.Headers))
					}
				} else if pathBlock.Redirect.URL != "" {
					// Set the code
					code := http.StatusFound
					if pathBlock.Redirect.Permanent {
						code = http.StatusMovedPermanently
					}

					// Create the redirect
					subdomainRouter.Handle(path, http.RedirectHandler(pathBlock.Redirect.URL, code))
				}
			}
		}
	}
}

func registerServices() (err error) {
	err = filepath.Walk(config.Global.ServiceDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".fgs" {
			return nil
		}

		// Open the service
		service, err := plugin.Open(path)
		if err != nil {
			return err
		}

		// Load the service information
		serviceInformation, err := service.Lookup("ServiceInformation")
		if err != nil {
			return errors.New("service lacks necessary information")
		}

		// Load the main function
		mainFunc, err := service.Lookup("Main")
		if err != nil {
			return errors.New("service lacks necessary main function")
		}

		// Register the service
		var inbox = make(chan library.InterServiceMessage, 1)
		lock.Lock()
		registeredServices[strings.ToLower(serviceInformation.(*library.Service).Name)] = Service{
			ServiceID:       serviceInformation.(*library.Service).ServiceID,
			Inbox:           inbox,
			ServiceMetadata: *serviceInformation.(*library.Service),
			ServiceMainFunc: mainFunc.(func(library.ServiceInitializationInformation)),
		}
		lock.Unlock()

		// Log the service registration
		slog.Info("Service " + strings.ToLower(serviceInformation.(*library.Service).Name) + " registered with ID " + serviceInformation.(*library.Service).ServiceID.String())

		return nil
	})

	return err
}

func initializeService(service Service, globalOutbox chan library.InterServiceMessage, subdomainRouter *chi.Mux) {
	// Get the plugin from the map
	slog.Info("Activating service " + strings.ToLower(service.ServiceMetadata.Name) + " with ID " + service.ServiceMetadata.ServiceID.String())

	serviceInitializationInformation := library.ServiceInitializationInformation{
		Domain:        strings.ToLower(service.ServiceMetadata.Name),
		Configuration: config.Services[strings.ToLower(service.ServiceMetadata.Name)].(map[string]interface{}),
		Outbox:        globalOutbox,
		Inbox:         service.Inbox,
		Router:        subdomainRouter,
	}

	// Check if they want a resource directory
	if service.ServiceMetadata.Permissions.Resources {
		serviceInitializationInformation.ResourceDir = os.DirFS(filepath.Join(config.Global.ResourceDirectory, service.ServiceMetadata.ServiceID.String()))
	}

	// Add the service to the active services
	lock.Lock()
	activeServices[service.ServiceMetadata.ServiceID] = service
	lock.Unlock()

	// Call the main function
	service.ServiceMainFunc(serviceInitializationInformation)

	// Log the service activation
	slog.Info("Service " + strings.ToLower(service.ServiceMetadata.Name) + " activated with ID " + service.ServiceMetadata.ServiceID.String())
}

func main() {
	// Parse the configuration file
	if len(os.Args) < 2 {
		info, err := os.Stat("config.yaml")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				slog.Error("No configuration file provided")
				os.Exit(1)
			} else {
				slog.Error("Error reading configuration file: " + err.Error())
				os.Exit(1)
			}
		}

		if info.IsDir() {
			slog.Error("No configuration file provided")
			os.Exit(1)
		}

		config = parseConfig("config.yaml")
	} else {
		config = parseConfig(os.Args[1])
	}

	// If we are using sqlite, create the database directory if it does not exist
	if config.Global.Database.Type == "sqlite" {
		err := os.MkdirAll(config.Global.Database.Path, 0755)
		if err != nil {
			slog.Error("Error creating database directory: " + err.Error())
			os.Exit(1)
		}
	}

	// Walk through the service directory and load the plugins
	err := registerServices()
	if err != nil {
		slog.Error("Error registering services: " + err.Error())
		os.Exit(1)
	}

	var globalOutbox = make(chan library.InterServiceMessage, 1)

	// Initialize the service discovery, health-check, and logging services
	// Since these are core services, always allocate them the service IDs 0, 1, and 2
	// These are not dynamically loaded, as they are integral to the system functioning
	go processInterServiceMessage(globalOutbox)

	// Start the storage service
	initializeService(registeredServices["storage"], globalOutbox, nil)

	// Iterate through the subdomains and create the routers as well as the compression levels and service maps
	iterateThroughSubdomains(globalOutbox)

	// Start the servers
	slog.Info("Starting servers")
	for port, router := range portRouters {
		if !router.HTTPSEnabled() {
			go func() {
				// Start the HTTP server
				err = http.ListenAndServe(config.Global.IP+":"+port, logger(serverChanger(http.HandlerFunc(router.Router))))
				slog.Error("Error starting server: " + err.Error())
				os.Exit(1)
			}()
		} else {
			// Create the TLS server
			server := &http.Server{
				Addr:    config.Global.IP + ":" + port,
				Handler: logger(serverChanger(http.HandlerFunc(router.Router))),
				TLSConfig: &tls.Config{
					GetCertificate: router.GetCertificate,
				},
			}

			go func() {
				// Start the TLS server
				err = server.ListenAndServeTLS("", "")
				slog.Error("Error starting HTTPS server: " + err.Error())
				os.Exit(1)
			}()
		}
	}

	slog.Info("Servers started. Fulgens is now running. Press Ctrl+C to stop the server.")

	// Wait for a signal to stop the server
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel
}
