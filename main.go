package main

import (
	library "git.ailur.dev/ailur/fg-library/v2"

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

	"compress/gzip"
	"crypto/tls"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"

	"github.com/andybalholm/brotli"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	Global struct {
		IP                string `yaml:"ip" validate:"required,ip_addr"`
		HTTPPort          string `yaml:"httpPort" validate:"required"`
		HTTPSPort         string `yaml:"httpsPort" validate:"required"`
		ServiceDirectory  string `yaml:"serviceDirectory" validate:"required"`
		ResourceDirectory string `yaml:"resourceDirectory" validate:"required"`
		Compression       struct {
			Algorithm string  `yaml:"algorithm" validate:"omitempty,oneof=gzip brotli zstd"`
			Level     float64 `yaml:"level" validate:"omitempty,min=1,max=22"`
		} `yaml:"compression"`
		Logging struct {
			Enabled bool   `yaml:"enabled"`
			File    string `yaml:"file" validate:"required_if=Enabled true"`
		} `yaml:"logging"`
		Database struct {
			Type             string `yaml:"type" validate:"required,oneof=sqlite postgres"`
			ConnectionString string `yaml:"connectionString" validate:"required_if=Type postgres"`
			Path             string `yaml:"path" validate:"required_if=Type sqlite"`
		} `yaml:"database" validate:"required"`
	} `yaml:"global" validate:"required"`
	Routes []struct {
		Subdomain string   `yaml:"subdomain" validate:"required"`
		Services  []string `yaml:"services"`
		Paths     []struct {
			Path  string `yaml:"path" validate:"required"`
			Proxy struct {
				URL         string `yaml:"url" validate:"required"`
				StripPrefix bool   `yaml:"stripPrefix"`
			} `yaml:"proxy" validate:"required_without=Static"`
			Static struct {
				Root             string `yaml:"root" validate:"required,isDirectory"`
				DirectoryListing bool   `yaml:"directoryListing"`
			} `yaml:"static" validate:"required_without=Proxy"`
		} `yaml:"paths"`
		HTTPS struct {
			CertificatePath string `yaml:"certificatePath" validate:"required"`
			KeyPath         string `yaml:"keyPath" validate:"required"`
		} `yaml:"https"`
		Compression struct {
			Algorithm string  `yaml:"algorithm" validate:"omitempty,oneof=gzip brotli zstd"`
			Level     float64 `yaml:"level" validate:"omitempty,min=1,max=22"`
		} `yaml:"compression"`
	} `yaml:"routes"`
	Services map[string]interface{} `yaml:"services"`
}

type Service struct {
	ServiceID       uuid.UUID
	ServiceMetadata library.Service
	ServiceMainFunc func(library.ServiceInitializationInformation)
	Inbox           chan library.InterServiceMessage
}

type ResponseWriterWrapper struct {
	http.ResponseWriter
	io.Writer
}

type CompressionSettings struct {
	Level     int
	Algorithm string
}

func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *ResponseWriterWrapper) Write(p []byte) (int, error) {
	return w.Writer.Write(p)
}

func checkCompressionAlgorithm(algorithm string, handler http.Handler) http.Handler {
	switch algorithm {
	case "gzip":
		return gzipHandler(handler)
	case "brotli":
		return brotliHandler(handler)
	case "zstd":
		return zStandardHandler(handler)
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
		w.Header().Set("Server", "Fulgens HTTP Server")
		w.Header().Set("X-Powered-By", "Go net/http")
		next.ServeHTTP(w, r)
	})
}

func gzipHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var compressionLevel int
			var host string
			if r.Header.Get("Host") != "" {
				host = r.Header.Get("Host")
			} else {
				host = "none"
			}

			compressionSettings, ok := compression[host]
			if !ok {
				compressionLevel = int(config.Global.Compression.Level)
			} else {
				compressionLevel = compressionSettings.Level
			}

			gzipWriter, err := gzip.NewWriterLevel(w, compressionLevel)
			if err != nil {
				slog.Error("Error creating gzip writer: " + err.Error())
				next.ServeHTTP(w, r)
				return
			}
			defer func() {
				w.Header().Del("Content-Length")
				err := gzipWriter.Close()
				if errors.Is(err, http.ErrBodyNotAllowed) {
					// This is fine, all it means is that they have it cached, and we don't need to send it
					return
				} else if err != nil {
					slog.Error("Error closing gzip writer: " + err.Error())
				}
			}()
			gzipResponseWriter := &ResponseWriterWrapper{ResponseWriter: w, Writer: gzipWriter}
			if w.Header().Get("Content-Encoding") != "" {
				w.Header().Set("Content-Encoding", w.Header().Get("Content-Encoding")+", gzip")
			} else {
				w.Header().Set("Content-Encoding", "gzip")
			}
			next.ServeHTTP(gzipResponseWriter, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
func brotliHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
			var compressionLevel int
			var host string
			if r.Header.Get("Host") != "" {
				host = r.Header.Get("Host")
			} else {
				host = "none"
			}

			compressionSettings, ok := compression[host]
			if !ok {
				compressionLevel = int(config.Global.Compression.Level)
			} else {
				compressionLevel = compressionSettings.Level
			}

			brotliWriter := brotli.NewWriterV2(w, compressionLevel)
			defer func() {
				w.Header().Del("Content-Length")
				err := brotliWriter.Close()
				if errors.Is(err, http.ErrBodyNotAllowed) {
					// This is fine, all it means is that they have it cached, and we don't need to send it
					return
				} else if err != nil {
					slog.Error("Error closing Brotli writer: " + err.Error())
				}
			}()
			brotliResponseWriter := &ResponseWriterWrapper{ResponseWriter: w, Writer: brotliWriter}
			if w.Header().Get("Content-Encoding") != "" {
				w.Header().Set("Content-Encoding", w.Header().Get("Content-Encoding")+", br")
			} else {
				w.Header().Set("Content-Encoding", "br")
			}
			next.ServeHTTP(brotliResponseWriter, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func zStandardHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "zstd") {
			var compressionLevel int
			var host string
			if r.Header.Get("Host") != "" {
				host = r.Header.Get("Host")
			} else {
				host = "none"
			}

			compressionSettings, ok := compression[host]
			if !ok {
				compressionLevel = int(config.Global.Compression.Level)
			} else {
				compressionLevel = compressionSettings.Level
			}

			zStandardWriter, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(compressionLevel)))
			if err != nil {
				slog.Error("Error creating ZStandard writer: " + err.Error())
				next.ServeHTTP(w, r)
				return
			}
			defer func() {
				w.Header().Del("Content-Length")
				err := zStandardWriter.Close()
				if err != nil {
					if errors.Is(err, http.ErrBodyNotAllowed) {
						// This is fine, all it means is that they have it cached, and we don't need to send it
						return
					} else {
						slog.Error("Error closing ZStandard writer: " + err.Error())
					}
				}
			}()
			gzipResponseWriter := &ResponseWriterWrapper{ResponseWriter: w, Writer: zStandardWriter}
			if w.Header().Get("Content-Encoding") != "" {
				w.Header().Set("Content-Encoding", w.Header().Get("Content-Encoding")+", zstd")
			} else {
				w.Header().Set("Content-Encoding", "zstd")
			}
			next.ServeHTTP(gzipResponseWriter, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func listDirectory(w http.ResponseWriter, r *http.Request, root string) {
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
		_, err = w.Write([]byte("<li><a href=\"" + filepath.Join(r.URL.Path, entry.Name()) + "\">" + entry.Name() + "</a></li>"))
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

func newFileServer(root string, directoryListing bool) http.Handler {
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
					listDirectory(w, r, root)
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

func serverError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	_, err := w.Write([]byte("<html><body><h2>" + strconv.Itoa(status) + " " + http.StatusText(status) + "</h2><span>Fulgens HTTP Server</span></body></html>"))
	if err != nil {
		slog.Error("Error writing " + strconv.Itoa(status) + ": " + err.Error())
		return
	}
}

func hostRouter(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	router, ok := subdomains[host]
	if !ok {
		router, ok = subdomains["none"]
		if !ok {
			serverError(w, 404)
			slog.Error("No subdomain found for " + host)
		}

	}

	compressionSettings, ok := compression[host]
	if !ok {
		checkCompressionAlgorithm(config.Global.Compression.Algorithm, router).ServeHTTP(w, r)
	} else {
		checkCompressionAlgorithm(compressionSettings.Algorithm, router).ServeHTTP(w, r)
	}
}

var (
	validate           *validator.Validate
	lock               sync.RWMutex
	config             Config
	registeredServices = make(map[string]Service)
	activeServices     = make(map[uuid.UUID]Service)
	certificates       = make(map[string]*tls.Certificate)
	compression        = make(map[string]CompressionSettings)
	subdomains         = make(map[string]*chi.Mux)
)

func loadTLSCertificate(certificatePath, keyPath string) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, err
	} else {
		return &certificate, nil
	}
}

func getTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := certificates[hello.ServerName]
	if !ok {
		return nil, errors.New("no certificate found")
	} else {
		return cert, nil
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
		} else if !ok {
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
		} else {
			// Send error message
			service, ok := activeServices[message.ServiceID]
			if ok {
				service.Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  1,
					SentAt:       time.Now(),
					Message:      errors.New("authentication service not yet available"),
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
		} else if !ok {
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
		} else {
			// Send error message
			service, ok := activeServices[message.ServiceID]
			if ok {
				service.Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  1,
					SentAt:       time.Now(),
					Message:      errors.New("blob storage is not yet available"),
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
		var subdomainRouter *chi.Mux
		// Create the subdomain router
		if route.Compression.Level != 0 {
			compression[route.Subdomain] = CompressionSettings{
				Level:     int(route.Compression.Level),
				Algorithm: route.Compression.Algorithm,
			}
		} else {
			subdomainRouter = chi.NewRouter()
			subdomainRouter.NotFound(func(w http.ResponseWriter, r *http.Request) {
				serverError(w, 404)
			})
		}

		subdomains[route.Subdomain] = subdomainRouter
		subdomains[route.Subdomain].Use(logger)
		subdomains[route.Subdomain].Use(serverChanger)

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
		for _, path := range route.Paths {
			if path.Static.Root != "" {
				// Serve the static directory
				subdomainRouter.Handle(path.Path, http.StripPrefix(strings.TrimSuffix(path.Path, "*"), newFileServer(path.Static.Root, path.Static.DirectoryListing)))
				slog.Info("Serving static directory " + path.Static.Root + " on subdomain " + route.Subdomain + " with pattern " + path.Path)
			} else if path.Proxy.URL != "" {
				// Parse the URL
				proxyUrl, err := url.Parse(path.Proxy.URL)
				if err != nil {
					slog.Error("Error parsing URL: " + err.Error())
					os.Exit(1)
				}
				// Create the proxy
				if path.Proxy.StripPrefix {
					subdomainRouter.Handle(path.Path, http.StripPrefix(strings.TrimSuffix(path.Path, "*"), httputil.NewSingleHostReverseProxy(proxyUrl)))
				} else {
					subdomainRouter.Handle(path.Path, httputil.NewSingleHostReverseProxy(proxyUrl))
				}
			}
		}

		// Add the TLS certificate
		if route.HTTPS.CertificatePath != "" && route.HTTPS.KeyPath != "" {
			certificate, err := loadTLSCertificate(route.HTTPS.CertificatePath, route.HTTPS.KeyPath)
			if err != nil {
				slog.Error("Error loading TLS certificate: " + err.Error())
				os.Exit(1)
			}
			certificates[route.Subdomain] = certificate
		}
	}
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
	err := filepath.Walk(config.Global.ServiceDirectory, func(path string, info os.FileInfo, err error) error {
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

	var globalOutbox = make(chan library.InterServiceMessage, 1)

	// Initialize the service discovery, health-check, and logging services
	// Since these are core services, always allocate them the service IDs 0, 1, and 2
	// These are not dynamically loaded, as they are integral to the system functioning
	go processInterServiceMessage(globalOutbox)

	// Start the storage service
	initializeService(registeredServices["storage"], globalOutbox, nil)

	// Iterate through the subdomains and create the routers as well as the compression levels and service maps
	iterateThroughSubdomains(globalOutbox)

	// Start the server
	slog.Info("Starting server on " + config.Global.IP + " with ports " + config.Global.HTTPPort + " and " + config.Global.HTTPSPort)
	go func() {
		// Create the TLS server
		server := &http.Server{
			Handler: http.HandlerFunc(hostRouter),
			Addr:    config.Global.IP + ":" + config.Global.HTTPSPort,
			TLSConfig: &tls.Config{
				GetCertificate: getTLSCertificate,
			},
		}

		// Start the TLS server
		err = server.ListenAndServeTLS("", "")
		slog.Error("Error starting HTTPS server: " + err.Error())
		os.Exit(1)
	}()

	// Start the HTTP server
	err = http.ListenAndServe(config.Global.IP+":"+config.Global.HTTPPort, http.HandlerFunc(hostRouter))
	slog.Error("Error starting server: " + err.Error())
	os.Exit(1)
}
