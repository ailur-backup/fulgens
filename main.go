package main

import (
	library "git.ailur.dev/ailur/fg-library/v2"

	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"plugin"
	"sort"
	"strings"
	"sync"
	"time"

	"compress/gzip"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/andybalholm/brotli"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/hostrouter"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	Global struct {
		IP                 string      `json:"ip" validate:"required,ip_addr"`
		Port               string      `json:"port" validate:"required"`
		ServiceDirectory   string      `json:"serviceDirectory" validate:"required"`
		ResourceDirectory  string      `json:"resourceDirectory" validate:"required"`
		Compression        string      `json:"compression" validate:"omitempty,oneof=gzip brotli zstd"`
		CompressionLevelJN json.Number `json:"compressionLevel" validate:"required_with=Compression"`
		CompressionLevel   int
	} `json:"global" validate:"required"`
	Logging struct {
		Enabled bool   `json:"enabled"`
		File    string `json:"file" validate:"required_if=Enabled true"`
	} `json:"logging"`
	Database struct {
		DatabaseType     string `json:"databaseType" validate:"required,oneof=sqlite postgres"`
		ConnectionString string `json:"connectionString" validate:"required_if=DatabaseType postgres"`
		DatabasePath     string `json:"databasePath" validate:"required_if=DatabaseType sqlite"`
	} `json:"database" validate:"required"`
	Static []struct {
		Subdomain string `json:"subdomain"`
		Directory string `json:"directory" validate:"required,isDirectory"`
		Pattern   string `json:"pattern"`
	} `json:"static"`
	Services map[string]interface{} `json:"services"`
}

type Service struct {
	ServiceID       uuid.UUID
	ServiceMetadata library.Service
	Inbox           chan library.InterServiceMessage
}

type ResponseWriterWrapper struct {
	http.ResponseWriter
	io.Writer
}

func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *ResponseWriterWrapper) Write(p []byte) (int, error) {
	return w.Writer.Write(p)
}

var (
	logger = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			slog.Info(r.Method + " " + r.URL.Path)
		})
	}
	serverChanger = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Fulgens HTTP Server")
			next.ServeHTTP(w, r)
		})
	}
	gzipHandler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				gzipWriter, err := gzip.NewWriterLevel(w, config.Global.CompressionLevel)
				if err != nil {
					slog.Error("Error creating gzip writer: ", err)
					next.ServeHTTP(w, r)
					return
				}
				if w.Header().Get("Content-Encoding") != "" {
					w.Header().Set("Content-Encoding", w.Header().Get("Content-Encoding")+", gzip")
				} else {
					w.Header().Set("Content-Encoding", "gzip")
				}
				defer func() {
					w.Header().Del("Content-Length")
					err := gzipWriter.Close()
					if errors.Is(err, http.ErrBodyNotAllowed) {
						// This is fine, all it means is that they have it cached, and we don't need to send it
						return
					} else if err != nil {
						slog.Error("Error closing gzip writer: ", err)
					}
				}()
				gzipResponseWriter := &ResponseWriterWrapper{ResponseWriter: w, Writer: gzipWriter}
				next.ServeHTTP(gzipResponseWriter, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
	brotliHandler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
				brotliWriter := brotli.NewWriterV2(w, config.Global.CompressionLevel)
				if w.Header().Get("Content-Encoding") != "" {
					w.Header().Set("Content-Encoding", w.Header().Get("Content-Encoding")+", br")
				} else {
					w.Header().Set("Content-Encoding", "br")
				}
				defer func() {
					w.Header().Del("Content-Length")
					err := brotliWriter.Close()
					if errors.Is(err, http.ErrBodyNotAllowed) {
						// This is fine, all it means is that they have it cached, and we don't need to send it
						return
					} else if err != nil {
						slog.Error("Error closing Brotli writer: ", err)
					}
				}()
				brotliResponseWriter := &ResponseWriterWrapper{ResponseWriter: w, Writer: brotliWriter}
				next.ServeHTTP(brotliResponseWriter, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
	zStandardHandler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Accept-Encoding"), "zstd") {
				zStandardWriter, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(config.Global.CompressionLevel)))
				if err != nil {
					slog.Error("Error creating ZStandard writer: ", err)
					next.ServeHTTP(w, r)
					return
				}
				if w.Header().Get("Content-Encoding") != "" {
					w.Header().Set("Content-Encoding", w.Header().Get("Content-Encoding")+", zstd")
				} else {
					w.Header().Set("Content-Encoding", "zstd")
				}
				defer func() {
					w.Header().Del("Content-Length")
					err := zStandardWriter.Close()
					if err != nil {
						if errors.Is(err, http.ErrBodyNotAllowed) {
							// This is fine, all it means is that they have it cached, and we don't need to send it
							return
						} else {
							slog.Error("Error closing ZStandard writer: ", err)
						}
					}
				}()
				gzipResponseWriter := &ResponseWriterWrapper{ResponseWriter: w, Writer: zStandardWriter}
				next.ServeHTTP(gzipResponseWriter, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
	validate   *validator.Validate
	services   = make(map[uuid.UUID]Service)
	lock       sync.RWMutex
	hostRouter = hostrouter.New()
	config     Config
)

func processInterServiceMessage(channel chan library.InterServiceMessage) {
	for {
		message := <-channel
		if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000000") {
			// Broadcast message
			for _, service := range services {
				service.Inbox <- message
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000001") {
			// Service initialization service
			switch message.MessageType {
			case 0:
				// This has been deprecated, ignore it
				// Send "true" back
				services[message.ServiceID].Inbox <- library.InterServiceMessage{
					ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					ForServiceID: message.ServiceID,
					MessageType:  0,
					SentAt:       time.Now(),
					Message:      true,
				}
			case 1:
				// Service database initialization message
				// Check if the service has the necessary permissions
				if services[message.ServiceID].ServiceMetadata.Permissions.Database {
					// Check if we are using sqlite or postgres
					if config.Database.DatabaseType == "sqlite" {
						// Open the database and return the connection
						pluginConn, err := sql.Open("sqlite3", filepath.Join(config.Database.DatabasePath, message.ServiceID.String()+".db"))
						if err != nil {
							// Report an error
							services[message.ServiceID].Inbox <- library.InterServiceMessage{
								ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
								ForServiceID: message.ServiceID,
								MessageType:  1,
								SentAt:       time.Now(),
								Message:      err,
							}
						} else {
							// Report a successful activation
							services[message.ServiceID].Inbox <- library.InterServiceMessage{
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
					} else if config.Database.DatabaseType == "postgres" {
						// Connect to the database
						conn, err := sql.Open("postgres", config.Database.ConnectionString)
						if err != nil {
							// Report an error
							services[message.ServiceID].Inbox <- library.InterServiceMessage{
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
								services[message.ServiceID].Inbox <- library.InterServiceMessage{
									ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
									ForServiceID: message.ServiceID,
									MessageType:  1,
									SentAt:       time.Now(),
									Message:      err,
								}
							} else {
								// Create a new connection to the database
								var connectionString string
								if strings.Contains(config.Database.ConnectionString, "?") {
									connectionString = config.Database.ConnectionString + "&search_path=\"" + message.ServiceID.String() + "\""
								} else {
									connectionString = config.Database.ConnectionString + "?search_path=\"" + message.ServiceID.String() + "\""
								}
								pluginConn, err := sql.Open("postgres", connectionString)
								if err != nil {
									// Report an error
									services[message.ServiceID].Inbox <- library.InterServiceMessage{
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
										services[message.ServiceID].Inbox <- library.InterServiceMessage{
											ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
											ForServiceID: message.ServiceID,
											MessageType:  1,
											SentAt:       time.Now(),
											Message:      err,
										}
									} else {
										// Report a successful activation
										services[message.ServiceID].Inbox <- library.InterServiceMessage{
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
					services[message.ServiceID].Inbox <- library.InterServiceMessage{
						ServiceID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
						ForServiceID: message.ServiceID,
						MessageType:  1,
						SentAt:       time.Now(),
						Message:      errors.New("database access not permitted"),
					}
				}
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000002") {
			// Logger service
			service, ok := services[message.ServiceID]
			if ok {
				switch message.MessageType {
				case 0:
					// Log message
					slog.Info(service.ServiceMetadata.Name + " says: " + message.Message.(string))
				case 1:
					// Warn message
					slog.Warn(service.ServiceMetadata.Name + " warns: " + message.Message.(string))
				case 2:
					// Error message
					slog.Error(service.ServiceMetadata.Name + " complains: " + message.Message.(string))
				case 3:
					// Fatal message
					slog.Error(service.ServiceMetadata.Name + "'s dying wish: " + message.Message.(string))
					os.Exit(1)
				}
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000003") {
			// We need to check if the service is allowed to access the Blob Storage service
			serviceMetadata, ok := services[message.ServiceID]
			if ok && serviceMetadata.ServiceMetadata.Permissions.BlobStorage {
				// Send message to Blob Storage service
				service, ok := services[uuid.MustParse("00000000-0000-0000-0000-000000000003")]
				if ok {
					service.Inbox <- message
				} else if !ok {
					// Send error message
					service, ok := services[message.ServiceID]
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
					service, ok := services[message.ServiceID]
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
				service, ok := services[message.ServiceID]
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
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000004") {
			// We need to check if the service is allowed to access the Authentication service
			serviceMetadata, ok := services[message.ServiceID]
			if ok && serviceMetadata.ServiceMetadata.Permissions.Authenticate {
				// Send message to Authentication service
				service, ok := services[uuid.MustParse("00000000-0000-0000-0000-000000000004")]
				if ok {
					service.Inbox <- message
				} else if !ok {
					// Send error message
					service, ok := services[message.ServiceID]
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
					service, ok := services[message.ServiceID]
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
				service, ok := services[message.ServiceID]
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
		} else {
			serviceMetadata, ok := services[message.ServiceID]
			if ok && serviceMetadata.ServiceMetadata.Permissions.InterServiceCommunication {
				// Send message to specific service
				service, ok := services[message.ForServiceID]
				if !ok {
					// Send error message
					service, ok := services[message.ServiceID]
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
				service, ok := services[message.ServiceID]
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
		slog.Error("Error registering custom validator: ", err)
		os.Exit(1)
	}

	// Parse the configuration file
	configFile, err := os.Open(path)
	if err != nil {
		slog.Error("Error reading configuration file: ", err)
		os.Exit(1)
	}

	// Parse the configuration file
	var config Config
	decoder := json.NewDecoder(configFile)
	decoder.UseNumber()
	err = decoder.Decode(&config)
	if err != nil {
		slog.Error("Error parsing configuration file: ", err)
		os.Exit(1)
	}

	// Set the compression level
	if config.Global.Compression != "" {
		compressionLevelI64, err := config.Global.CompressionLevelJN.Int64()
		if err != nil {
			slog.Error("Error parsing compression level: ", err)
			os.Exit(1)
		}
		config.Global.CompressionLevel = int(compressionLevelI64)
	}

	// Validate the configuration
	err = validate.Struct(config)
	if err != nil {
		slog.Error("Invalid configuration: ", err)
		os.Exit(1)
	}

	// Check if we are logging to a file
	if config.Logging != (Config{}.Logging) && config.Logging.Enabled {
		// Check if the log file is set
		logFilePath := config.Logging.File

		// Set the log file
		logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			slog.Error("Error opening log file: ", err)
			os.Exit(1)
		}

		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	}

	return config
}

func main() {
	// Parse the configuration file
	if len(os.Args) < 2 {
		info, err := os.Stat("config.json")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				slog.Error("No configuration file provided")
				os.Exit(1)
			} else {
				slog.Error("Error reading configuration file: ", err)
				os.Exit(1)
			}
		}

		if info.IsDir() {
			slog.Error("No configuration file provided")
			os.Exit(1)
		}

		config = parseConfig("config.json")
	} else {
		config = parseConfig(os.Args[1])
	}

	// If we are using sqlite, create the database directory if it does not exist
	if config.Database.DatabaseType == "sqlite" {
		err := os.MkdirAll(config.Database.DatabasePath, 0755)
		if err != nil {
			slog.Error("Error creating database directory: ", err)
			os.Exit(1)
		}
	}

	// Create the router
	router := chi.NewRouter()
	router.Use(logger)
	router.Use(serverChanger)

	// Iterate through the service configurations and create routers for each unique subdomain
	subdomains := make(map[string]*chi.Mux)
	for _, service := range config.Services {
		if service.(map[string]interface{})["subdomain"] != nil {
			subdomain := service.(map[string]interface{})["subdomain"].(string)
			if subdomains[subdomain] == nil {
				subdomains[subdomain] = chi.NewRouter()
				slog.Info("Mapping subdomain " + subdomain)
				hostRouter.Map(subdomain, subdomains[subdomain])
			}
		}
	}

	// Iterate through the static configurations and create routers for each unique subdomain
	for _, static := range config.Static {
		// Check if it wants a subdomain
		if static.Subdomain != "" {
			// Check if the subdomain exists
			if subdomains[static.Subdomain] == nil {
				subdomains[static.Subdomain] = chi.NewRouter()
				slog.Info("Mapping subdomain " + static.Subdomain)
				hostRouter.Map(static.Subdomain, subdomains[static.Subdomain])
			}
		}
	}

	var globalOutbox = make(chan library.InterServiceMessage)

	// Initialize the service discovery, health-check, and logging services
	// Since these are core services, always allocate them the service IDs 0, 1, and 2
	// These are not dynamically loaded, as they are integral to the system functioning
	go processInterServiceMessage(globalOutbox)

	// Initialize all the services
	plugins := make(map[time.Time]string)
	err := filepath.Walk(config.Global.ServiceDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".fgs" {
			return nil
		}

		// Add the plugin to the list of plugins
		if info.Name() == "storage.fgs" {
			plugins[time.Unix(0, 0)] = path
			return nil
		} else if info.Name() == "auth.fgs" {
			plugins[time.Unix(0, 1)] = path
			return nil
		}

		plugins[info.ModTime()] = path

		return nil
	})
	if err != nil {
		slog.Error("Error walking the services directory: ", err)
		os.Exit(1)
	}

	// Sort the plugins by modification time, newest last
	var keys []time.Time
	for k := range plugins {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Before(keys[j])
	})

	for _, k := range keys {
		// Get the plugin path
		pluginPath := plugins[k]

		// Load the plugin
		servicePlugin, err := plugin.Open(pluginPath)
		if err != nil {
			slog.Error("Could not load service: ", err)
			os.Exit(1)
		}

		// Load the service information
		serviceInformationSymbol, err := servicePlugin.Lookup("ServiceInformation")
		if err != nil {
			slog.Error("Service lacks necessary information: ", err)
			os.Exit(1)
		}

		serviceInformation := *serviceInformationSymbol.(*library.Service)

		// Load the main function
		main, err := servicePlugin.Lookup("Main")
		if err != nil {
			slog.Error("Service lacks necessary main function: ", err)
			os.Exit(1)
		}

		// Initialize the service
		var inbox = make(chan library.InterServiceMessage)
		lock.Lock()
		services[serviceInformation.ServiceID] = Service{
			ServiceID:       serviceInformation.ServiceID,
			Inbox:           inbox,
			ServiceMetadata: serviceInformation,
		}
		lock.Unlock()

		slog.Info("Activating service " + serviceInformation.Name + " with ID " + serviceInformation.ServiceID.String())

		// Make finalRouter a subdomain router if necessary
		var finalRouter *chi.Mux
		if config.Services[strings.ToLower(serviceInformation.Name)].(map[string]interface{})["subdomain"] != nil {
			finalRouter = subdomains[config.Services[strings.ToLower(serviceInformation.Name)].(map[string]interface{})["subdomain"].(string)]
		} else {
			finalRouter = router
		}

		// Check if they want a resource directory
		var resourceDir fs.FS = nil
		if serviceInformation.Permissions.Resources {
			resourceDir = os.DirFS(filepath.Join(config.Global.ResourceDirectory, serviceInformation.ServiceID.String()))
		}

		main.(func(library.ServiceInitializationInformation))(library.ServiceInitializationInformation{
			Domain:        serviceInformation.Name,
			Configuration: config.Services[strings.ToLower(serviceInformation.Name)].(map[string]interface{}),
			Outbox:        globalOutbox,
			Inbox:         inbox,
			ResourceDir:   resourceDir,
			Router:        finalRouter,
		})

		// Log the service activation
		slog.Info("Service " + serviceInformation.Name + " activated with ID " + serviceInformation.ServiceID.String())
	}

	// Mount the host router
	router.Mount("/", hostRouter)
	slog.Info("All subdomains mapped")

	// Initialize the static file servers
	for _, static := range config.Static {
		if static.Subdomain != "" {
			// Serve the static directory
			if static.Pattern != "" {
				subdomains[static.Subdomain].Handle(static.Pattern, http.FileServerFS(os.DirFS(static.Directory)))
				slog.Info("Serving static directory " + static.Directory + " on subdomain " + static.Subdomain + " with pattern " + static.Pattern)
			} else {
				subdomains[static.Subdomain].Handle("/*", http.FileServerFS(os.DirFS(static.Directory)))
				slog.Info("Serving static directory " + static.Directory + " on subdomain " + static.Subdomain)
			}
		} else {
			// Serve the static directory
			if static.Pattern != "" {
				router.Handle(static.Pattern, http.FileServerFS(os.DirFS(static.Directory)))
				slog.Info("Serving static directory " + static.Directory + " with pattern " + static.Pattern)
			} else {
				router.Handle("/*", http.FileServerFS(os.DirFS(static.Directory)))
				slog.Info("Serving static directory " + static.Directory)
			}
		}
	}

	// Start the server
	slog.Info("Starting server on " + config.Global.IP + ":" + config.Global.Port)
	switch config.Global.Compression {
	case "":
		err = http.ListenAndServe(config.Global.IP+":"+config.Global.Port, router)
	case "gzip":
		slog.Info("GZip compression enabled")
		err = http.ListenAndServe(config.Global.IP+":"+config.Global.Port, gzipHandler(router))
	case "brotli":
		slog.Info("Brotli compression enabled")
		err = http.ListenAndServe(config.Global.IP+":"+config.Global.Port, brotliHandler(router))
	case "zstd":
		slog.Info("ZStandard compression enabled")
		err = http.ListenAndServe(config.Global.IP+":"+config.Global.Port, zStandardHandler(router))
	}
	if err != nil {
		slog.Error("Error starting server: ", err)
		os.Exit(1)
	}
}
