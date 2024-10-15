package main

import (
	"errors"
	library "git.ailur.dev/ailur/fg-library"
	"io"
	"log"
	"os"
	"plugin"
	"sort"
	"strings"
	"sync"
	"time"

	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/hostrouter"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type Config struct {
	Global struct {
		IP                string `json:"ip" validate:"required,ip_addr"`
		Port              string `json:"port" validate:"required"`
		ServiceDirectory  string `json:"serviceDirectory" validate:"required"`
		ResourceDirectory string `json:"resourceDirectory" validate:"required"`
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
	Services map[string]interface{} `json:"services"`
}

type Service struct {
	ServiceID           uuid.UUID
	ServiceMetadata     library.Service
	Inbox               chan library.InterServiceMessage
	ActivationConfirmed bool
}

var (
	logger = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			slog.Info(r.Method + " " + r.URL.Path)
		})
	}
	validate *validator.Validate
	services = make(map[uuid.UUID]Service)
	lock     sync.RWMutex
)

func processInterServiceMessage(channel chan library.InterServiceMessage, config Config) {
	for {
		message := <-channel
		if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000000") {
			// Broadcast message
			for _, service := range services {
				// We don't want to overwhelm a non-activated service
				if service.ActivationConfirmed {
					service.Inbox <- message
				}
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000001") {
			// Service initialization service
			switch message.MessageType {
			case 0:
				// Service initialization message, register the service
				lock.Lock()
				inbox := services[message.ServiceID].Inbox
				services[message.ServiceID] = Service{
					ServiceID:           message.ServiceID,
					Inbox:               inbox,
					ActivationConfirmed: true,
					ServiceMetadata:     services[message.ServiceID].ServiceMetadata,
				}
				lock.Unlock()
				// Report a successful activation
				inbox <- library.InterServiceMessage{
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
						pluginConn, err := sql.Open("sqlite", filepath.Join(config.Database.DatabasePath, message.ServiceID.String()+".db"))
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
				if ok && service.ActivationConfirmed {
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
				if ok && service.ActivationConfirmed {
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
	configFile, err := os.ReadFile(path)
	if err != nil {
		slog.Error("Error reading configuration file: ", err)
		os.Exit(1)
	}

	// Parse the configuration file
	var config Config
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		slog.Error("Error parsing configuration file: ", err)
		os.Exit(1)
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
	var config Config
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

	// Create the router
	router := chi.NewRouter()
	router.Use(logger)
	hostRouter := hostrouter.New()

	var globalOutbox = make(chan library.InterServiceMessage)

	// Initialize the service discovery, health-check, and logging services
	// Since these are core services, always allocate them the service IDs 0, 1, and 2
	// These are not dynamically loaded, as they are integral to the system functioning
	go processInterServiceMessage(globalOutbox, config)

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
			ServiceID:           serviceInformation.ServiceID,
			Inbox:               inbox,
			ActivationConfirmed: false,
			ServiceMetadata:     serviceInformation,
		}
		lock.Unlock()

		// Check if they want a subdomain
		finalRouter := chi.NewRouter()
		serviceConfig, ok := config.Services[strings.ToLower(serviceInformation.Name)]
		if !ok {
			slog.Error("Service configuration not found for service: ", serviceInformation.Name)
			os.Exit(1)
		}
		if serviceConfig.(map[string]interface{})["subdomain"] != nil {
			hostRouter.Map(serviceConfig.(map[string]interface{})["subdomain"].(string), finalRouter)
		} else {
			hostRouter.Map("", finalRouter)
		}

		slog.Info("Activating service " + serviceInformation.Name + " with ID " + serviceInformation.ServiceID.String())

		// Check if they want a resource directory
		if serviceInformation.Permissions.Resources {
			main.(func(library.ServiceInitializationInformation))(library.ServiceInitializationInformation{
				Domain:        serviceInformation.Name,
				Configuration: config.Services[strings.ToLower(serviceInformation.Name)].(map[string]interface{}),
				Outbox:        globalOutbox,
				Inbox:         inbox,
				ResourceDir:   os.DirFS(filepath.Join(config.Global.ResourceDirectory, serviceInformation.ServiceID.String())),
				Router:        finalRouter,
			})
		} else {
			main.(func(library.ServiceInitializationInformation))(library.ServiceInitializationInformation{
				Domain:        serviceInformation.Name,
				Configuration: config.Services[strings.ToLower(serviceInformation.Name)].(map[string]interface{}),
				Outbox:        globalOutbox,
				Inbox:         inbox,
				Router:        finalRouter,
			})
		}

		// Log the service activation
		slog.Info("Service " + serviceInformation.Name + " activated with ID " + serviceInformation.ServiceID.String())
	}

	// Start the server
	slog.Info("Starting server on " + config.Global.IP + ":" + config.Global.Port)
	err = http.ListenAndServe(config.Global.IP+":"+config.Global.Port, router)
	if err != nil {
		slog.Error("Error starting server: ", err)
		os.Exit(1)
	}
}
