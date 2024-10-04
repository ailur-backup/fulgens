package main

import (
	"errors"
	"fmt"
	library "git.ailur.dev/ailur/fg-library"
	"github.com/go-chi/chi/v5/middleware"
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
		DatabasePath     string `json:"databasePath" validate:"required_if=DatabaseType sqlite,isDirectory"`
	} `json:"database" validate:"required"`
	Services map[string]interface{} `json:"services"`
}

type ActiveService struct {
	ServiceID           uuid.UUID
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
	validate       *validator.Validate
	activeServices = make(map[uuid.UUID]ActiveService)
	services       = make(map[uuid.UUID]library.Service)
	lock           sync.RWMutex
)

func processInterServiceMessage(channel chan library.InterServiceMessage, config Config) {
	for {
		message := <-channel
		if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000000") {
			// Broadcast message
			for _, service := range activeServices {
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
				inbox := activeServices[message.ServiceID].Inbox
				activeServices[message.ServiceID] = ActiveService{
					ServiceID:           message.ServiceID,
					Inbox:               inbox,
					ActivationConfirmed: true,
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
				if services[message.ServiceID].Permissions.Database {
					// Check if we are using sqlite or postgres
					if config.Database.DatabaseType == "sqlite" {
						// Open the database and return the connection
						pluginConn, err := sql.Open("sqlite", filepath.Join(config.Database.DatabasePath, message.ServiceID.String()+".db"))
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
								Message:      pluginConn,
							}
						}
					} else if config.Database.DatabaseType == "postgres" {
						// Connect to the database
						conn, err := sql.Open("postgres", config.Database.ConnectionString)
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
							_, err = conn.Exec("CREATE SCHEMA IF NOT EXISTS " + message.ServiceID.String())
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
								pluginConn, err := sql.Open("postgres", config.Database.ConnectionString+" dbname="+message.ServiceID.String())
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
									// Try to switch schemas
									_, err = pluginConn.Exec("SET search_path TO " + message.ServiceID.String())
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
											Message:      pluginConn,
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
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000002") {
			// Logger service
			service, ok := services[message.ServiceID]
			if ok {
				switch message.MessageType {
				case 0:
					// Log message
					slog.Info(service.Name + " says: " + message.Message.(string))
				case 1:
					// Warn message
					slog.Warn(service.Name + " warns: " + message.Message.(string))
				case 2:
					// Error message
					slog.Error(service.Name + " complains: " + message.Message.(string))
				case 3:
					// Fatal message
					slog.Error(service.Name + "'s dying wish: " + message.Message.(string))
					os.Exit(1)
				}
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000003") {
			// We need to check if the service is allowed to access the Blob Storage service
			serviceMetadata, ok := services[message.ServiceID]
			if ok && serviceMetadata.Permissions.BlobStorage {
				// Send message to Blob Storage service
				service, ok := activeServices[uuid.MustParse("00000000-0000-0000-0000-000000000003")]
				if ok && service.ActivationConfirmed {
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
					fmt.Println(message.ServiceID, message.ForServiceID)
					os.Exit(1)
				}
			}
		} else if message.ForServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000004") {
			// We need to check if the service is allowed to access the Authentication service
			serviceMetadata, ok := services[message.ServiceID]
			if ok && serviceMetadata.Permissions.Authenticate {
				// Send message to Authentication service
				service, ok := activeServices[uuid.MustParse("00000000-0000-0000-0000-000000000004")]
				if ok && service.ActivationConfirmed {
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
		} else {
			serviceMetadata, ok := services[message.ServiceID]
			if ok && serviceMetadata.Permissions.InterServiceCommunication {
				// Send message to specific service
				service, ok := activeServices[message.ForServiceID]
				if ok && service.ActivationConfirmed {
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
							Message:      errors.New("requested service not found"),
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
							Message:      errors.New("requested service not yet available"),
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
		slog.Error(fmt.Sprintf("Invalid configuration: \n%s", err))
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
		serviceInformation, err := servicePlugin.Lookup("ServiceInformation")
		if err != nil {
			slog.Error("Service lacks necessary information: ", err)
			os.Exit(1)
		}

		// Load the main function
		main, err := servicePlugin.Lookup("Main")
		if err != nil {
			slog.Error("Service lacks necessary main function: ", err)
			os.Exit(1)
		}

		// Add the service to the services map
		lock.Lock()
		services[serviceInformation.(*library.Service).ServiceID] = *serviceInformation.(*library.Service)
		lock.Unlock()

		// Initialize the service
		var inbox = make(chan library.InterServiceMessage)
		lock.Lock()
		activeServices[serviceInformation.(*library.Service).ServiceID] = ActiveService{
			ServiceID:           serviceInformation.(*library.Service).ServiceID,
			Inbox:               inbox,
			ActivationConfirmed: false,
		}
		lock.Unlock()

		// Check if they want a subdomain
		var finalRouter *chi.Mux
		serviceConfig, ok := config.Services[strings.ToLower(serviceInformation.(*library.Service).Name)]
		if !ok {
			slog.Error("Service configuration not found for service: ", serviceInformation.(*library.Service).Name)
			os.Exit(1)
		}
		if serviceConfig.(map[string]interface{})["subdomain"] != nil {
			subdomainRouter := chi.NewRouter()
			router.Use(middleware.RouteHeaders().
				Route("Host", config.Services[strings.ToLower(serviceInformation.(*library.Service).Name)].(map[string]interface{})["subdomain"].(string), middleware.New(subdomainRouter)).
				Handler)
			finalRouter = subdomainRouter
		} else {
			finalRouter = router
		}

		slog.Info("Activating service " + serviceInformation.(*library.Service).Name + " with ID " + serviceInformation.(*library.Service).ServiceID.String())

		// Check if they want a resource directory
		if serviceInformation.(*library.Service).Permissions.Resources {
			main.(func(library.ServiceInitializationInformation))(library.ServiceInitializationInformation{
				Domain:        serviceInformation.(*library.Service).Name,
				Configuration: config.Services[strings.ToLower(serviceInformation.(*library.Service).Name)].(map[string]interface{}),
				Outbox:        globalOutbox,
				Inbox:         inbox,
				ResourceDir:   os.DirFS(filepath.Join(config.Global.ResourceDirectory, serviceInformation.(*library.Service).ServiceID.String())),
				Router:        finalRouter,
			})
		} else {
			main.(func(library.ServiceInitializationInformation))(library.ServiceInitializationInformation{
				Domain:        serviceInformation.(*library.Service).Name,
				Configuration: config.Services[strings.ToLower(serviceInformation.(*library.Service).Name)].(map[string]interface{}),
				Outbox:        globalOutbox,
				Inbox:         inbox,
				Router:        finalRouter,
			})
		}

		// Log the service activation
		slog.Info("Service " + serviceInformation.(*library.Service).Name + " activated with ID " + serviceInformation.(*library.Service).ServiceID.String())
	}

	// Start the server
	slog.Info(fmt.Sprintf("Starting server on %s:%s", config.Global.IP, config.Global.Port))
	err = http.ListenAndServe(config.Global.IP+":"+config.Global.Port, router)
	if err != nil {
		slog.Error("Error starting server: ", err)
		os.Exit(1)
	}
}
