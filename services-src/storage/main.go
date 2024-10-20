package main

import (
	"database/sql"
	"errors"
	library "git.ailur.dev/ailur/fg-library/v2"
	nucleusLibrary "git.ailur.dev/ailur/fg-nucleus-library"
	"github.com/go-chi/chi/v5"
	"path/filepath"

	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

var ServiceInformation = library.Service{
	Name: "Storage",
	Permissions: library.Permissions{
		Authenticate:              false, // This service does not require authentication
		Database:                  true,  // This service requires database access to store quotas
		BlobStorage:               false, // This service *is* the blob storage
		InterServiceCommunication: true,  // This service does require inter-service communication
	},
	ServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000003"),
}

var conn library.Database

func getQuota(user uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	// Get the user's quota from the database
	var quota int64
	userBytes, err := user.MarshalBinary()
	if err != nil {
		return 0, err
	}
	err = conn.DB.QueryRow("SELECT quota FROM quotas WHERE id = $1", userBytes).Scan(&quota)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// The user has no quota set, so we'll set it to the default quota
			_, err = conn.DB.Exec("INSERT INTO quotas (id, quota) VALUES ($1, $2)", userBytes, int64(information.Configuration["defaultQuota"].(float64)))
			if err != nil {
				return 0, err
			}
			return int64(information.Configuration["defaultQuota"].(float64)), nil
		}
		return 0, err
	}

	return quota, nil
}

func getUsed(user uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	// Check the user's used space via the filesystem
	var used int64
	_, err := os.Stat(filepath.Join(information.Configuration["path"].(string), user.String()))
	if err != nil {
		if os.IsNotExist(err) {
			// The user has no files stored, so we'll set it to 0
			return 0, nil
		}
		return 0, err
	} else {
		err := filepath.Walk(filepath.Join(information.Configuration["path"].(string), user.String()), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			used += info.Size()
			return nil
		})
		if err != nil {
			return 0, err
		}
		return used, nil
	}
}

func logFunc(message string, messageType uint64, information library.ServiceInitializationInformation) {
	// Log the error message to the logger service
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000002"), // Logger service
		MessageType:  messageType,
		SentAt:       time.Now(),
		Message:      message,
	}
}

func storeFile(file nucleusLibrary.File, serviceID uuid.UUID, information library.ServiceInitializationInformation) {
	// Create a folder for the user if it doesn't exist
	err := os.MkdirAll(filepath.Join(information.Configuration["path"].(string), file.User.String()), 0755)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Check if the user has enough space to store the file
	// Get the user's used space
	used, err := getUsed(file.User, information)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Check if the file already exists
	stats, err := os.Stat(filepath.Join(information.Configuration["path"].(string), file.User.String(), serviceID.String(), file.Name))
	if err == nil {
		// The file already exists, subtract the old file size from the user's used space
		used -= stats.Size()
	}

	// Get the user's quota
	quota, err := getQuota(file.User, information)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Check if the user has enough space to store the file
	if used+int64(len(file.Bytes)) > quota {
		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  3, // It's the user's fault (never say that to the customer ;P)
			SentAt:       time.Now(),
			Message:      "User has exceeded their quota",
		}
	}

	// Create a folder within that for the service if it doesn't exist
	err = os.MkdirAll(filepath.Join(information.Configuration["path"].(string), file.User.String(), serviceID.String()), 0755)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Store the file
	fileStream, err := os.OpenFile(filepath.Join(information.Configuration["path"].(string), file.User.String(), serviceID.String(), file.Name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Write the file
	_, err = fileStream.Write(file.Bytes)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Close the file
	err = fileStream.Close()
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Report success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: serviceID,
		MessageType:  0, // Success
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func readFile(file nucleusLibrary.File, serviceID uuid.UUID, information library.ServiceInitializationInformation) {
	// Open the file
	fileStream, err := os.Open(filepath.Join(information.Configuration["path"].(string), file.User.String(), serviceID.String(), file.Name))
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Return the reader
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: serviceID,
		MessageType:  0, // Success
		SentAt:       time.Now(),
		Message:      fileStream,
	}
}

func removeFile(file nucleusLibrary.File, serviceID uuid.UUID, information library.ServiceInitializationInformation) {
	// Remove the file
	err := os.Remove(filepath.Join(information.Configuration["path"].(string), file.User.String(), serviceID.String(), file.Name))
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    ServiceInformation.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Report success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: serviceID,
		MessageType:  0, // Success
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func Main(information library.ServiceInitializationInformation) *chi.Mux {
	go func() {
		for {
			message := <-information.Inbox
			if message.ServiceID == uuid.MustParse("00000000-0000-0000-0000-000000000001") {
				if message.MessageType == 1 {
					// We've received an error message. This should never happen.
					logFunc("Bit flip error: Error given to non-errored service. Move away from radiation or use ECC memory.", 3, information)
				}
			} else {
				switch message.MessageType {
				case 0:
					// Insert file
					validate := validator.New()
					err := validate.Struct(message.Message.(nucleusLibrary.File))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Store file
						storeFile(message.Message.(nucleusLibrary.File), message.ServiceID, information)
					}
				case 1:
					// Read file
					validate := validator.New()
					err := validate.Struct(message.Message.(nucleusLibrary.File))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Read file
						readFile(message.Message.(nucleusLibrary.File), message.ServiceID, information)
					}
				case 2:
					// Remove file
					validate := validator.New()
					err := validate.Struct(message.Message.(nucleusLibrary.File))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Remove file
						removeFile(message.Message.(nucleusLibrary.File), message.ServiceID, information)
					}
				case 3:
					// Get quota
					validate := validator.New()
					err := validate.Struct(message.Message.(uuid.UUID))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Get quota
						quota, err := getQuota(message.Message.(uuid.UUID), information)
						if err != nil {
							// First contact the logger service
							logFunc(err.Error(), 2, information)

							// Then send the error message to the requesting service
							information.Outbox <- library.InterServiceMessage{
								ServiceID:    ServiceInformation.ServiceID,
								ForServiceID: message.ServiceID,
								MessageType:  1, // An error that's not your fault
								SentAt:       time.Now(),
								Message:      err.Error(),
							}
						}

						// Report success
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  0, // Success
							SentAt:       time.Now(),
							Message:      quota,
						}
					}
				case 4:
					// Get used
					validate := validator.New()
					err := validate.Struct(message.Message.(uuid.UUID))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Get used
						used, err := getUsed(message.Message.(uuid.UUID), information)
						if err != nil {
							// First contact the logger service
							logFunc(err.Error(), 2, information)

							// Then send the error message to the requesting service
							information.Outbox <- library.InterServiceMessage{
								ServiceID:    ServiceInformation.ServiceID,
								ForServiceID: message.ServiceID,
								MessageType:  1, // An error that's not your fault
								SentAt:       time.Now(),
								Message:      err.Error(),
							}
						}

						// Report success
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    ServiceInformation.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  0, // Success
							SentAt:       time.Now(),
							Message:      used,
						}
					}
				}
			}
		}
	}()

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
		// Create the quotas table if it doesn't exist
		if conn.DBType == library.Sqlite {
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS quotas (id BLOB PRIMARY KEY, quota BIGINT)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		} else {
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS quotas (id BYTEA PRIMARY KEY, quota BIGINT)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		}
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	return nil
}
