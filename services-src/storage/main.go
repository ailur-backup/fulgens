package main

import (
	"database/sql"
	"git.ailur.dev/ailur/fulgens/library"
	"path/filepath"

	"io"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type InsertFile struct {
	File   File      `validate:"required"`
	Stream io.Reader `validate:"required"`
}

type ReadFile struct {
	File   File      `validate:"required"`
	Stream io.Writer `validate:"required"`
}

type File struct {
	Name string    `validate:"required"`
	Size int64     `validate:"required"`
	User uuid.UUID `validate:"required"`
}

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

var conn *sql.DB

func getQuota(user uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	// Get the user's quota from the database
	var quota int64
	err := conn.QueryRow("SELECT quota FROM quotas WHERE id = $1", user).Scan(&quota)
	if err != nil {
		return 0, err
	}

	return quota, nil
}

func getUsed(user uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	// Check the user's used space via the filesystem
	var used int64
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

func logFunc(message string, messageType uint64, information library.ServiceInitializationInformation) {
	// Log the error message to the logger service
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    information.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000002"), // Logger service
		MessageType:  messageType,
		SentAt:       time.Now(),
		Message:      message,
	}
}

func storeFile(file InsertFile, serviceID uuid.UUID, information library.ServiceInitializationInformation) {
	// Create a folder for the user if it doesn't exist
	err := os.MkdirAll(filepath.Join(information.Configuration["path"].(string), file.File.User.String()), 0755)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Check if the user has enough space to store the file
	quota, err := getQuota(file.File.User, information)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	used, err := getUsed(file.File.User, information)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Check if the user has enough space to store the file
	if used+file.File.Size > quota {
		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  3, // It's the user's fault (never say that to the customer ;P)
			SentAt:       time.Now(),
			Message:      "User has exceeded their quota",
		}
	}

	// Create a folder within that for the service if it doesn't exist
	err = os.MkdirAll(filepath.Join(information.Configuration["path"].(string), file.File.User.String(), serviceID.String()), 0755)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Store the file
	fileStream, err := os.OpenFile(filepath.Join(information.Configuration["path"].(string), file.File.User.String(), serviceID.String(), file.File.Name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Write the file
	_, err = io.Copy(fileStream, file.Stream)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
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
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Report success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    information.ServiceID,
		ForServiceID: serviceID,
		MessageType:  0, // Success
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func readFile(file ReadFile, serviceID uuid.UUID, information library.ServiceInitializationInformation) {
	// Open the file
	fileStream, err := os.Open(filepath.Join(information.Configuration["path"].(string), file.File.User.String(), serviceID.String(), file.File.Name))
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Read the file
	_, err = io.Copy(file.Stream, fileStream)
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
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
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Report success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    information.ServiceID,
		ForServiceID: serviceID,
		MessageType:  0, // Success
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func removeFile(file File, serviceID uuid.UUID, information library.ServiceInitializationInformation) {
	// Remove the file
	err := os.Remove(filepath.Join(information.Configuration["path"].(string), file.User.String(), serviceID.String(), file.Name))
	if err != nil {
		// First contact the logger service
		logFunc(err.Error(), 2, information)

		// Then send the error message to the requesting service
		information.Outbox <- library.InterServiceMessage{
			ServiceID:    information.ServiceID,
			ForServiceID: serviceID,
			MessageType:  1, // An error that's not your fault
			SentAt:       time.Now(),
			Message:      err.Error(),
		}
	}

	// Report success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    information.ServiceID,
		ForServiceID: serviceID,
		MessageType:  0, // Success
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func Main(information library.ServiceInitializationInformation) {
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
					err := validate.Struct(message.Message.(InsertFile))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    information.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Store file
						storeFile(message.Message.(InsertFile), message.ServiceID, information)
					}
				case 1:
					// Read file
					validate := validator.New()
					err := validate.Struct(message.Message.(ReadFile))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    information.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Read file
						readFile(message.Message.(ReadFile), message.ServiceID, information)
					}
				case 2:
					// Remove file
					validate := validator.New()
					err := validate.Struct(message.Message.(File))
					if err != nil {
						information.Outbox <- library.InterServiceMessage{
							ServiceID:    information.ServiceID,
							ForServiceID: message.ServiceID,
							MessageType:  2, // An error that's your fault
							SentAt:       time.Now(),
							Message:      err.Error(),
						}
					} else {
						// Remove file
						removeFile(message.Message.(File), message.ServiceID, information)
					}
				}
			}
		}
	}()

	// Report a successful activation
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    information.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), // Activation service
		MessageType:  0,
		SentAt:       time.Now(),
		Message:      true,
	}
}
