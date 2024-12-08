package main

import (
	"bytes"
	library "git.ailur.dev/ailur/fg-library/v2"
	nucleusLibrary "git.ailur.dev/ailur/fg-nucleus-library"

	"errors"
	"os"
	"time"

	"database/sql"
	"path/filepath"

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

func respondError(message string, information library.ServiceInitializationInformation, myFault bool, serviceID uuid.UUID) {
	// Respond with an error message
	var err uint64 = 1
	if myFault {
		// Log the error message to the logger service
		logFunc(message, 2, information)
		err = 2
	}
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: serviceID,
		MessageType:  err,
		SentAt:       time.Now(),
		Message:      errors.New(message),
	}
}

func checkUserExists(userID uuid.UUID) bool {
	// Check if a user exists in the database
	var userCheck []byte
	err := conn.DB.QueryRow("SELECT id FROM users WHERE id = $1", userID[:]).Scan(&userCheck)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		} else {
			return false
		}
	} else {
		return bytes.Equal(userCheck, userID[:])
	}
}

// addQuota can be used with a negative quota to remove quota from a user
func addQuota(information library.ServiceInitializationInformation, message library.InterServiceMessage) {
	// Add more quota to a user
	userID := message.Message.(nucleusLibrary.Quota).User
	if checkUserExists(userID) {
		_, err := conn.DB.Exec("UPDATE users SET quota = quota + $1 WHERE id = $2", message.Message.(nucleusLibrary.Quota).Bytes, message.Message.(nucleusLibrary.Quota).User)
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
	} else {
		_, err := conn.DB.Exec("INSERT INTO users (id, quota, reserved) VALUES ($1, $2, 0)", userID[:], int64(information.Configuration["defaultQuota"].(int))+message.Message.(nucleusLibrary.Quota).Bytes)
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
	}

	// Success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: message.ServiceID,
		MessageType:  0,
		SentAt:       time.Now(),
		Message:      nil,
	}
}

// And so does addReserved
func addReserved(information library.ServiceInitializationInformation, message library.InterServiceMessage) {
	// Add more reserved space to a user
	userID := message.Message.(nucleusLibrary.Quota).User
	if checkUserExists(userID) {
		// Check if the user has enough space
		quota, err := getQuota(userID)
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
		used, err := getUsed(userID, information)
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
		if used+message.Message.(nucleusLibrary.Quota).Bytes > quota {
			respondError("insufficient storage", information, false, message.ServiceID)
			return
		}
		_, err = conn.DB.Exec("UPDATE users SET reserved = reserved + $1 WHERE id = $2", message.Message.(nucleusLibrary.Quota).Bytes, userID[:])
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
	} else {
		// Check if the user has enough space
		if int64(information.Configuration["defaultQuota"].(int)) < message.Message.(nucleusLibrary.Quota).Bytes {
			respondError("insufficient storage", information, false, message.ServiceID)
			return
		}
		_, err := conn.DB.Exec("INSERT INTO users (id, quota, reserved) VALUES ($1, $2, $3)", userID[:], int64(information.Configuration["defaultQuota"].(int)), message.Message.(nucleusLibrary.Quota).Bytes)
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
	}

	// Success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: message.ServiceID,
		MessageType:  0,
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func getQuota(userID uuid.UUID) (int64, error) {
	// Get the quota for a user
	var quota int64
	err := conn.DB.QueryRow("SELECT quota FROM users WHERE id = $1", userID[:]).Scan(&quota)
	if err != nil {
		return 0, err
	}
	return quota, nil
}

func getUsed(userID uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	// Get the used space for a user by first getting the reserved space from file storage
	_, err := os.Stat(filepath.Join(information.Configuration["path"].(string), userID.String()))
	if os.IsNotExist(err) {
		// Create the directory
		err = os.Mkdir(filepath.Join(information.Configuration["path"].(string), userID.String()), 0755)
		if err != nil {
			return 0, err
		}
	}

	var used int64
	err = filepath.Walk(filepath.Join(information.Configuration["path"].(string), userID.String()), func(path string, entry os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		used += entry.Size()

		return nil
	})
	if err != nil {
		return 0, err
	}

	// Then add the reserved space from the database
	var reserved int64
	err = conn.DB.QueryRow("SELECT reserved FROM users WHERE id = $1", userID[:]).Scan(&reserved)
	if err != nil {
		return 0, err
	}

	return used + reserved, nil
}

func modifyFile(information library.ServiceInitializationInformation, message library.InterServiceMessage) {
	// Check if the file already exists
	path := filepath.Join(information.Configuration["path"].(string), message.Message.(nucleusLibrary.File).User.String(), message.Message.(nucleusLibrary.File).Name)

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		// Delete the file
		err = os.Remove(path)
		if err != nil {
			respondError(err.Error(), information, true, message.ServiceID)
		}
	}

	// Check if the user has enough space
	quota, err := getQuota(message.Message.(nucleusLibrary.File).User)
	if err != nil {
		respondError(err.Error(), information, true, message.ServiceID)
	}
	used, err := getUsed(message.Message.(nucleusLibrary.File).User, information)
	if err != nil {
		respondError(err.Error(), information, true, message.ServiceID)
	}
	if used+int64(len(message.Message.(nucleusLibrary.File).Bytes)) > quota {
		respondError("insufficient storage", information, false, message.ServiceID)
		return
	}

	// Add a file to the user's storage
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		respondError(err.Error(), information, true, message.ServiceID)
	}

	// Write the file
	_, err = file.Write(message.Message.(nucleusLibrary.File).Bytes)
	if err != nil {
		respondError(err.Error(), information, true, message.ServiceID)
	}

	// Close the file
	err = file.Close()
	if err != nil {
		respondError(err.Error(), information, true, message.ServiceID)
	}

	// Success
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: message.ServiceID,
		MessageType:  0,
		SentAt:       time.Now(),
		Message:      nil,
	}
}

func getFile(information library.ServiceInitializationInformation, message library.InterServiceMessage) {
	// Check if the file exists
	path := filepath.Join(information.Configuration["path"].(string), message.Message.(nucleusLibrary.File).User.String(), message.Message.(nucleusLibrary.File).Name)

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		respondError("file not found", information, false, message.ServiceID)
		return
	}

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		respondError(err.Error(), information, true, message.ServiceID)
	}

	// Respond with the file
	// It's their responsibility to close the file
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: message.ServiceID,
		MessageType:  0,
		SentAt:       time.Now(),
		Message:      file,
	}
}

// processInterServiceMessages listens for incoming messages and processes them
func processInterServiceMessages(information library.ServiceInitializationInformation) {
	// Listen for incoming messages
	for {
		message := <-information.Inbox
		switch message.MessageType {
		case 1:
			// Add quota
			addQuota(information, message)
		case 2:
			// Add reserved
			addReserved(information, message)
		case 3:
			// Modify file
			modifyFile(information, message)
		case 4:
			// Get file
			getFile(information, message)
		default:
			// Respond with an error message
			respondError("invalid message type", information, false, message.ServiceID)
		}
	}
}

func Main(information library.ServiceInitializationInformation) {
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
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BLOB PRIMARY KEY, quota BIGINT, reserved BIGINT)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		} else {
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BYTEA PRIMARY KEY, quota BIGINT, reserved BIGINT)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		}
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Listen for incoming messages
	go processInterServiceMessages(information)
}
