package main

import (
	library "git.ailur.dev/ailur/fg-library/v3"
	nucleusLibrary "git.ailur.dev/ailur/fg-nucleus-library"
	"io"

	"bytes"
	"os"

	"database/sql"
	"errors"
	"path/filepath"

	"github.com/google/uuid"
)

var ServiceInformation = library.Service{
	Name: "Storage",
	Permissions: library.Permissions{
		Authenticate:              false, // This service does not require authentication
		Router:                    false, // This service does not serve web pages
		Database:                  true,  // This service requires database access to store quotas
		BlobStorage:               false, // This service *is* the blob storage
		InterServiceCommunication: true,  // This service does require inter-service communication
		Resources:                 false, // This service does not require access to its resource directory
	},
	ServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000003"),
}

var (
	loggerService = uuid.MustParse("00000000-0000-0000-0000-000000000002")
)

func logFunc(message string, messageType library.MessageCode, information *library.ServiceInitializationInformation) {
	// Log the message to the logger service
	information.SendISMessage(loggerService, messageType, message)
}

func respondError(message library.InterServiceMessage, err error, information *library.ServiceInitializationInformation, myFault bool) {
	// Respond with an error message
	var errCode = library.BadRequest
	if myFault {
		// Log the error message to the logger service
		logFunc(err.Error(), 2, information)
		errCode = library.InternalError
	}

	message.Respond(errCode, err, information)
}

func checkUserExists(userID uuid.UUID, conn library.Database) bool {
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
func addQuota(information *library.ServiceInitializationInformation, message library.InterServiceMessage, conn library.Database) {
	// Add more quota to a user
	userID := message.Message.(nucleusLibrary.Quota).User
	if checkUserExists(userID, conn) {
		_, err := conn.DB.Exec("UPDATE users SET quota = quota + $1 WHERE id = $2", message.Message.(nucleusLibrary.Quota).Bytes, message.Message.(nucleusLibrary.Quota).User)
		if err != nil {
			respondError(message, err, information, true)
		}
	} else {
		_, err := conn.DB.Exec("INSERT INTO users (id, quota, reserved) VALUES ($1, $2, 0)", userID[:], int64(information.Configuration["defaultQuota"].(int))+message.Message.(nucleusLibrary.Quota).Bytes)
		if err != nil {
			respondError(message, err, information, true)
		}
	}

	// Success
	message.Respond(library.Success, nil, information)
}

// And so does addReserved
func addReserved(information *library.ServiceInitializationInformation, message library.InterServiceMessage, conn library.Database) {
	// Add more reserved space to a user
	userID := message.Message.(nucleusLibrary.Quota).User
	if checkUserExists(userID, conn) {
		// Check if the user has enough space
		quota, err := getQuota(information, userID, conn)
		if err != nil {
			respondError(message, err, information, true)
		}
		used, err := getUsed(userID, information, conn)
		if err != nil {
			respondError(message, err, information, true)
		}
		if used+message.Message.(nucleusLibrary.Quota).Bytes > quota {
			respondError(message, errors.New("insufficient storage"), information, false)
			return
		}
		_, err = conn.DB.Exec("UPDATE users SET reserved = reserved + $1 WHERE id = $2", message.Message.(nucleusLibrary.Quota).Bytes, userID[:])
		if err != nil {
			respondError(message, err, information, true)
		}
	} else {
		// Check if the user has enough space
		if int64(information.Configuration["defaultQuota"].(int)) < message.Message.(nucleusLibrary.Quota).Bytes {
			respondError(message, errors.New("insufficient storage"), information, false)
			return
		}
		_, err := conn.DB.Exec("INSERT INTO users (id, quota, reserved) VALUES ($1, $2, $3)", userID[:], int64(information.Configuration["defaultQuota"].(int)), message.Message.(nucleusLibrary.Quota).Bytes)
		if err != nil {
			respondError(message, err, information, true)
		}
	}

	// Success
	message.Respond(library.Success, nil, information)
}

func getQuota(information *library.ServiceInitializationInformation, userID uuid.UUID, conn library.Database) (int64, error) {
	// Get the quota for a user
	var quota int64
	err := conn.DB.QueryRow("SELECT quota FROM users WHERE id = $1", userID[:]).Scan(&quota)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_, err := conn.DB.Exec("INSERT INTO users (id, quota, reserved) VALUES ($1, $2, 0)", userID[:], int64(information.Configuration["defaultQuota"].(int)))
			if err != nil {
				return 0, err
			}
			return int64(information.Configuration["defaultQuota"].(int)), nil
		} else {
			return 0, err
		}
	}
	return quota, nil
}

func getUsed(userID uuid.UUID, information *library.ServiceInitializationInformation, conn library.Database) (int64, error) {
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
		if errors.Is(err, sql.ErrNoRows) {
			_, err := conn.DB.Exec("INSERT INTO users (id, quota, reserved) VALUES ($1, $2, 0)", userID[:], int64(information.Configuration["defaultQuota"].(int)))
			if err != nil {
				return 0, err
			}
			return 0, nil
		} else {
			return 0, err
		}
	}

	return used + reserved, nil
}

func modifyFile(information *library.ServiceInitializationInformation, message library.InterServiceMessage, conn library.Database) {
	// Check if the file already exists
	path := filepath.Join(information.Configuration["path"].(string), message.Message.(nucleusLibrary.File).User.String(), message.Message.(nucleusLibrary.File).Name)

	logFunc(path, 0, information)

	_, err := os.Stat(path)
	if err == nil {
		// Delete the file
		err = os.Remove(path)
		if err != nil {
			respondError(message, err, information, true)
		}
	} else if !os.IsNotExist(err) {
		respondError(message, err, information, true)
	}

	// Check if the user has enough space
	quota, err := getQuota(information, message.Message.(nucleusLibrary.File).User, conn)
	if err != nil {
		respondError(message, err, information, true)
	}
	used, err := getUsed(message.Message.(nucleusLibrary.File).User, information, conn)
	if err != nil {
		respondError(message, err, information, true)
	}
	if used+message.Message.(nucleusLibrary.File).Reader.N > quota {
		respondError(message, errors.New("insufficient storage"), information, false)
		return
	}

	// Add a file to the user's storage
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		respondError(message, err, information, true)
	}

	// Write the file
	_, err = io.Copy(file, message.Message.(nucleusLibrary.File).Reader)
	if err != nil {
		respondError(message, err, information, true)
	}

	// Close the file
	err = file.Close()
	if err != nil {
		respondError(message, err, information, true)
	}

	// Success
	message.Respond(library.Success, nil, information)
}

func getFile(information *library.ServiceInitializationInformation, message library.InterServiceMessage) {
	// Check if the file exists
	path := filepath.Join(information.Configuration["path"].(string), message.Message.(nucleusLibrary.File).User.String(), message.Message.(nucleusLibrary.File).Name)

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		println("file not found: " + path)
		respondError(message, errors.New("file not found"), information, false)
		return
	}

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		respondError(message, err, information, true)
	}

	// Respond with the file
	// It's their responsibility to close the file
	message.Respond(library.Success, file, information)
}

func deleteFile(information *library.ServiceInitializationInformation, message library.InterServiceMessage) {
	// Check if the file exists
	path := filepath.Join(information.Configuration["path"].(string), message.Message.(nucleusLibrary.File).User.String(), message.Message.(nucleusLibrary.File).Name)

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		respondError(message, errors.New("file not found"), information, false)
		return
	}

	// Delete the file
	err = os.Remove(path)
	if err != nil {
		respondError(message, err, information, true)
	}

	// Success
	message.Respond(library.Success, nil, information)
}

// processInterServiceMessages listens for incoming messages and processes them
func processInterServiceMessages(information *library.ServiceInitializationInformation, conn library.Database) {
	// Listen for incoming messages
	for {
		message := information.AcceptMessage()
		switch message.MessageType {
		case 1:
			// Add quota
			addQuota(information, message, conn)
		case 2:
			// Add reserved
			addReserved(information, message, conn)
		case 3:
			// Modify file
			modifyFile(information, message, conn)
		case 4:
			// Get file
			getFile(information, message)
		case 5:
			deleteFile(information, message)
		default:
			// Respond with an error message
			respondError(message, errors.New("invalid message type"), information, false)
		}
	}
}

func Main(information *library.ServiceInitializationInformation) {
	// Start up the ISM processor
	go information.StartISProcessor()

	// Get the database connection
	conn, err := information.GetDatabase()
	if err != nil {
		logFunc(err.Error(), 3, information)
	}

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

	// Listen for incoming messages
	go processInterServiceMessages(information, conn)
}
