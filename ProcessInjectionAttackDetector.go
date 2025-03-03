package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"
	"syscall"
	"golang.org/x/sys/windows"
)

func computeSHA256Hash(filePath string) {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Create SHA256 hash object
	hash := sha256.New()

	// Read the file in chunks and update the hash
	buf := make([]byte, 1024)
	for {
		n, err := file.Read(buf)
		if err != nil && err.Error() != "EOF" {
			fmt.Println("Error reading file:", err)
			return
		}
		if n == 0 {
			break
		}
		hash.Write(buf[:n])
	}

	// Output the computed hash
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	fmt.Println("SHA256 hash of the file:", hashString)
}

// Function to analyze the PE file - simplified version
func analyzePEFile(filePath string) {
	// For simplicity, this function will just print the file information
	fmt.Printf("Analyzing PE file (Windows executable) at: %s\n", filePath)
	// Full PE file parsing would require complex header and section parsing logic
}

// Function to monitor a running process for suspicious DLLs
func monitorProcess(filePath string) {
	// Start the executable as a process
	cmd := syscall.StringToUTF16Ptr(filePath)
	pi := &windows.ProcessInformation{}
	si := &windows.StartupInfo{}
	err := windows.CreateProcess(nil, cmd, nil, nil, false, 0, nil, nil, si, pi)
	if err != nil {
		fmt.Printf("Failed to start process: %v\n", err)
		return
	}

	fmt.Printf("Monitoring process with PID: %d...\n", pi.ProcessId)

	// Monitor the process for suspicious DLLs (simplified version)
	for {
		// Here you could implement module enumeration to detect loaded DLLs
		// This is a placeholder loop for the purpose of this example.
		fmt.Printf("Monitoring process PID: %d\n", pi.ProcessId)

		// Sleep to simulate checking every second
		time.Sleep(1 * time.Second)
	}

	// Wait for the process to finish
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
}

// Main function
func main() {
	var filePath string
	

	// Get file path from user
	fmt.Print("Please enter the path of the executable file to analyze:")
	fmt.Scanf("%s", &filePath)

	// Check if the file exists
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		fmt.Printf("Error: The file '%s' does not exist.\n", filePath)
		return
	}

	// Compute SHA256 hash of the executable file for integrity checking
	computeSHA256Hash(filePath)

	// Perform PE analysis for Windows Executables
	if strings.HasSuffix(strings.ToLower(filePath), ".exe") {
		analyzePEFile(filePath)
	} else {
		fmt.Println("The file is not a Windows executable (.exe). No PE analysis performed.")
	}

	// Ask user if they want to monitor the process for injection behavior
	var userInput string
	fmt.Printf("Would you like to monitor the process of %s? (y/n): ", filePath)
	fmt.Scanf("%s", &userInput)

	if strings.ToLower(userInput) == "y" {
		monitorProcess(filePath)
	} else {
		fmt.Println("Exiting the tool.")
	}
}
