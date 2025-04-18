# Go Application with Tester

This project consists of a Go application that listens on port 5000 and handles authentication-related requests. Additionally, there is a separate testing application that sends requests to the main application and verifies the responses.

## Project Structure

```
go-app-with-tester
├── app
│   ├── main.go              # Entry point of the application
│   ├── handlers             # Contains HTTP handler functions
│   │   └── auth.go          # Authentication-related handlers
│   ├── utils                # Utility functions
│   │   └── env.go           # Environment variable management
│   └── go.mod               # Go module definition for the app
├── tester
│   ├── main.go              # Entry point for the testing application
│   └── go.mod               # Go module definition for the tester
└── README.md                # Project documentation
```

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd go-app-with-tester
   ```

2. **Navigate to the app directory and install dependencies:**
   ```
   cd app
   go mod tidy
   ```

3. **Navigate to the tester directory and install dependencies:**
   ```
   cd ../tester
   go mod tidy
   ```

## Running the Application

1. **Start the main application:**
   ```
   cd app
   go run main.go
   ```

   The application will start listening on port 5000.

2. **Run the tester application:**
   ```
   cd ../tester
   go run main.go
   ```

   The tester will send requests to the main application and verify the responses.

## Usage

- The main application handles authentication-related requests.
- The tester application is designed to validate the functionality of the main application by sending various requests and checking the responses.

## License

This project is licensed under the MIT License.