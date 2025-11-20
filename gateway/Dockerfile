# Use a specific Go runtime version as a parent image
FROM golang:1.25.4-alpine

# Set the current working directory inside the container
WORKDIR /app

# Copy the Go code into the container at /app
COPY . .

# Get dependencies (in case you have any Go modules)
RUN go mod tidy

# Build the Go binary
RUN go build -o main ./cmd/server/main.go

# Expose the port the app runs on
EXPOSE 8080

# Run the Go binary
CMD ["./main"]
