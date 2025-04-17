FROM golang:1.24-alpine

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /app/security-app .
RUN apk add --no-cache ca-certificates

RUN chmod +x /app/security-app

CMD ["/app/security-app"]