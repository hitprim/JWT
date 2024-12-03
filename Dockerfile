FROM golang:1.23.1-alpine

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main ./cmd/main.go

EXPOSE 8080

# Запускаем приложение
CMD ["./main"]