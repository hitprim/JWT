package jwtdb

import (
	"database/sql"
	"log"
)

type JWTDB struct {
	db *sql.DB
}

func NewJWTDB(httpURL string) *JWTDB {
	db, err := sql.Open("postgres", httpURL)
	if err != nil {
		log.Fatalln("Faild to connect to DB: ", err)
	}
	return &JWTDB{db: db}
}

func (t *JWTDB) CreateTable() {
	query := `CREATE TABLE IF NOT EXISTS token (
   		guid VARCHAR(255),
           refresh_token VARCHAR(255)
		)`
	_, err := t.db.Exec(query)
	if err != nil {
		log.Fatalln("Error to create Database: ", err)
	}
}

func (t *JWTDB) AddRefreshToken(guid, data string) {
	query := "INSERT INTO token (guid, refresh_token) VALUES ($1, $2)"
	_, err := t.db.Exec(query, guid, data)
	if err != nil {
		log.Fatalln("Error to inert data in Database: ", err)
	}
}

func (t *JWTDB) GetGUID(refreshToken string) (string, error) {
	var guid string
	query := "SELECT guid FROM token WHERE refresh_token = $1"
	err := t.db.QueryRow(query, refreshToken).Scan(&guid)
	return guid, err
}

func (t *JWTDB) UpdateToken(guid, refresh_token string) {
	query := "UPDATE token SET refresh_token = $1 WHERE guid = $2"
	_, err := t.db.Exec(query, refresh_token, guid)
	if err != nil {
		log.Fatalln("Cannot update refresh token: ", err)
	}
}
