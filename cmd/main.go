package main

import (
	jwtdb "JWT_Token/internal"
	"JWT_Token/internal/jwt_token"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

var dbURL = "postgres://pia:0000@localhost:5432/RefreshToken?sslmode=disable"

const ADD = "add"
const UPDATE = "update"

func sentEmail() {}

func writeARTokens(w http.ResponseWriter, r *http.Request, guid, flag string) (string, string, error) {
	userIp := r.RemoteAddr
	//jw := jwt_token.NewJWT()
	access, refresh, err := jwt_token.CreateJWT(userIp, guid)
	if err != nil {
		log.Panicln("Error to create JWT or Refresh tokens: ", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		HttpOnly: true,
		Path:     "/",
	})

	jwtDb := jwtdb.NewJWTDB(dbURL)
	if flag == ADD {
		jwtDb.CreateTable()
		jwtDb.AddRefreshToken(guid, refresh)
	} else if flag == "update" {
		jwtDb.UpdateToken(guid, refresh)
	}

	return access, refresh, nil
}

func getARTokens(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	access, refresh, _ := writeARTokens(w, r, guid, ADD)
	fmt.Fprintf(w, "Access token: %s\n Refresh token: %s", access, refresh)

}

func refreshJWT(w http.ResponseWriter, r *http.Request) {

	refreshTokenURL := r.URL.Query().Get("refresh")
	jwtDb := jwtdb.NewJWTDB(dbURL)

	guidFromDB, err := jwtDb.GetGUID(refreshTokenURL)
	if err != nil {
		log.Fatalln("Error to create Database: ", err)
		return
	}

	cookie, _ := r.Cookie("access_token")
	accessTokenCookie, _, _ := jwt.NewParser().ParseUnverified(cookie.Value, jwt.MapClaims{})
	userIp := r.RemoteAddr

	if claims, ok := accessTokenCookie.Claims.(jwt.MapClaims); ok {
		if claims["ip"].(string) != userIp {
			sentEmail()
			fmt.Fprintf(w, "Invalid user ip")
		} else {
			_, _, err := writeARTokens(w, r, guidFromDB, UPDATE)
			if err != nil {
				log.Panicln("Error to create JWT or Refresh tokens: ", err)
			}
			fmt.Fprintf(w, "Updated succesfully")
		}
	}

}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/token?{guid}", getARTokens).Methods("GET")
	r.HandleFunc("/refresh?{refresh}", refreshJWT).Methods("POST")

	log.Fatalln(http.ListenAndServe(":8080", nil))
}
