package main

import (
	"JWT_Token/internal/jwt_token"
	jwtdb "JWT_Token/internal/postgres"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var dbURL = "postgres://postgres:1234@localhost:5432/JWT?sslmode=disable"

const ADD = "add"
const UPDATE = "update"

func sentEmail() {}

func writeARTokens(w http.ResponseWriter, r *http.Request, guid, flag string) (string, string, error) {
	userIp := strings.Split(r.RemoteAddr, ":")[0]

	//создаем access и refresh токены непосредственно
	access, refresh, err := jwt_token.CreateJWT(userIp, guid)
	if err != nil {
		log.Panicln("Error to create JWT or Refresh tokens: ", err)
	}

	//устанавливаем куки для access токена
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		HttpOnly: true,
		Path:     "/",
	})

	//в зависимости от флага: записываем в базу refresh токен или обновляем его
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
	//получаем guid
	vars := mux.Vars(r)
	guid := vars["guid"]

	guidRegex := `^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`
	match, _ := regexp.Match(guidRegex, []byte(guid))

	if !match {
		fmt.Fprintf(w, "Missmath with GUID form")
	} else {
		//создаем токены с флагом Добавить(ADD)
		access, refresh, _ := writeARTokens(w, r, guid, ADD)
		fmt.Fprintf(w, "Access token: %s\n Refresh token: %s", access, refresh)
	}

}

func refreshJWT(w http.ResponseWriter, r *http.Request) {
	//получаем рефреш токен
	refreshTokenURL := r.URL.Query().Get("refresh")

	//получаем guid из базы
	jwtDb := jwtdb.NewJWTDB(dbURL)
	guidFromDB, err := jwtDb.GetGUID(refreshTokenURL)
	if err != nil {
		log.Fatalln("Error to create Database: ", err)
		return
	}

	//смотрим куки access токена
	cookie, _ := r.Cookie("access_token")
	// парсим токен чтобы получить ip пользователя
	accessTokenCookie, _, _ := jwt.NewParser().ParseUnverified(cookie.Value, jwt.MapClaims{})
	userIp := strings.Split(r.RemoteAddr, ":")[0]

	if claims, ok := accessTokenCookie.Claims.(jwt.MapClaims); ok {
		//если ip не совпадает с текущим, то отправляем оповещение на мыло
		if claims["ip"].(string) != userIp {
			sentEmail()
			fmt.Fprintf(w, "Invalid user ip")
		} else {
			if claims["guid"] == guidFromDB {
				// если ip совпадает, то создаем токены с флагом Обновить(UPDATE)
				_, _, err := writeARTokens(w, r, guidFromDB, UPDATE)
				if err != nil {
					log.Panicln("Error to create JWT or Refresh tokens: ", err)
				}
				fmt.Fprintf(w, "Updated succesfully")
			} else {
				fmt.Fprintf(w, "Invalid refresh token")
				return
			}
		}
	}

}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/token/{guid}", getARTokens).Methods("GET")
	r.HandleFunc("/refresh", refreshJWT).Methods("POST")

	log.Fatalln(http.ListenAndServe(":8080", r))
}
