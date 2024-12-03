package jwt_token

import (
	"crypto/rand"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
)

//type JWT struct {
//}
//
//var jwtSecretKey = []byte("key")
//
//func NewJWT() JWT {
//	return JWT
//}

func CreateJWT(ip, guid string) (string, string, error) {
	claims := jwt.MapClaims{
		"ip":   ip,
		"guid": guid,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SigningString()
	if err != nil {
		log.Fatalln("Error to create access token: ", err)
		return "", "", err
	}

	bufToken := make([]byte, 32)
	rand.Read(bufToken)

	refreshHashedToken, err := bcrypt.GenerateFromPassword(bufToken, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalln("Error to generate refresh token: ", err)
		return "", "", err
	}

	return accessToken, string(refreshHashedToken), nil
}
