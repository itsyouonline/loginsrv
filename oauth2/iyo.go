package oauth2

import (
	"encoding/json"
	"fmt"
	"os"
	"github.com/itsyouonline/loginsrv/model"
	"io/ioutil"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"crypto/ecdsa"
)

var jwtPubKey *ecdsa.PublicKey

const (
	iyoPubKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAES5X8XrfKdx9gYayFITc89wad4usrk0n2
7MjiGYvqalizeSWTHEpnd7oea9IQ8T5oJjMVH5cc0H5tFSKilFFeh//wngxIyny6
6+Vq5t5B0V0Ehy01+2ceEon2Y0XDkIKv
-----END PUBLIC KEY-----`
)


func init() {
	RegisterProvider(providerIYO)
	var err error

	jwtPubKey, err = jwt.ParseECPublicKeyFromPEM([]byte(iyoPubKey))
	if err != nil {
		fmt.Printf("failed to parse pub key:%v\n", err)
		os.Exit(1)
	}
}

// IYOUser is used for parsing the itsyou.online response
type IYOUser struct {
	FirstName      	string `json:"firstname,omitempty"`
	LastName      	string `json:"lastname,omitempty"`
	UserName      	string `json:"username,omitempty"`
}

var providerIYO = Provider{
	Name:     "itsyouonline",
	AuthURL:  "https://itsyou.online/v1/oauth/authorize",
	TokenURL: "https://itsyou.online/v1/oauth/access_token",
	GetUserInfo: func(token TokenInfo) (model.UserInfo, string, error) {
		// Get JWT to extract user name from it
		req, err := http.NewRequest("GET", "https://itsyou.online/v1/oauth/jwt", nil)
		if err != nil {
			return model.UserInfo{}, "", err
		}

		req.Header.Set("Authorization", "token "+token.AccessToken)
		// do request
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return model.UserInfo{}, "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return model.UserInfo{}, "", fmt.Errorf("code=%v", resp.StatusCode)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error reading itsyou.online get jwt: %v", err)
		}
		// verify token
		jwtToken, err := jwt.Parse(string(body), func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodES384 {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return jwtPubKey, nil
		})
		if err != nil {
			return model.UserInfo{}, "", err
		}

		// get claims
		claims, _ := jwtToken.Claims.(jwt.MapClaims)
		userName, _ := claims["username"].(string)

		// Get User profile
		iyoUser := IYOUser{}
		client := &http.Client{}
		req, _ = http.NewRequest("GET", "https://itsyou.online/api/users/"+userName+"/info", nil)
		req.Header.Set("Authorization", "token "+ token.AccessToken)
		response, err := client.Do(req)

		if err != nil {
			return model.UserInfo{}, "", err
		}

		if response.StatusCode != 200 {
			return model.UserInfo{}, "", fmt.Errorf("got http status %v on itsyou.online get user info", response.StatusCode)
		}

		profile, err := ioutil.ReadAll(response.Body)

		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error reading itsyou.online get user info: %v", err)
		}

		err = json.Unmarshal(profile, &iyoUser)
		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error parsing itsyou.online get user info: %v", err)
		}

		return model.UserInfo{
			Sub:	 iyoUser.UserName,
			Name:    iyoUser.FirstName+" "+iyoUser.LastName,
		}, string(profile), nil
	},
}

