package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/gofly/ovpnsub/auth"
)

var (
	authEncKey   string
	easyrsaPath  string
	confTplPath  string
	sanyAuthHost string
)

type MethodCall struct {
	XMLName    xml.Name `xml:"methodCall"`
	MethodName string   `xml:"methodName"`
	Params     string   `xml:"params"`
}

type Member struct {
	Name  string `xml:"name"`
	Value struct {
		InnerXML string `xml:",innerxml"`
	} `xml:"value"`
}

type SessionXML struct {
	XMLName xml.Name `xml:"methodResponse"`
	Member  []Member `xml:"params>param>value>struct>member"`
}

type Param struct {
	Value struct {
		String []byte `xml:",chardata"`
	} `xml:"value>string"`
}

type UserLoginXML struct {
	XMLName xml.Name `xml:"methodResponse"`
	Params  []Param  `xml:"params>param"`
}

type OpenVPNAuth struct {
	CACert  string
	Cert    string
	Key     string
	TlsAuth string
}

func readCert(data []byte) (string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("can not decode cert")
	}
	return string(pem.EncodeToMemory(block)), nil
}

func GetOpenVPNAuth(username string) (*OpenVPNAuth, error) {
	auth := &OpenVPNAuth{}
	ca, err := ioutil.ReadFile(path.Join(easyrsaPath, "pki", "ca.crt"))
	if err != nil {
		return nil, err
	}
	auth.CACert = string(ca)

	ta, err := ioutil.ReadFile(path.Join(easyrsaPath, "pki", "ta.key"))
	if err != nil {
		return nil, err
	}
	auth.TlsAuth = string(ta)

	cert, err := ioutil.ReadFile(path.Join(easyrsaPath, "pki", "issued", username+".crt"))
	if err != nil {
		return nil, err
	}
	auth.Cert, err = readCert(cert)
	if err != nil {
		return nil, err
	}

	key, err := ioutil.ReadFile(path.Join(easyrsaPath, "pki", "private", username+".key"))
	if err != nil {
		return nil, err
	}
	auth.Key = string(key)

	return auth, nil
}

func main() {
	flag.StringVar(&easyrsaPath, "easyrsa-path", "/etc/openvpn/easyrsa", "easyrsa path")
	flag.StringVar(&confTplPath, "conf-tpl-path", "config.ovpn.tpl", "keys path")
	flag.StringVar(&authEncKey, "auth-enc-key", "this_is_enc_key", "key for hmac-sha1 in local auth")
	flag.StringVar(&sanyAuthHost, "sany-auth-host", "", "sany auth service host")
	flag.Parse()
	info, err := os.Stat(easyrsaPath)
	if err != nil || !info.IsDir() {
		log.Fatal("easyrsa path invalid")
	}

	tpl, err := template.ParseFiles(confTplPath)
	if err != nil {
		log.Fatalf("parse config template with error: %s", err)
	}
	var authService auth.AuthService
	if sanyAuthHost != "" {
		authService = &auth.SanyAuthService{
			Host: sanyAuthHost,
		}
	} else {
		authService = &auth.LocalAuthService{
			AuthEncKey: authEncKey,
		}
	}
	http.HandleFunc("/rest/GetUserlogin", func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			log.Printf("[WARN] user %s password incorrect", username)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Printf("[INFO] method:/rest/GetUserlogin username:%s", username)

		token, err := authService.Authorize(context.Background(), username, password)
		if err != nil || token == "" {
			log.Printf("[WARN] user %s password incorrect", username)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ovpnAuth, err := GetOpenVPNAuth(username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] get ovpn auth error: %s", err)
			return
		}
		err = tpl.Execute(w, ovpnAuth)
		if err != nil {
			log.Printf("[ERROR] execute template with error: %s", err)
		}
	})

	http.HandleFunc("/RPC2", func(w http.ResponseWriter, r *http.Request) {
		call := MethodCall{}
		err := xml.NewDecoder(r.Body).Decode(&call)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Bad request")
			return
		}
		switch call.MethodName {
		case "GetSession":
			status := Member{Name: "status"}
			status.Value.InnerXML = "<int>1</int>"
			sessionID := Member{Name: "session_id"}
			username, password, ok := r.BasicAuth()
			if ok {
				token, err := authService.Authorize(context.Background(), username, password)
				if err != nil {
					log.Printf("[WARN] user %s password incorrect", username)
				} else {
					p := path.Join(easyrsaPath, "pki", "issued", username+".crt")
					_, err := os.Stat(p)
					if err != nil {
						log.Printf("[ERROR] stat key path %s is unavailable", p)
					} else {
						status.Value.InnerXML = "<int>0</int>"
						sessionID.Value.InnerXML = fmt.Sprintf("<string>%s</string>", token)
					}
				}
			}
			log.Printf("[INFO] method:%s username:%s %s", call.MethodName, username, sessionID.Value.InnerXML)
			s := SessionXML{
				Member: []Member{status, sessionID},
			}
			buf := bytes.NewBuffer(nil)
			buf.WriteString(xml.Header)
			err := xml.NewEncoder(buf).Encode(s)
			if err != nil {
				log.Printf("[ERROR] marshal xml with error: %s", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, err)
				return
			}
			io.Copy(w, buf)
		case "GetUserlogin", "GetAutologin":
			baseAuth := strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
			authVal, err := base64.StdEncoding.DecodeString(baseAuth)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			token := strings.TrimPrefix(string(authVal), "SESSION_ID:")
			log.Printf("[INFO] method:%s token: %s", call.MethodName, token)
			username, err := authService.VerifyToken(context.Background(), token)
			if err != nil {
				log.Printf("[ERROR] session invalid, token: %+v, error: %s", token, err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			ovpnAuth, err := GetOpenVPNAuth(username)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("[ERROR] get ovpn auth error: %s", err)
				return
			}

			buf := bytes.NewBuffer(nil)
			buf.WriteString(xml.Header)
			login := UserLoginXML{
				Params: make([]Param, 2),
			}

			b := bytes.NewBuffer(nil)
			err = tpl.Execute(b, ovpnAuth)
			if err != nil {
				log.Printf("[ERROR] execute template with error: %s", err)
			} else {
				login.Params[0].Value.String = b.Bytes()
				login.Params[1].Value.String = b.Bytes()
			}

			err = xml.NewEncoder(buf).Encode(login)
			if err != nil {
				log.Printf("[ERROR] marshal xml with error: %s", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, err)
				return
			}
			io.Copy(w, buf)
		}
	})
	http.ListenAndServe(":1380", nil)
}
