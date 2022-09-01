package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

var (
	sessions map[string]Session
	lock     sync.RWMutex
	encKey   string
	keysPath string
)

type Session struct {
	Username string
	Expires  time.Time
}

func (s *Session) Expired() bool {
	return time.Now().After(s.Expires)
}

func init() {
	sessions = make(map[string]Session)
}

func genSession(username string) string {
	sid := strconv.FormatInt(rand.Int63(), 36)
	lock.Lock()
	defer lock.Unlock()
	sessions[sid] = Session{
		Username: username,
		Expires:  time.Now().Add(time.Minute * 5),
	}
	return sid
}

func getSession(sid string) (Session, bool) {
	lock.RLock()
	defer lock.RUnlock()
	s, ok := sessions[sid]
	return s, ok
}

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
	ca, err := ioutil.ReadFile(path.Join(keysPath, username, "ca.crt"))
	if err != nil {
		return nil, err
	}
	auth.CACert = string(ca)

	ta, err := ioutil.ReadFile(path.Join(keysPath, username, "ta.key"))
	if err != nil {
		return nil, err
	}
	auth.TlsAuth = string(ta)

	cert, err := ioutil.ReadFile(path.Join(keysPath, username, username+".crt"))
	if err != nil {
		return nil, err
	}
	auth.Cert, err = readCert(cert)
	if err != nil {
		return nil, err
	}

	key, err := ioutil.ReadFile(path.Join(keysPath, username, username+".key"))
	if err != nil {
		return nil, err
	}
	auth.Key = string(key)

	return auth, nil
}

func verifyPassword(pwdPath, password string) (ok bool, err error) {
	data, err := ioutil.ReadFile(pwdPath)
	if err != nil {
		return false, err
	}

	expected := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(expected, data)
	if err != nil {
		return
	}
	h := hmac.New(sha1.New, []byte(encKey))
	h.Write([]byte(password))
	fact := h.Sum(nil)
	ok = bytes.Equal(fact, expected[:n])
	return
}

func main() {
	flag.StringVar(&keysPath, "keys-path", "/etc/openvpn/client/keys", "keys path")
	flag.StringVar(&encKey, "enc-key", "", "hmac key")
	flag.Parse()
	info, err := os.Stat(keysPath)
	if err != nil || !info.IsDir() {
		log.Fatal("keys path invalid")
	}

	tpl, err := template.ParseFiles("config.ovpn.tpl")
	if err != nil {
		log.Fatalf("parse config template with error: %s", err)
	}

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
				p := path.Join(keysPath, username)
				info, err := os.Stat(p)
				if err != nil || !info.IsDir() {
					log.Printf("[ERROR] stat key path %s is unavailable", p)
				} else {
					pass, err := verifyPassword(path.Join(p, "password"), password)
					if err != nil {
						log.Printf("[ERROR] verify password with error: %s", err)
					} else if pass {
						sid := genSession(username)
						log.Printf("[INFO] gen session %s", sid)
						status.Value.InnerXML = "<int>0</int>"
						sessionID.Value.InnerXML = fmt.Sprintf("<string>%s</string>", sid)
					} else {
						log.Printf("[WARN] user %s password incorrect", username)
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
			auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
			authStr, err := base64.StdEncoding.DecodeString(auth)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sid := strings.TrimPrefix(string(authStr), "SESSION_ID:")
			log.Printf("[INFO] method:%s sid: %s", call.MethodName, sid)
			session, ok := getSession(sid)
			if !ok || session.Expired() {
				log.Printf("[ERROR] session invalid, ok: %t, session: %+v", ok, session)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			oAuth, err := GetOpenVPNAuth(session.Username)
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
			err = tpl.Execute(b, oAuth)
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
