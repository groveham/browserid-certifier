package certifier

import (
	"fmt"
	"log"
	"net/http"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
)

var bindAddress, issuer_hostname, pub_key_path, priv_key_path string
var verbose = false
var validity = 86400000

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s issuer_hostname pub_key_path priv_key_path\n", os.Args[0])
	flag.PrintDefaults()
}

type errorFixture struct {
	Success bool `json:"success"`
	Reason string `json:"reason"`
}

type successFixtue struct {
	Success bool `json:"success"`
	Certificate string `json:"certificate"`
}

type requestFixture struct {
	Email string `json:"email"`
	Duration int `json:"duration,omitempty"`
	Pubkey string  `json:"pubkey"`
}

func jsonResponse(w http.ResponseWriter, v interface{}) string {
	response, _ := json.Marshal(v)
	return string(response)
}

func main() {
	flag.Usage = usage
	flag.StringVar(&bindAddress, "bind", "127.0.0.1:8000", "Address to bind to")
	flag.BoolVar(&verbose, "verbose", false, "Be more verbose")
	flag.IntVar(&validity, "validity", 86400000, "Default validity in ms")
	flag.Parse()

	if flag.NArg() != 3 {
		flag.Usage()
		return
	}
	issuer_hostname = flag.Arg(0)
	pub_key_path = flag.Arg(1)
	priv_key_path = flag.Arg(2)

	http.HandleFunc("/cert_key", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		w.Header().Set("Content-type", "application/json")

		var decoded requestFixture
		body, _ := ioutil.ReadAll(r.Body)
		err := json.Unmarshal(body, &decoded)

		if err != nil {
			http.Error(w, jsonResponse(w, errorFixture{
				Success:false,
				Reason:err.Error(),
			}), 400)
			return
		}
		if len(decoded.Email) <= 0 {
			http.Error(w, jsonResponse(w, errorFixture{
				Success:false,
				Reason:"email argument is required and must be a string",
			}), 400)
			return
		}
		if len(decoded.Pubkey) <= 0 {
			http.Error(w, jsonResponse(w, errorFixture{
				Success:false,
				Reason:"pubkey argument is required and must be a string",
			}), 400)
			return
		}
		if decoded.Duration <= 0 {
			decoded.Duration = validity
		}

		// Do the certificate signing with something like
		// https://github.com/dgrijalva/jwt-go
	})
	http.HandleFunc("/__heartbeat__", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok certifier"))
	})
	log.Print("Running on: ", bindAddress)
	err := http.ListenAndServe(bindAddress, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
