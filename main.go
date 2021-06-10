package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

var cookieHandler = securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
var ipAddress string
var color *string

func extractHeaderInformation(request *http.Request) string {
	var headerString string

	for name, value := range request.Header {
		headerString += name + ": " + strings.Join(value, ", ") + "<br/>"
	}

	return headerString
}

const indexPage = `
<h1 style="color: %s">Login</h1>
<h2>Your IP - %s</h2>
<p><b>Request Header</b> - %s</p>
<h3>Served from %s</h3>
<hr/>
<form method="post" action="/login">
	<label for="name">User name</label>
	<input type="text" id="name" name="name"/>
	<label for="password">Password</label>
	<input type="password" id="password" name="password"/>
	<button type="submit">Login</button>
</form>`

func indexPageHandler(response http.ResponseWriter, request *http.Request) {
	log.Printf("%s %s %s\n", request.RemoteAddr, request.Method, request.RequestURI)

	userName := getUserName(request)
	if userName != "" {
		http.Redirect(response, request, "/internal", http.StatusFound)
	} else {
		headerInfo := extractHeaderInformation(request)
		fmt.Fprintf(response, indexPage, *color, request.RemoteAddr, headerInfo, ipAddress)
	}
}

const internalPage = `
<h1 style="color: %s">Internal</h1>
<h2>Your IP - %s</h2>
<p><b>Request Header</b> - %s</p>
<h3>Served from %s</h3>
<hr/>
<small>User: %s</small>
<form method="post" action="/logout">
	<button type="submit">Logout</button>
</form>`

func internalPageHandler(response http.ResponseWriter, request *http.Request) {
	log.Printf("%s %s %s\n", request.RemoteAddr, request.Method, request.RequestURI)

	userName := getUserName(request)
	if userName != "" {
		headerInfo := extractHeaderInformation(request)
		fmt.Fprintf(response, internalPage, *color, request.RemoteAddr, headerInfo, ipAddress, userName)
	} else {
		http.Redirect(response, request, "/", http.StatusFound)
	}
}

func loginHandler(response http.ResponseWriter, request *http.Request) {
	log.Printf("%s %s %s\n", request.RemoteAddr, request.Method, request.RequestURI)

	name := request.FormValue("name")
	pass := request.FormValue("password")
	redirectTarget := "/"
	if name != "" && pass != "" {
		// .. check credentials ..
		setSession(name, response)
		redirectTarget = "/internal"
	}
	http.Redirect(response, request, redirectTarget, http.StatusFound)
}

func logoutHandler(response http.ResponseWriter, request *http.Request) {
	log.Printf("%s %s %s\n", request.RemoteAddr, request.Method, request.RequestURI)

	clearSession(response)
	http.Redirect(response, request, "/", http.StatusFound)
}

func setSession(userName string, response http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func getUserName(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}

func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

var router = mux.NewRouter()

func getIPAddress() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

func main() {

	color = flag.String("color", "black", "Provide the color for header")
	flag.Parse()

	var err error

	ipAddress, err = getIPAddress()
	if err != nil {
		log.Println(err)
	}

	router.HandleFunc("/", indexPageHandler)
	router.HandleFunc("/internal", internalPageHandler)

	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler).Methods("POST")

	router.HandleFunc("/health", func(response http.ResponseWriter, request *http.Request) {
		log.Printf("%s %s %s\n", request.RemoteAddr, request.Method, request.RequestURI)

		fmt.Fprintf(response, "healthy")
	})

	http.Handle("/", router)

	log.Println("Server is listening at 0.0.0.0:8080")
	http.ListenAndServe("0.0.0.0:8080", nil)
}
