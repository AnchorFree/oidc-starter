package main

import (
	"html/template"
	"log"
	"net/http"
)

type tokenTmplData struct {
	IDToken       string
	RefreshToken  string
	RedirectURL   string
	Claims        string
	WebPathPrefix string
	VaultVersion  string
	OS            string
}

var tokenTmpl = template.Must(template.ParseGlob("web/template/token-*.html"))

func renderToken(w http.ResponseWriter, redirectURL, idToken string, claims string, webPathPrefix string, vaultVersion string) {
	renderTemplate(w, tokenTmpl, tokenTmplData{
		IDToken:       idToken,
		RedirectURL:   redirectURL,
		WebPathPrefix: webPathPrefix,
		VaultVersion:  vaultVersion,
		Claims:        claims,
		OS:            "linux",
	})
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(w, data)
	if err == nil {
		return
	}

	log.Printf("%+v", data)

	switch err := err.(type) {
	case *template.Error:
		// An ExecError guarantees that Execute has not written to the underlying reader.
		log.Printf("Error rendering template %s: %s", tmpl.Name(), err)

		// TODO(ericchiang): replace with better internal server error.
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		log.Printf("%+v\n", err)
	}
}
