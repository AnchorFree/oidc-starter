package main

import (
	"html/template"
	"log"
	"net/http"
)

var indexTmpl = template.Must(template.New("index.html").Parse(`<html>
  <body>
    <form action="/login" method="post">
       <p>
         Authenticate for:<input type="text" name="cross_client" placeholder="list of client-ids">
       </p>
       <p>
         Extra scopes:<input type="text" name="extra_scopes" placeholder="list of scopes">
       </p>
	   <p>
	     Request offline access:<input type="checkbox" name="offline_access" value="yes" checked>
       </p>
       <input type="submit" value="Login">
    </form>
  </body>
</html>`))

func renderIndex(w http.ResponseWriter) {
	renderTemplate(w, indexTmpl, nil)
}

type tokenTmplData struct {
	IDToken      string
	RefreshToken string
	RedirectURL  string
	Claims       string
}

var tokenTmpl = template.Must(template.New("token.html").Parse(`<html>
  <head>
    <style>
/* make pre wrap */
pre {
 white-space: pre-wrap;       /* css-3 */
 white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
 white-space: -pre-wrap;      /* Opera 4-6 */
 white-space: -o-pre-wrap;    /* Opera 7 */
 word-wrap: break-word;       /* Internet Explorer 5.5+ */
}
    </style>
  </head>
  <body>
    <p> Copy the following command and use it gather vault token: <pre><code>vault write oidc/login token={{ .IDToken }}</code></pre></p>
  </body>
</html>
`))

func renderToken(w http.ResponseWriter, redirectURL, idToken string) {
	renderTemplate(w, tokenTmpl, tokenTmplData{
		IDToken:     idToken,
		RedirectURL: redirectURL,
	})
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(w, data)
	if err == nil {
		return
	}

	switch err := err.(type) {
	case *template.Error:
		// An ExecError guarantees that Execute has not written to the underlying reader.
		log.Printf("Error rendering template %s: %s", tmpl.Name(), err)

		// TODO(ericchiang): replace with better internal server error.
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		// An error with the underlying write, such as the connection being
		// dropped. Ignore for now.
	}
}
