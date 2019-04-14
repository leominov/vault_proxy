package sso

import (
	"net/http"
)

func (s *SSO) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	state, b, err := s.stateFromRequest(r)
	if err != nil && err != http.ErrNoCookie {
		s.setLogoutCookie(w)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if state == nil {
		http.Redirect(w, r, loginRoute, http.StatusFound)
		return
	}
	requiredPolicies, ok := s.isAccessAllowed(r.Method, r.URL.Path, state.Policies)
	if !ok {
		data := map[string]interface{}{
			"meta": s.c.Meta,
			"request": map[string]interface{}{
				"method":   r.Method,
				"path":     r.URL.Path,
				"policies": requiredPolicies,
			},
		}
		s.log.Errorf("Failed to access %v", data["request"])
		s.showForbiddenError(w, r, data)
		return
	}
	r.Header.Add(s.c.HeaderName, string(b))
	r.URL.Scheme = s.c.upstreamURL.Scheme
	r.URL.Host = s.c.upstreamURL.Host
	r.Host = s.c.upstreamURL.Host
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	s.proxy.ServeHTTP(w, r)
}
