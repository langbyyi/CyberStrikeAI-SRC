package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/network"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
)

func TestProjectVPNPasswordUploadRetentionAndRedaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-auth-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := "client\ndev tun\nremote vpn.example.test 1194\n<ca>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "</ca>\nns-cert-type server\nauth-user-pass\n"
	db, user := setupConversationRBACTest(t)
	p, err := db.CreateProject(&database.Project{Name: "synthetic password project", ScopeJSON: `{"targets":["*.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAll, Permissions: map[string]bool{"project:read": true, "project:write": true}})
	})
	NewNetworkHandler(s, db).Register(r.Group("/api"))
	path := "/api/projects/" + p.ID
	send := func(method, endpoint string, value interface{}) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(value)
		req := httptest.NewRequest(method, path+endpoint, strings.NewReader(string(encoded)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if strings.Contains(w.Body.String(), "synthetic-password") || strings.Contains(w.Body.String(), "fixture-account") {
			t.Fatal("network response leaked VPN credentials")
		}
		return w
	}
	credentials := map[string]string{"username": "fixture-account", "password": "synthetic-password"}
	result := send("POST", "/vpn-profile", map[string]interface{}{"config": raw, "credentials": credentials, "version": 0})
	if result.Code != 200 {
		t.Fatalf("password upload rejected: %d %s", result.Code, result.Body)
	}
	result = send("GET", "/network-policy", nil)
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"vpn_has_auth":true`) {
		t.Fatal("missing safe configured indicator")
	}
	result = send("POST", "/vpn-profile", map[string]interface{}{"config": raw, "version": 1})
	if result.Code != 200 {
		t.Fatalf("replacement must retain credentials: %s", result.Body)
	}
	credentials["password"] = "synthetic-password-rotated"
	result = send("POST", "/vpn-profile", map[string]interface{}{"credentials": credentials, "version": 2})
	if result.Code != 200 {
		t.Fatalf("credential-only rotation failed: %s", result.Body)
	}
	result = send("POST", "/vpn-profile", map[string]interface{}{"credentials": credentials, "version": 2})
	if result.Code != 409 {
		t.Fatal("stale credential update was not rejected")
	}
	result = send("POST", "/vpn-profile", map[string]interface{}{"credentials": map[string]string{"username": "fixture-account"}, "version": 3})
	if result.Code != 400 || s.Policy(p.ID).Version != 3 {
		t.Fatal("partial credentials changed saved profile")
	}
}
