package sshagent

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestDestinationGrantsRequireBoundHostAuthentication(t *testing.T) {
	key, _ := sshkey.NewEd25519("client", "")
	pub, _ := key.PublicKey()
	host, _ := sshkey.NewEd25519("server", "")
	signer, _ := host.Signer()
	other, _ := sshkey.NewEd25519("other", "")
	otherSigner, _ := other.Signer()
	session := []byte("unique-session-key-exchange-hash")
	type auth struct {
		Session               []byte
		Message               byte
		User, Service, Method string
		HasSignature          bool
		Algorithm             string
		Public, Host          []byte
	}
	good := auth{session, 50, "admin", "ssh-connection", "publickey-hostbound-v00@openssh.com", true, pub.Type(), pub.Marshal(), signer.PublicKey().Marshal()}
	for _, tc := range []string{"allowed", "no binding", "wrong user", "wrong host", "wrong session", "generic signing", "legacy auth", "bad signature", "forwarding", "rebind", "other connection", "wrong key", "wrong service"} {
		t.Run(tc, func(t *testing.T) {
			provider := &staticProvider{keys: []KeyEntry{{Key: key, Destinations: []Destination{{User: "admin", HostKeys: [][]byte{signer.PublicKey().Marshal()}}}}}}
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()
			go agent.ServeAgent(New(provider), server)
			c := agent.NewClient(client)
			signWith := signer
			if tc == "wrong host" {
				signWith = otherSigner
			}
			signature, _ := signWith.Sign(rand.Reader, session)
			if tc == "bad signature" {
				signature.Blob[0] ^= 0xff
			}
			bind := ssh.Marshal(struct {
				Host, Session, Signature []byte
				Forward                  bool
			}{signWith.PublicKey().Marshal(), session, ssh.Marshal(signature), tc == "forwarding"})
			if tc != "no binding" {
				_, err := c.Extension("session-bind@openssh.com", bind)
				if tc == "bad signature" || tc == "forwarding" {
					if err == nil {
						t.Fatal("invalid binding accepted")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if tc == "rebind" {
				if _, err := c.Extension("session-bind@openssh.com", bind); err == nil {
					t.Fatal("rebind accepted")
				}
			}
			if tc == "other connection" {
				s2, c2 := net.Pipe()
				defer s2.Close()
				defer c2.Close()
				go agent.ServeAgent(New(provider), s2)
				c = agent.NewClient(c2)
			}
			req := good
			switch tc {
			case "wrong user":
				req.User = "root"
			case "wrong session":
				req.Session = []byte("other")
			case "legacy auth":
				req.Method = "publickey"
			case "wrong key":
				req.Public = otherSigner.PublicKey().Marshal()
			case "wrong service":
				req.Service = "not-ssh"
			}
			data := ssh.Marshal(req)
			if tc == "generic signing" {
				data = []byte("arbitrary document")
			}
			signature, err := c.Sign(pub, data)
			if tc == "allowed" {
				if err != nil || pub.Verify(data, signature) != nil {
					t.Fatal("valid destination rejected", err)
				}
			} else if err == nil {
				t.Fatal("unauthorized signature returned")
			}
		})
	}
}
