package ed25519

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	"time"

	"github.com/ockam-network/did"
	"github.com/ockam-network/ockam"
	"github.com/ockam-network/ockam/entity"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// Ed25519 is
type Ed25519 struct {
	public  *publicKey
	private ed25519.PrivateKey
	hasher  hash.Hash
}

// Option is
type Option func(*Ed25519)

// New returns
func New(options ...Option) (*Ed25519, error) {
	s := &Ed25519{}

	for _, option := range options {
		option(s)
	}

	if s.public == nil && s.private == nil {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		s.public = &publicKey{ed25519Public: public}
		s.private = private
	}

	if s.hasher == nil {
		s.hasher = sha512.New()
	}

	return s, nil
}

// PublicKey is
func PublicKey(public []byte) Option {
	return func(s *Ed25519) {
		s.public = &publicKey{ed25519Public: public}
	}
}

// PrivateKey is
func PrivateKey(private []byte) Option {
	return func(s *Ed25519) {
		s.private = private
	}
}

// PublicKey is
func (k *Ed25519) PublicKey() ockam.PublicKey {
	return k.public
}

// PrivateKey is
func (k *Ed25519) PrivateKey() []byte {
	return k.private
}

// Sign is
func (k *Ed25519) Sign(c ockam.Claim) error {
	claimJSON, err := c.MarshalJSON()
	if err != nil {
		return err
	}

	var claimMap map[string]interface{}
	err = json.Unmarshal(claimJSON, &claimMap)
	if err != nil {
		return errors.WithStack(err)
	}

	delete(claimMap, "signatures")

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/nquads"
	options.Algorithm = "URDNA2015"

	canonicalized, err := proc.Normalize(claimMap, options)
	if err != nil {
		return errors.WithStack(err)
	}

	toSign := []byte(canonicalized.(string))

	k.hasher.Write(toSign)
	signature := ed25519.Sign(k.private, k.hasher.Sum(nil))

	s := &Signature{
		t:              "Ed25519Signature2018",
		creator:        c.Issuer().ID().String() + k.PublicKey().Label(),
		created:        time.Now().UTC().Format(time.RFC3339),
		nonce:          c.Nonce(),
		signatureValue: signature,
		signedValue:    toSign,
	}

	c.AddSignature(s)
	return nil
}

// SignatureType is
func (k *Ed25519) SignatureType() string {
	return ""
}

// publicKey is
type publicKey struct {
	label string
	owner ockam.Entity

	ed25519Public ed25519.PublicKey
}

// Label is
func (p *publicKey) Label() string {
	return p.label
}

// SetLabel is
func (p *publicKey) SetLabel(l string) {
	p.label = l
}

// Owner is
func (p *publicKey) Owner() ockam.Entity {
	return p.owner
}

// SetOwner is
func (p *publicKey) SetOwner(o ockam.Entity) {
	p.owner = o
}

// Type is
func (p *publicKey) Type() string {
	return "Ed25519VerificationKey2018"
}

// Encoding is
func (p *publicKey) Encoding() string {
	return "Hex"
}

// Value is
func (p *publicKey) Value() string {
	return hex.EncodeToString(p.ed25519Public)
}

// DID is
func (p *publicKey) DID() (*did.DID, error) {
	return entity.NewDID([]byte(p.Value()))
}
