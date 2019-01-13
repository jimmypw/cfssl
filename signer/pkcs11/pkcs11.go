package pkcs11

import (
	"errors"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer/local"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"

	"github.com/letsencrypt/pkcs11key"
)

// Config struct
type Config struct {
	Module string
	PIN    string
	Token  string
}

// New instantiates the pkcs11 signer
func New(cert string, policy *config.Signing, conf *Config) (signer.Signer, error) {
	cacertdata, err := helpers.ReadBytes(cert)

	if err != nil {
		return nil, errors.New("Unable to read CA Certificate")
	}

	cacertparsed, err := helpers.ParseCertificatePEM(cacertdata)
	if err != nil {
		return nil, errors.New("Unable to parse CA Certificate")
	}

	log.Debugf("Loading PKCS11 Module %s", conf.Module)

	privkey, err := pkcs11key.New(conf.Module, conf.Token, conf.PIN, cacertparsed.PublicKey)
	if err != nil {
		return nil, errors.New("Failed to instantiate pkcs11key")
	}
	sigAlgo := signer.DefaultSigAlgo(privkey)

	return local.NewSigner(privkey, cacertparsed, sigAlgo, policy)
}
