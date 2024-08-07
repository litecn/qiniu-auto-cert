package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
	"github.com/joho/godotenv"
)

var CertFolder string

type Cert struct {
	CertID    string    `json:"SerialNumber"`
	DNSNames  []string  `json:"DNSNames"`
	NotBefore time.Time `json:"NotBefore"`
	NotAfter  time.Time `json:"NotAfter"`
}

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func init() {
	godotenv.Load()
	folder, ok := os.LookupEnv("CERT_FOLDER")
	if ok {
		if filepath.IsAbs(folder) {
			CertFolder = folder
		} else {
			local, _ := os.Getwd()
			CertFolder = path.Join(local, folder)
		}
	} else {
		local, _ := os.Getwd()
		CertFolder = path.Join(local, "cert")
	}
	log.Println("cert folder: ", CertFolder)
	err := os.MkdirAll(CertFolder, os.ModePerm)
	if err != nil {
		log.Println("mkdir ", err)
	}
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func generatePrivateKey(file string) (crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pemKey := pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			log.Println("close", file, "error: ", err)
		}
	}()

	err = pem.Encode(certOut, &pemKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func GetAcmeClient(email string) (*lego.Client, error) {
	user := User{Email: email}

	var client *lego.Client
	var err error
	var reg *registration.Resource

	privateKeyPath := path.Join(CertFolder, email+".privateKey")
	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		key, err := generatePrivateKey(privateKeyPath)
		if err != nil {
			return nil, err
		}
		user.key = key

		cfg := lego.NewConfig(user)
		// cfg.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		// cfg.CADirURL = lego.LEDirectoryStaging
		client, err = lego.NewClient(cfg)
		if err != nil {
			return nil, err
		}

		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
	} else {
		user.key = key
		client, err = lego.NewClient(lego.NewConfig(user))
		if err != nil {
			return nil, err
		}

		reg, err = client.Registration.ResolveAccountByKey()
		if err != nil {
			return nil, err
		}
	}

	user.Registration = reg

	// provider, err := dns.NewDNSChallengeProviderByName(os.Getenv("DNS_PROVIDER"))
	// if err != nil {
	// 	return nil, err
	// }
	client.Challenge.Remove(challenge.HTTP01)
	client.Challenge.Remove(challenge.TLSALPN01)
	// err = client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{
	// 	"223.5.5.5:53",
	// 	"1.1.1.1:53",
	// }))
	provider, ok := os.LookupEnv("DNS_PROVIDER")
	if !ok {
		return nil, fmt.Errorf("no env DNS_PROVIDER")
	}
	err = setProvider(client, provider)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ObtainCert(email string, domain []string) (*certificate.Resource, error) {
	client, err := GetAcmeClient(email)
	if err != nil {
		return nil, err
	}
	cert, err := LoadCertResource(domain[0])
	if err != nil {
		return obtainNewCert(client, domain)
	}

	// cert, err = client.Certificate.Renew(*cert, false, false, "")
	cert, err = client.Certificate.RenewWithOptions(*cert, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return obtainNewCert(client, domain)
	}
	if err := saveCertInfo(domain[0], cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func obtainNewCert(client *lego.Client, domain []string) (*certificate.Resource, error) {
	cert, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domain,
		Bundle:  true,
	})
	if err != nil {
		return nil, err
	}
	if err := saveCertInfo(domain[0], cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func saveCertInfo(domain string, cert *certificate.Resource) error {
	metaPath := path.Join(CertFolder, domain+".json")
	privateKeyPath := path.Join(CertFolder, domain+".key")
	certPath := path.Join(CertFolder, domain+".crt")
	metaData, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	err = os.WriteFile(metaPath, metaData, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(privateKeyPath, cert.PrivateKey, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(certPath, cert.Certificate, 0600)
	if err != nil {
		return err
	}
	return nil
}

func LoadCertResource(domain string) (*certificate.Resource, error) {
	metaPath := path.Join(CertFolder, domain+".json")
	privateKeyPath := path.Join(CertFolder, domain+".key")
	certPath := path.Join(CertFolder, domain+".crt")
	cert := new(certificate.Resource)
	meta, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(meta, cert); err != nil {
		return nil, err
	}
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	cert.PrivateKey = privateKey
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	cert.Certificate = certData
	return cert, nil
}

func setProvider(client *lego.Client, provider string) error {
	switch provider {
	case "cloudflare":
		// cfg := cloudflare.NewDefaultConfig()
		// authToken, ok := os.LookupEnv("CLOUDFLARE_DNS_API_TOKEN")
		// if ok {
		// 	cfg.AuthToken = authToken
		// } else {
		// 	cfEmail, okEmail := os.LookupEnv("CLOUDFLARE_EMAIL")
		// 	cfAuthKey, okAuthKey := os.LookupEnv("CLOUDFLARE_API_KEY")
		// 	if !okEmail || !okAuthKey {
		// 		return fmt.Errorf("no env CLOUDFLARE_DNS_API_TOKEN or CLOUDFLARE_EMAIL and CLOUDFLARE_API_KEY")
		// 	}
		// 	cfg.AuthEmail = cfEmail
		// 	cfg.AuthKey = cfAuthKey
		// }
		// p, err := cloudflare.NewDNSProviderConfig(cfg)
		p, err := cloudflare.NewDNSProvider()
		if err != nil {
			return err
		}
		err = client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return err
		}
	case "alidns":
		p, err := alidns.NewDNSProvider()
		if err != nil {
			return err
		}
		err = client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return err
		}
	case "tencentcloud":
		p, err := tencentcloud.NewDNSProvider()
		if err != nil {
			return err
		}
		err = client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return err
		}
	default:
		err := fmt.Errorf("invalid dns provider")
		return err
	}
	return nil
}

func GetCertInfo(cert certificate.Resource) (*Cert, error) {
	var certData Cert
	block, _ := pem.Decode(cert.Certificate)
	// log.Println("block:", block)

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("parse certificate:", err)
		return &certData, err
	}
	// crtJSON, _ := json.Marshal(crt)

	// err = json.Unmarshal(crtJSON, &certData)
	// if err != nil {
	// 	log.Println("Failed to unmarshal certificate JSON:", err) // 添加日志
	// 	// return nil, err
	// }
	certData.CertID = crt.SerialNumber.String()
	certData.DNSNames = crt.DNSNames
	certData.NotAfter = crt.NotAfter
	certData.NotBefore = crt.NotBefore
	// retrun crt
	// fmt.Printf("证书信息:\n")
	// fmt.Printf("  主题: %s\n", cert.Subject.String())
	// fmt.Printf("  颁发者: %s\n", cert.Issuer.String())
	// fmt.Printf("  验证码: %s\n", cert.SerialNumber.String()) // 修改为获取序列号
	// fmt.Printf("  到期日: %s\n", cert.NotAfter.String())
	// fmt.Printf("  起始日: %s\n", cert.NotBefore.String())
	// fmt.Println(cert.DNSNames)
	// fmt.Println(cert.PublicKey)
	// fmt.Println(cert.Signature)
	// fmt.Println(cert.SignatureAlgorithm.String())

	// fmt.Printf("证书信息:\n")
	// for _, ext := range cert.Extensions {
	// 	fmt.Printf("%x: %s\n", ext.Id, string(ext.Value))
	// }
	return &certData, nil
}
