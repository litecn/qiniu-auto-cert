package main

import (
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/litecn/qiniu-auto-cert/acme"
	"github.com/litecn/qiniu-auto-cert/qiniu"
	"github.com/pkg/errors"
)

var NotAfter *time.Time

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	NotAfter = timePtr(time.Now())
}

// 辅助函数：返回时间指针
func timePtr(t time.Time) *time.Time {
	return &t
}

func main() {
	// qnClient := qiniu.New(
	// 	os.Getenv("QINIU_ACCESSKEY"),
	// 	os.Getenv("QINIU_SECRETKEY"),
	// )

	Email := os.Getenv("EMAIL")
	Domains := os.Getenv("DOMAIN")
	// 使用正则表达式分割字符串
	re := regexp.MustCompile(`[,\s|]+`)
	Domain := re.Split(strings.TrimSpace(Domains), -1)

	if len(Domain) < 1 {
		log.Println("error: no domain")
		return
	}
	log.Println(Domain)
	// if err := autoCert(qnClient, Domain[0], Email); err != nil {
	// 	log.Println(err)
	// }
	// for range time.Tick(time.Hour * 3) {
	// 	if err := autoCert(qnClient, Domain[0], Email); err != nil {
	// 		log.Println(err)
	// 	}
	// }
	cert, err := acme.LoadCertResource(Domain[0])
	if err != nil {
		if NotAfter, err = obtainCert(Domain, Email, NotAfter); err != nil {
			log.Println(err)
		}
	} else {
		certInfo, err := acme.GetCertInfo(*cert)
		log.Printf("证书信息:\n")
		log.Printf("  序列号: %s\n", certInfo.CertID)
		log.Printf("  域名: %s\n", certInfo.DNSNames)
		log.Printf("  到期日: %s\n", certInfo.NotAfter.String())
		log.Printf("  起始日: %s\n", certInfo.NotBefore.String())
		if err != nil {
			if NotAfter, err = obtainCert(Domain, Email, NotAfter); err != nil {
				log.Println(err)
			}
		}
		NotAfter = &certInfo.NotAfter
	}
	for range time.Tick(time.Hour * 3) {
		if NotAfter, err = obtainCert(Domain, Email, NotAfter); err != nil {
			log.Println(err)
		}
	}

}

func autoCert(qnClient *qiniu.Client, Domain, Email string) error {
	domainInfo, err := qnClient.GetDomainInfo(Domain)
	if err != nil {
		log.Fatalln(err)
	}
	if domainInfo.HTTPS.CertID != "" {
		info, err := qnClient.GetCertInfo(domainInfo.HTTPS.CertID)
		if err != nil {
			return errors.WithMessage(err, "get cert info failed")
		}
		if time.Until(info.Cert.NotAfter.Time) > time.Hour*24*30 {
			return nil
		}
		upload, err := obtainAndUploadCert(qnClient, Domain, Email)
		if err != nil {
			return errors.WithMessage(err, "obtain and upload cert failed")
		}
		_, err = qnClient.UpdateHttpsConf(Domain, upload.CertID)
		if err != nil {
			return errors.WithMessage(err, "update domain certID failed")
		}
		_, err = qnClient.DeleteCert(domainInfo.HTTPS.CertID)
		return errors.WithMessage(err, "delete cert failed")
	}
	upload, err := obtainAndUploadCert(qnClient, Domain, Email)
	if err != nil {
		return errors.WithMessage(err, "obtain and upload cert failed")
	}
	_, err = qnClient.DomainSSLize(Domain, upload.CertID)
	return errors.WithMessage(err, "sslize domain failed")
}

func obtainAndUploadCert(qnClient *qiniu.Client, Domain string, Email string) (*qiniu.UploadCertResp, error) {
	cert, err := acme.ObtainCert(Email, []string{Domain})
	if err != nil {
		return nil, err
	}
	upload, err := qnClient.UploadCert(qiniu.Cert{
		Name:       strings.Split(Domain, ".")[0],
		CommonName: Domain,
		CA:         string(cert.Certificate),
		Pri:        string(cert.PrivateKey),
	})
	if err != nil {
		return nil, err
	}
	return upload, nil
}

func obtainCert(Domain []string, Email string, NotAfter *time.Time) (*time.Time, error) {
	// log.Println(NotAfter.Local().Format("2006-01-02 15:04:06"), time.Until(*NotAfter))
	if time.Until(*NotAfter) > time.Hour*24*30 {
		log.Println("not not after", NotAfter.String())
		return NotAfter, nil
	}
	cert, err := acme.ObtainCert(Email, Domain)
	if err != nil {
		log.Println("cert error:", err)
		return NotAfter, err
	}
	certInfo, err := acme.GetCertInfo(*cert)
	if err != nil {
		log.Println("cert info error:", err)
		return NotAfter, err
	}
	NotAfter = &certInfo.NotAfter
	return NotAfter, nil
}
