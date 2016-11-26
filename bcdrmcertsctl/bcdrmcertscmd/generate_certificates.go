/*
Copyright Huawei Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bcdrmcertscmd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/net/context"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/bcdrmcertsctl/caclient"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/primitives/ecies"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/spf13/cobra"
)

type User struct {
	enrollID               string
	enrollPwd              []byte
	enrollPrivKey          *ecdsa.PrivateKey
	role                   int
	affiliation            string
	registrarRoles         []string
	registrarDelegateRoles []string
}

var (
	// ECertSubjectRole is the ASN1 object identifier of the subject's role.
	ECertSubjectRole = asn1.ObjectIdentifier{2, 1, 3, 4, 5, 6, 7}
	Name             string
	Token            string
)

// Cmd returns the Cobra Command for Version
func GenerateCmd() *cobra.Command {
	// Set the flags on the node start command.
	flags := generateCommand.Flags()
	flags.StringVarP(&CertificatesAddr, "certificates-addr", "c", "127.0.0.1:7054", "the address of certificates endpoint")
	flags.StringVarP(&Name, "user-name", "n", "", "the name of the user")
	flags.StringVarP(&Token, "user-token", "t", "", "the token of the user")
	return generateCommand
}

var generateCommand = &cobra.Command{
	Use:   "generate",
	Short: "generate cmd.",
	Long:  `generate certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		GenerateCertificate()
	},
}

func GenerateCertificate() error {
	if len(Name) == 0 {
		return fmt.Errorf("Name is needed")
	}
	if len(Token) == 0 {
		return fmt.Errorf("Token is needed")
	}
	user := User{enrollID: Name, enrollPwd: []byte(Token)}
	err := EnrollUser(&user)
	if err != nil {
		return fmt.Errorf("Error GenerateCertificate: %s/n", err)
	}
	return nil
}

func EnrollUser(user *User) error {
	eCAPClient, err := caclient.GetECAPClient(CertificatesAddr)
	if err != nil {
		return fmt.Errorf("Error GetECAPClient")
	}
	// Phase 1 of the protocol: Generate crypto material
	signPriv, err := primitives.NewECDSAKey()
	user.enrollPrivKey = signPriv
	if err != nil {
		return err
	}
	signPub, err := x509.MarshalPKIXPublicKey(&signPriv.PublicKey)
	if err != nil {
		return err
	}

	encPriv, err := primitives.NewECDSAKey()
	if err != nil {
		return err
	}
	encPub, err := x509.MarshalPKIXPublicKey(&encPriv.PublicKey)
	if err != nil {
		return err
	}

	req := &pb.ECertCreateReq{
		Ts:   &timestamp.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
		Id:   &pb.Identity{Id: user.enrollID},
		Tok:  &pb.Token{Tok: user.enrollPwd},
		Sign: &pb.PublicKey{Type: pb.CryptoType_ECDSA, Key: signPub},
		Enc:  &pb.PublicKey{Type: pb.CryptoType_ECDSA, Key: encPub},
		Sig:  nil}

	resp, err := eCAPClient.CreateCertificatePair(context.Background(), req)
	if err != nil {
		return err
	}

	//Phase 2 of the protocol
	spi := ecies.NewSPI()
	eciesKey, err := spi.NewPrivateKey(nil, encPriv)
	if err != nil {
		return err
	}

	ecies, err := spi.NewAsymmetricCipherFromPublicKey(eciesKey)
	if err != nil {
		return err
	}

	out, err := ecies.Process(resp.Tok.Tok)
	if err != nil {
		return err
	}

	req.Tok.Tok = out
	req.Sig = nil

	hash := primitives.NewHash()
	raw, _ := proto.Marshal(req)
	hash.Write(raw)

	r, s, err := ecdsa.Sign(rand.Reader, signPriv, hash.Sum(nil))
	if err != nil {
		return err
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}

	resp, err = eCAPClient.CreateCertificatePair(context.Background(), req)
	if err != nil {
		return err
	}

	rawSignPriv, err := primitives.PrivateKeyToPEM(signPriv, nil)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(user.enrollID+".sign.pem", rawSignPriv, 0700)
	if err != nil {
		return err
	}
	//	rawSignPub, err := primitives.PublicKeyToPEM(&signPriv.PublicKey, nil)
	//	if err != nil {
	//		return err
	//	}
	//	err = ioutil.WriteFile(user.enrollID+".sign.pub", rawSignPub, 0700)
	//	if err != nil {
	//		return err
	//	}

	rawEncKey, err := primitives.PrivateKeyToPEM(encPriv, nil)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(user.enrollID+".enc.pem", rawEncKey, 0700)
	if err != nil {
		return err
	}
	//	rawEncPub, err := primitives.PublicKeyToPEM(&encPriv.PublicKey, nil)
	//	if err != nil {
	//		return err
	//	}
	//	err = ioutil.WriteFile(user.enrollID+".enc.pub", rawEncPub, 0700)
	//	if err != nil {
	//		return err
	//	}

	// Verify we got valid crypto material back
	x509SignCert, err := primitives.DERToX509Certificate(resp.Certs.Sign)
	if err != nil {
		return err
	}
	fmt.Printf("x509SignCert.ExtraExtensions: %s\n", x509SignCert.ExtraExtensions)

	pemSignCert := primitives.DERCertToPEM(resp.Certs.Sign)
	if err != nil {
		return fmt.Errorf("Error primitives.DERCertToPEM")
	}
	err = ioutil.WriteFile(user.enrollID+".sign.cert", pemSignCert, 0755)
	if err != nil {
		panic(fmt.Errorf("Fatal error when storing pemCACert: %s\n", err))
	}

	_, err = primitives.GetCriticalExtension(x509SignCert, ECertSubjectRole)
	if err != nil {
		return err
	}

	x509EncCert, err := primitives.DERToX509Certificate(resp.Certs.Enc)
	if err != nil {
		return err
	}
	//	fmt.Printf("x509EncCert: %s\n", x509EncCert)

	pemCert := primitives.DERCertToPEM(resp.Certs.Enc)
	if err != nil {
		return fmt.Errorf("Error primitives.DERCertToPEM")
	}
	err = ioutil.WriteFile(user.enrollID+".enc.cert", pemCert, 0755)
	if err != nil {
		panic(fmt.Errorf("Fatal error when storing pemCACert: %s\n", err))
	}

	_, err = primitives.GetCriticalExtension(x509EncCert, ECertSubjectRole)
	if err != nil {
		return err
	}

	//	fmt.Printf("CreateCertificatePair: %s\n", resp.Certs)
	return nil
}
