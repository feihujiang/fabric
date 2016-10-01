/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package membersrvc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/core/comm"
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
	testAdmin = User{enrollID: "WebAppAdmin", enrollPwd: []byte("DJY27pEnl16d")}
	testUser  = User{enrollID: "testUserFlyTigering", role: 1, affiliation: "institution_a"}
)

var (
	// ECertSubjectRole is the ASN1 object identifier of the subject's role.
	//
	ECertSubjectRole = asn1.ObjectIdentifier{2, 1, 3, 4, 5, 6, 7}
)

// Cmd returns the Cobra Command for Version
func Cmd() *cobra.Command {
	return cobraCommand
}

var cobraCommand = &cobra.Command{
	Use:   "membersrvc <username>",
	Short: "membersrvc cmd.",
	Long:  `Register user.`,
	Run: func(cmd *cobra.Command, args []string) {
		//		GetECACert(cmd)
		RegisterUser(cmd, args)
	},
}

func RegisterUser(cmd *cobra.Command, args []string) error {
	// Check for username argument
	if len(args) == 0 {
		ReadECACert()
		fmt.Printf("Must supply username")
		return errors.New("Must supply username")
	}

	// Check for other extraneous arguments
	if len(args) != 1 {
		ReadCertificatePair(args[0])
		//		fmt.Printf("Must supply username as the 1st and only parameter")
		//		return errors.New("Must supply username as the 1st and only parameter")
		return nil

	}
	testUser.enrollID = args[0]
	err := setSignPrivKey(&testAdmin)
	if err != nil {
		fmt.Printf("RegisterUser error: %s\n", err)
		return err
	}

	path := "/var/hyperledger/production/crypto/client/WebAppAdmin/ks/raw/enrollment.key"
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("ReadFile err: %s\n", err)
		return err
	}

	privateKey, err := primitives.PEMtoPrivateKey(raw, nil)
	if err != nil {
		fmt.Printf("PEMtoPrivateKey err: %s\n", err)
		return err
	}
	testAdmin.enrollPrivKey = privateKey.(*ecdsa.PrivateKey)

	//	err := enrollUser(&testAdmin)
	//	if err != nil {
	//		fmt.Printf("enrollUser error: %s\n", err)
	//		return err
	//	}

	err = registerUser(testAdmin, &testUser)

	if err != nil {
		fmt.Printf("RegisterUser error: %s\n", err)
		return err
	}
	return nil
}

func registerUser(registrar User, user *User) error {
	eCAAClient, err := GetECAAClient()
	if err != nil {
		return fmt.Errorf("Error GetECAAClient")
	}

	//create req
	req := &pb.RegisterUserReq{
		Id:          &pb.Identity{Id: user.enrollID},
		Role:        pb.Role(user.role),
		Affiliation: user.affiliation,
		Registrar: &pb.Registrar{
			Id:            &pb.Identity{Id: registrar.enrollID},
			Roles:         user.registrarRoles,
			DelegateRoles: user.registrarDelegateRoles,
		},
		Sig: nil}

	//sign the req
	hash := primitives.NewHash()
	raw, _ := proto.Marshal(req)
	hash.Write(raw)

	//jfh sign
	//	sec, err := crypto.InitClient("admin", nil)
	//	if err != nil {
	//		fmt.Printf("InitClient err: %s\n", err)
	//	}

	//	// Obtain the client CertificateHandler
	//	handler, err := sec.GetEnrollmentCertificateHandler()
	//	if err != nil {
	//		fmt.Printf("GetEnrollmentCertificateHandler err: %s\n", err)
	//	}
	//	req.Sig, err = handler.Sign(hash.Sum(nil))
	//	if err != nil {
	//		fmt.Printf("handler.Sign err: %s\n", err)
	//	}

	r, s, err := ecdsa.Sign(rand.Reader, registrar.enrollPrivKey, hash.Sum(nil))
	if err != nil {
		msg := "Failed to register user. Error (ECDSA) signing request: " + err.Error()
		return errors.New(msg)
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}

	//	req.Sig = nil

	token, err := eCAAClient.RegisterUser(context.Background(), req)

	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("Failed to obtain token")
	}

	fmt.Printf("registerUser: %s\n", token)

	user.enrollPwd = token.Tok

	//	enrollUser(user)

	return nil

}

func setSignPrivKey(user *User) error {
	// Phase 1 of the protocol: Generate crypto material
	signPriv, err := primitives.NewECDSAKey()
	user.enrollPrivKey = signPriv
	if err != nil {
		return err
	}
	return nil
}

func enrollUser(user *User) error {
	eCAPClient, err := GetECAPClient()
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

	// Verify we got valid crypto material back
	x509SignCert, err := primitives.DERToX509Certificate(resp.Certs.Sign)
	if err != nil {
		return err
	}

	_, err = primitives.GetCriticalExtension(x509SignCert, ECertSubjectRole)
	if err != nil {
		return err
	}

	x509EncCert, err := primitives.DERToX509Certificate(resp.Certs.Enc)
	if err != nil {
		return err
	}

	fmt.Printf("x509EncCert: %s\n", x509EncCert)

	_, err = primitives.GetCriticalExtension(x509EncCert, ECertSubjectRole)
	if err != nil {
		return err
	}

	fmt.Printf("CreateCertificatePair: %s\n", resp.Certs)

	return nil
}

func ReadCertificatePair(id string) error {
	eCAPClient, err := GetECAPClient()
	if err != nil {
		return fmt.Errorf("Error GetECAPClient")
	}

	fmt.Printf("id: %s\n", id)
	req := &pb.ECertReadReq{Id: &pb.Identity{Id: "testUser"}}

	certPair, err := eCAPClient.ReadCertificatePair(context.Background(), req)
	if err != nil {
		fmt.Printf("Error ReadCertificatePair, err: %s", err)
		return fmt.Errorf("Error ReadCertificatePair")
	}
	fmt.Printf("certPair: %s\n", certPair)
	return nil
}

func ReadECACert() error {
	eCAPClient, err := GetECAPClient()
	if err != nil {
		return fmt.Errorf("Error GetECAPClient")
	}

	empty := &pb.Empty{}
	cert, err := eCAPClient.ReadCACertificate(context.Background(), empty)
	if err != nil {
		return fmt.Errorf("Error ReadCACertificate")
	}

	fmt.Printf("ReadCACertificate: %s\n", cert)
	return nil
}

// GetDevopsClient returns a new client connection for this peer
func GetECAPClient() (pb.ECAPClient, error) {
	clientConn, err := newMemberSrvcClientConnection()
	if err != nil {
		return nil, fmt.Errorf("Error trying to connect to local peer: %s", err)
	}
	eCAPClient := pb.NewECAPClient(clientConn)
	return eCAPClient, nil
}

// GetDevopsClient returns a new client connection for this peer
func GetECAAClient() (pb.ECAAClient, error) {
	clientConn, err := newMemberSrvcClientConnection()
	if err != nil {
		return nil, fmt.Errorf("Error trying to connect to local peer: %s", err)
	}
	eCAAClient := pb.NewECAAClient(clientConn)
	return eCAAClient, nil
}

func newMemberSrvcClientConnection() (*grpc.ClientConn, error) {
	var memberSrvcAddress = getMemberSrvcAddress()
	//	if comm.TLSEnabled() {
	//		return comm.NewClientConnectionWithAddress(peerAddress, true, true, comm.InitTLSForPeer())
	//	}
	return comm.NewClientConnectionWithAddress(memberSrvcAddress, true, false, nil)
}

func getMemberSrvcAddress() string {
	return "127.0.0.1:7054"
}
