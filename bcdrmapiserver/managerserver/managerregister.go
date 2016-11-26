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

package managerserver

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"golang.org/x/net/context"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/bcdrmcertsctl/caclient"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
)

var (
	CaAddr string
)

func GetRegister(enrollId, privateKeyPath string) (User, error) {
	//	path := "/var/hyperledger/production/crypto/client/WebAppAdmin/ks/raw/enrollment.key"
	raw, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Printf("ReadFile err: %s\n", err)
		return User{}, err
	}

	privateKey, err := primitives.PEMtoPrivateKey(raw, nil)
	if err != nil {
		fmt.Printf("PEMtoPrivateKey err: %s\n", err)
		return User{}, err
	}
	registrarAdmin := User{enrollID: enrollId, enrollPrivKey: privateKey.(*ecdsa.PrivateKey)}
	return registrarAdmin, nil
}

func RegisterUser(registrar User, userInformation string) (string, string, error) {
	attributes, user, err := getAttributes(userInformation)

	if err != nil {
		return "", "", fmt.Errorf("Validate certifacte attributes: %s\n", err)
	}

	eCAAClient, err := caclient.GetECAAClient(CaAddr)
	if err != nil {
		return "", "", fmt.Errorf("Error GetECAAClient")
	}

	//create req
	req := &pb.RegisterUserReq{
		Id:          &pb.Identity{Id: user.enrollID},
		Role:        pb.Role(user.role),
		Attributes:  attributes,
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

	r, s, err := ecdsa.Sign(rand.Reader, registrar.enrollPrivKey, hash.Sum(nil))
	if err != nil {
		msg := "Failed to register user. Error (ECDSA) signing request: " + err.Error()
		return "", "", errors.New(msg)
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}

	token, err := eCAAClient.RegisterUser(context.Background(), req)
	if err != nil {
		return "", "", err
	}

	if token == nil {
		return "", "", errors.New("Failed to obtain token")
	}
	fmt.Printf("Register user to membersrvc successfully\n")
	fmt.Printf("User: %s Token: %s\n", user.enrollID, string(token.Tok))

	//	err = ioutil.WriteFile(user.enrollID+".tok", token.Tok, 0700)
	//	if err != nil {
	//		return "", "", err
	//	}
	return user.enrollID, string(token.Tok), nil
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

func getAttributes(userInformation string) ([]*pb.Attribute, *User, error) {
	certAttrsJson := userInformation

	certAttrs := BcdrmCertAttrs{}
	if err := json.Unmarshal([]byte(certAttrsJson), &certAttrs); err != nil {
		//	if err := json.Unmarshal(certAttrsRaw, &certAttrs); err != nil {
		return nil, nil, fmt.Errorf("unexpected error: %v", err)
	}

	aggr := ValidateBcdrmCertAttrs(&certAttrs).ToAggregate()
	if aggr != nil {
		return nil, nil, fmt.Errorf("Error: %v", aggr)
	}

	user := User{}
	if certAttrs.Type == UserCertType {
		userCertAttrs := certAttrs
		fmt.Printf("bcdrmCertAttrs.Type: %d\n", userCertAttrs.Type)
		fmt.Printf("bcdrmCertAttrs.UserCert.UserType: %d\n", userCertAttrs.User.UserType)
		fmt.Printf("bcdrmCertAttrs.UserCert.enrollmentID: %s\n", userCertAttrs.User.EnrollmentID)
		fmt.Printf("bcdrmCertAttrs.UserCert.SystemRole: %d\n", userCertAttrs.User.SystemRole)

		user.enrollID = userCertAttrs.User.EnrollmentID
		user.role = userCertAttrs.User.SystemRole
		user.affiliation = "institution_a"

	} else if certAttrs.Type == DeviceCertType {

		deviceCertAttrs := certAttrs
		fmt.Printf("bcdrmCertAttrs.Type: %d\n", deviceCertAttrs.Type)
		fmt.Printf("bcdrmCertAttrs.Device.DeviceType: %d\n", deviceCertAttrs.Device.DeviceType)
		fmt.Printf("bcdrmCertAttrs.Device.EnrollmentID: %s\n", deviceCertAttrs.Device.EnrollmentID)
		fmt.Printf("bcdrmCertAttrs.Device.SystemRole: %d\n", deviceCertAttrs.Device.SystemRole)
		fmt.Printf("bcdrmCertAttrs.Device.ClientAttrs.DeviceCertType: %d\n", deviceCertAttrs.Device.ClientAttrs.DeviceCertType)
		fmt.Printf("bcdrmCertAttrs.Device.ClientAttrs.SecurityLevel: %d\n", deviceCertAttrs.Device.ClientAttrs.SecurityLevel)
		fmt.Printf("bcdrmCertAttrs.Device.ClientAttrs.Manualfacturer: %s\n", deviceCertAttrs.Device.ClientAttrs.Manualfacturer)
		fmt.Printf("bcdrmCertAttrs.Device.ClientAttrs.ModelName: %s\n", deviceCertAttrs.Device.ClientAttrs.ModelName)

		user.enrollID = deviceCertAttrs.Device.EnrollmentID
		user.role = deviceCertAttrs.Device.SystemRole
		user.affiliation = "institution_a"
	} else {
		return nil, nil, fmt.Errorf("Error certificate type")
	}

	fmt.Printf("certAttrsJson: %s\n", certAttrsJson)

	var attributes []*pb.Attribute
	attributes = append(attributes, &pb.Attribute{Name: "bcdrmAttributes", Value: certAttrsJson})
	return attributes, &user, nil
}
