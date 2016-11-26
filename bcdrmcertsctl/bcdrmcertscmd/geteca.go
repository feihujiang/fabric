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
	"fmt"
	"io/ioutil"

	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/bcdrmcertsctl/caclient"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/spf13/cobra"
)

// Cmd returns the Cobra Command for Version
func GetEcaCmd() *cobra.Command {
	// Set the flags on the node start command.
	flags := ecaCommand.Flags()
	flags.StringVarP(&CertificatesAddr, "certificates-addr", "c", "", "the address of certificates endpoint")
	return ecaCommand
}

var ecaCommand = &cobra.Command{
	Use:   "geteca",
	Short: "geteca cmd.",
	Long:  `Get the certificate of ECA .`,
	Run: func(cmd *cobra.Command, args []string) {
		GetEcaCert(cmd)
	},
}

func GetEcaCert(cmd *cobra.Command) error {
	eCAPClient, err := caclient.GetECAPClient(CertificatesAddr)
	if err != nil {
		return fmt.Errorf("Error GetECAPClient")
	}

	empty := &pb.Empty{}
	cert, err := eCAPClient.ReadCACertificate(context.Background(), empty)
	if err != nil {
		return fmt.Errorf("Error ReadCACertificate")
	}

	//	fmt.Printf("ReadCACertificate DER: %s\n", cert)

	//	x509CACert, err := x509.ParseCertificate(cert.Cert)
	//	if err != nil {
	//		return fmt.Errorf("Error x509.ParseCertificate")
	//	}
	//	fmt.Printf("ReadCACertificate x509: %s\n", x509CACert)

	pemCACert := primitives.DERCertToPEM(cert.Cert)
	if err != nil {
		return fmt.Errorf("Error primitives.DERCertToPEM")
	}
	fmt.Printf("ReadCACertificate pemCACert:\n%s\n", pemCACert)
	err = ioutil.WriteFile("eca.cert", pemCACert, 0755)
	if err != nil {
		panic(fmt.Errorf("Fatal error when storing pemCACert: %s\n", err))
	}
	return nil
}

func ReadCertificatePair(id string) error {
	eCAPClient, err := caclient.GetECAPClient(CertificatesAddr)
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
