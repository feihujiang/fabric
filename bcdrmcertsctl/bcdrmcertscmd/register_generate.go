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
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

var (
	AttrsFile string
)

// Cmd returns the Cobra Command for Version
func RegisterCmd() *cobra.Command {
	// Set the flags on the node start command.
	flags := registerCommand.Flags()
	flags.StringVarP(&AttrsFile, "attrs-file", "a", "", "the file of certifacte attributes")
	flags.StringVarP(&CertificatesAddr, "certificates-addr", "c", "127.0.0.1:7054", "the address of certificates endpoint")
	flags.StringVarP(&RegisterAddr, "register-addr", "r", "127.0.0.1:9091", "the address of register endpoint")
	return registerCommand
}

var registerCommand = &cobra.Command{
	Use:   "register-generate",
	Short: "register-generate cmd.",
	Long:  `Register user.`,
	Run: func(cmd *cobra.Command, args []string) {
		//		GetECACert(cmd)
		RegisterAndGenerate(cmd, args)
	},
}

func RegisterAndGenerate(cmd *cobra.Command, args []string) error {
	// Check for arguments
	if len(args) != 0 {
		return errors.New("Args not supported\n")
	}
	fmt.Printf("the file of certifacte attributes: %s\n", AttrsFile)
	certAttrsRaw, err := ioutil.ReadFile(AttrsFile)
	if err != nil {
		fmt.Printf("ReadFile error: %v", err)
		return err
	}
	name, token, err := RegisterUser(certAttrsRaw)
	if err != nil {
		fmt.Printf("RegisterUser error: %v\n", err)
		return err
	}

	user := User{enrollID: name, enrollPwd: []byte(token)}
	err = EnrollUser(&user)
	if err != nil {
		return fmt.Errorf("Error GenerateCertificate: %s/n", err)
	}
	return nil
}
