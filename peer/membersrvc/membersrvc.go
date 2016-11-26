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
	"encoding/asn1"

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
		return nil
	}
	return nil
}
