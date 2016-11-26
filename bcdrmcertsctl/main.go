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

package main

import (
	"fmt"
	"os"

	"github.com/op/go-logging"
	"github.com/hyperledger/fabric/bcdrmcertsctl/bcdrmcertscmd"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/spf13/cobra"
)

var logger = logging.MustGetLogger("main")

// Constants go here.
const fabric = "hyperledger"
const cmdRoot = "core"

// The main command describes the service and
// defaults to printing the help message.
var mainCmd = &cobra.Command{
	Use: "Bcdrm",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

func main() {
	// Define command-line flags that are valid for all peer commands and
	// subcommands.
	//	mainFlags := mainCmd.PersistentFlags()
	//	mainFlags.BoolVarP(&versionFlag, "version", "v", false, "Display current version of fabric peer server")

	//	mainFlags.String("logging-level", "", "Default logging level and overrides, see core.yaml for full syntax")
	mainCmd.AddCommand(bcdrmcertscmd.RegisterCmd())
	mainCmd.AddCommand(bcdrmcertscmd.GetEcaCmd())
	mainCmd.AddCommand(bcdrmcertscmd.RestRegisterCmd())
	mainCmd.AddCommand(bcdrmcertscmd.GenerateCmd())

	// Init the crypto layer
	if err := crypto.Init(); err != nil {
		panic(fmt.Errorf("Failed to initialize the crypto layer: %s", err))
	}

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
	logger.Info("Exiting.....")
}
