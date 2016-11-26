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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

// restResult defines the response payload for a general REST interface request.
type RestResult struct {
	Status string `json:"status"`
	Name  string `json:",omitempty"`
	Token  string `json:",omitempty"`
	Error  string `json:",omitempty"`
}

var (
	RegisterAddr string
)

// Cmd returns the Cobra Command for Version
func RestRegisterCmd() *cobra.Command {
	// Set the flags on the register command.
	flags := restRegisterCommand.Flags()
	flags.StringVarP(&AttrsFile, "attrs-file", "a", "", "the file of certifacte attributes")
	flags.StringVarP(&RegisterAddr, "register-addr", "r", "127.0.0.1:9091", "the address of register endpoint")
	return restRegisterCommand
}

var restRegisterCommand = &cobra.Command{
	Use:   "register",
	Short: "register cmd.",
	Long:  `Register user.`,
	Run: func(cmd *cobra.Command, args []string) {
		RestRegisterUser(cmd, args)
	},
}

func RestRegisterUser(cmd *cobra.Command, args []string) error {
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
	if _, _, err = RegisterUser(certAttrsRaw); err != nil {
		fmt.Printf("error: %v", err)
	}
	return nil
}

func RegisterUser(user []byte) (name string, token string, err error) {

	client := http.DefaultClient
	resp, err := client.Post("http://"+RegisterAddr+"/register", "application/json", bytes.NewReader(user))
	if err != nil {
		fmt.Printf("Failed to register: %s\n", err)
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	result := RestResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		//	if err := json.Unmarshal(certAttrsRaw, &certAttrs); err != nil {
		return "", "", fmt.Errorf("unexpected error: %v", err)
	}
	if strings.EqualFold(result.Status, "failed") {
		return "", "", fmt.Errorf(result.Error)
	}

	fmt.Println(string(body))
	fmt.Printf("Register user successfully\n")
	err = ioutil.WriteFile(result.Name+".tok", []byte(result.Token), 0700)
	if err != nil {
		return "", "", err
	}
	return result.Name, result.Token, nil
}
