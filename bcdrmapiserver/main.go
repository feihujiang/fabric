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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocraft/web"
	"github.com/hyperledger/fabric/bcdrmapiserver/managerserver"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

// Rest API description http://127.0.0.1:9091/register
//    {
//      "method": "POST",
//      "summary": "register a user",
//      "parameters": [
//       {
//        "type": "BcdrmCertAttrs",
//        "paramType": "body",
//        "required": true
//       }
//      ],
//      "responseMessages": [
//       {
//        "code": 200,
//        "responseModel": "RestResult"
//       }
//      ],
//      "produces": [
//       "application/json",
//      ],
//      "consumes": [
//       "application/json",
//      ]
//     }

var restLogger = logging.MustGetLogger("rest")
var RegisterAdmin managerserver.User

func main() {
	fmt.Printf("Server start!\n")
	ReadConfig()
	// Init the crypto layer
	if err := crypto.Init(); err != nil {
		panic(fmt.Errorf("Failed to initialize the crypto layer: %s", err))
	}
	//	startHttpServer()
	startRestRegisterServer()
}

func ReadConfig() {
	viper.SetEnvPrefix("MANAGERSERVER")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("managerconfig")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	// Path to look for the config file based on GOPATH
	gopath := os.Getenv("GOPATH")
	for _, p := range filepath.SplitList(gopath) {
		cfgpath := filepath.Join(p, "src/github.com/hyperledger/fabric/bcdrmapiserver")
		fmt.Printf("cfgpath: %s\n", cfgpath)
		viper.AddConfigPath(cfgpath)
	}

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error when reading %s config file: %s\n", "managerserver", err))
	}
	fmt.Printf("Get server.address: %s from config\n", viper.GetString("server.address"))
	
	managerserver.CaAddr = viper.GetString("ca.address")
	fmt.Printf("Get ca.address: %s from config\n", viper.GetString("ca.address"))	

	getRegisterFromconfig()
}

func getRegisterFromconfig() {
	enrollId := viper.GetString("eca.registrar.enrollId")
	privateKeyPath := viper.GetString("eca.registrar.privatekeypath")
	
	if len(enrollId) == 0 || len(privateKeyPath) == 0 {
		panic(fmt.Errorf("Must set register enrollId and privateKeyPath"))
	}
	register, err := managerserver.GetRegister(enrollId, privateKeyPath)
	if err != nil {
		panic(fmt.Errorf("Get register failed: %s", err))
	}
	RegisterAdmin = register
	fmt.Printf("registrar id: %s\nprivateKeyPath: %s\n", enrollId, privateKeyPath)
}

func startRestRegisterServer() {
	router := buildRESTRouter()
	// Start server
	err := http.ListenAndServe(viper.GetString("server.address"), router)
	if err != nil {
		restLogger.Errorf("ListenAndServe: %s", err)
	}
}

func buildRESTRouter() *web.Router {
	router := web.New(ServerRegisterREST{})

	// Add middleware
	router.Middleware((*ServerRegisterREST).SetRegister)
	router.Middleware((*ServerRegisterREST).SetResponseType)

	// Add routes
	router.Post("/register", (*ServerRegisterREST).Register)
	// Add not found page
	router.NotFound((*ServerRegisterREST).NotFound)
	return router
}

type ServerRegisterREST struct {
	RegisterAdmin managerserver.User
}

// RestResult defines the response payload for a general REST interface request.
type RestResult struct {
	Status string `json:"status"`
	Name   string `json:",omitempty"`
	Token  string `json:",omitempty"`
	Error  string `json:",omitempty"`
}

// Register a user with an administrator user
func (s *ServerRegisterREST) Register(rw web.ResponseWriter, req *web.Request) {
	restLogger.Info("REST Register...")
	encoder := json.NewEncoder(rw)

	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(RestResult{Status: fmt.Sprintf("failed"), Error: fmt.Sprintf("%s", err)})
		return
	}

	name, token, err := managerserver.RegisterUser(s.RegisterAdmin, string(reqBody))
	if err != nil {
		encoder.Encode(RestResult{Status: fmt.Sprintf("failed"), Error: fmt.Sprintf("%s", err)})
		return
	}
	rw.WriteHeader(http.StatusOK)
	encoder.Encode(RestResult{Status: fmt.Sprintf("successful"), Name: name, Token: token})
}

func (s *ServerRegisterREST) NotFound(rw web.ResponseWriter, r *web.Request) {
	rw.WriteHeader(http.StatusNotFound)
	json.NewEncoder(rw).Encode(RestResult{Error: "endpoint not found."})
}

// SetResponseType is a middleware function that sets the appropriate response
// headers. Currently, it is setting the "Content-Type" to "application/json"
func (s *ServerRegisterREST) SetResponseType(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	rw.Header().Set("Content-Type", "application/json")
	next(rw, req)
}

func (s *ServerRegisterREST) SetRegister(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	s.RegisterAdmin = RegisterAdmin
	next(rw, req)
}
