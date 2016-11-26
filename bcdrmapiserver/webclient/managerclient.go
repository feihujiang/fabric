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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	client := &http.Client{}
	certAttrsJson := `{"type":1, "userCert":{"userType":1, "enrollmentID":"User1995", "systemRole":1}}`
	resp, err := client.Post("http://127.0.0.1:9091/register", "application/json", bytes.NewReader([]byte(certAttrsJson)))
	if err != nil {
		fmt.Printf("Failed to get from the server: %s", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}
