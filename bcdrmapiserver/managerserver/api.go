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

import "crypto/ecdsa"

type User struct {
	enrollID               string
	enrollPwd              []byte
	enrollPrivKey          *ecdsa.PrivateKey
	role                   int
	affiliation            string
	registrarRoles         []string
	registrarDelegateRoles []string
}

type UserCert struct {
	UserType     int    `json:"userType"`
	EnrollmentID string `json:"enrollmentID"`
	SystemRole   int    `json:"systemRole"`
}

type BcdrmClientCertAttrs struct {
	DeviceCertType int    `json:"deviceCertType"`
	SecurityLevel  int    `json:"securityLevel"`
	Manualfacturer string `json:"manualfacturer"`
	ModelName      string `json:"modelName"`
}

type DeviceCert struct {
	DeviceType   int                  `json:"deviceType"`
	EnrollmentID string               `json:"enrollmentID"`
	SystemRole   int                  `json:"systemRole"`
	ClientAttrs  BcdrmClientCertAttrs `json:"bcdrmClientCertAttrs"`
}

type BcdrmCertAttrs struct {
	Type   int        `json:"type,omitempty"`
	User   UserCert   `json:"userCert,omitempty"`
	Device DeviceCert `json:"deviceCert,omitempty"`
}

const (
	UserCertType   = 1
	DeviceCertType = 2
)
