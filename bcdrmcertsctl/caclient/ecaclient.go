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

package caclient

import (
	"fmt"

	"google.golang.org/grpc"

	"github.com/hyperledger/fabric/core/comm"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
)

func GetECAPClient(memberSrvcAddress string) (pb.ECAPClient, error) {
	clientConn, err := newMemberSrvcClientConnection(memberSrvcAddress)
	if err != nil {
		return nil, fmt.Errorf("Error trying to connect to local peer: %s", err)
	}
	eCAPClient := pb.NewECAPClient(clientConn)
	return eCAPClient, nil
}

func GetECAAClient(memberSrvcAddress string) (pb.ECAAClient, error) {
	clientConn, err := newMemberSrvcClientConnection(memberSrvcAddress)
	if err != nil {
		return nil, fmt.Errorf("Error trying to connect to local peer: %s", err)
	}
	eCAAClient := pb.NewECAAClient(clientConn)
	return eCAAClient, nil
}

func newMemberSrvcClientConnection(memberSrvcAddress string) (*grpc.ClientConn, error) {
	//	var memberSrvcAddress = getMemberSrvcAddress()
	//	if comm.TLSEnabled() {
	//		return comm.NewClientConnectionWithAddress(peerAddress, true, true, comm.InitTLSForPeer())
	//	}
	return comm.NewClientConnectionWithAddress(memberSrvcAddress, true, false, nil)
}

//func getMemberSrvcAddress() string {
//	if len(CertificatesAddr) != 0 {
//		return CertificatesAddr
//	}
//	return "127.0.0.1:7054"
//}
