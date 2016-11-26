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

import "github.com/hyperledger/fabric/bcdrmapiserver/field"

// ValidateBcdrmCertAttrs tests if required fields in the BcdrmCertAttrs are set.
func ValidateBcdrmCertAttrs(certAttrs *BcdrmCertAttrs) field.ErrorList {
	allErrs := field.ErrorList{}
	if certAttrs.Type == UserCertType {
		allErrs = append(allErrs, ValidateUserCert(&(certAttrs.User), field.NewPath("userCert"))...)
	} else if certAttrs.Type == DeviceCertType {
		allErrs = append(allErrs, ValidateDeviceCert(&(certAttrs.Device), field.NewPath("deviceCert"))...)
	} else {
		allErrs = append(allErrs, field.Invalid(field.NewPath("type"), certAttrs.Type, "Only UserCertType:1 or DeviceCertType:2 could be set"))
	}
	return allErrs
}

func ValidateUserCert(user *UserCert, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if user == nil {
		allErrs = append(allErrs, field.Required(fldPath, "need to be set"))
		return allErrs
	}
	if user.UserType > 7 || user.UserType <= 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("userType"), user.UserType, "Only Distributor:1, CP:2, 3, EndUser:4, 5, 6, 7 could be set"))
	}

	if len(user.EnrollmentID) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("enrollmentID"), "need to be set"))
	}

	if user.SystemRole != 1 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("systemRole"), user.SystemRole, "Only Fabric client:1 could be set"))
	}
	return allErrs
}

func ValidateDeviceCert(device *DeviceCert, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if device == nil {
		allErrs = append(allErrs, field.Required(fldPath, "need to be set"))
		return allErrs
	}

	if device.DeviceType > 6 || device.DeviceType <= 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("deviceType"), device.DeviceType, "Only 1, 2, 3, 4, 5, 6 could be set"))
	}

	if len(device.EnrollmentID) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("enrollmentID"), "need to be set"))
	}

	if device.DeviceType != 4 && device.SystemRole != 1 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("systemRole"), device.SystemRole, "Only Fabric client:1 could be set"))
	} else if device.DeviceType == 4 && (device.SystemRole != 2 || device.SystemRole != 4) {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("systemRole"), device.SystemRole, "Only Fabric peer:2, validator:4 could be set"))
	}

	if device.DeviceType == 1 {
		allErrs = append(allErrs, ValidateBcdrmClientCertAttrs(&(device.ClientAttrs), fldPath.Child("bcdrmClientCertAttrs"))...)
	}
	return allErrs
}

func ValidateBcdrmClientCertAttrs(clientCertAttrs *BcdrmClientCertAttrs, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if clientCertAttrs == nil {
		allErrs = append(allErrs, field.Required(fldPath, "need to be set"))
		return allErrs
	}

	if clientCertAttrs.DeviceCertType != 1 && clientCertAttrs.DeviceCertType != 2 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("deviceCertType"), clientCertAttrs.DeviceCertType, "Only ModelCert:1, DeviceCert:2 could be set"))
	}

	if clientCertAttrs.DeviceCertType == 1 {
		if clientCertAttrs.SecurityLevel != 100 && clientCertAttrs.SecurityLevel != 200 && clientCertAttrs.SecurityLevel != 500 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("securityLevel"), clientCertAttrs.SecurityLevel, "Only 100, 200, 500 could be set"))
		}

		if len(clientCertAttrs.Manualfacturer) > 32 {
			allErrs = append(allErrs, field.TooLong(fldPath.Child("manualfacturer"), len(clientCertAttrs.Manualfacturer), 32))
		}

		if len(clientCertAttrs.ModelName) > 32 {
			allErrs = append(allErrs, field.TooLong(fldPath.Child("modelName"), len(clientCertAttrs.ModelName), 32))
		}
	}else if clientCertAttrs.DeviceCertType == 2 {
		if clientCertAttrs.SecurityLevel != 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("securityLevel"), clientCertAttrs.SecurityLevel, "Should not be set"))
		}
		
		if len(clientCertAttrs.Manualfacturer) != 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("manualfacturer"), clientCertAttrs.Manualfacturer, "Should not be set"))
		}
		
		if len(clientCertAttrs.ModelName) != 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("modelName"), clientCertAttrs.ModelName, "Should not be set"))			
		}
	}
	return allErrs
}
