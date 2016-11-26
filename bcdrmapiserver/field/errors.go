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

package field

import (
	"encoding/json"
	"fmt"
)

// Aggregate represents an object that contains multiple errors.
type Aggregate interface {
	error
	Errors() []error
}

// NewAggregate converts a slice of errors into an Aggregate interface.
// If the slice is empty, this returns nil.
func NewAggregate(errlist []error) Aggregate {
	if len(errlist) == 0 {
		return nil
	}
	return aggregate(errlist)
}

type aggregate []error

// Error is part of the error interface.
func (agg aggregate) Error() string {
	if len(agg) == 0 {
		// This should never happen, really.
		return ""
	}
	if len(agg) == 1 {
		return agg[0].Error()
	}
	result := fmt.Sprintf("[%s", agg[0].Error())
	for i := 1; i < len(agg); i++ {
		result += fmt.Sprintf(", %s", agg[i].Error())
	}
	result += "]"
	return result
}

// Errors is part of the Aggregate interface.
func (agg aggregate) Errors() []error {
	return []error(agg)
}

// Error is an implementation of the 'error' interface, which represents a
// field-level validation error.
type Error struct {
	Type     ErrorType
	Field    string
	BadValue interface{}
	Detail   string
}

var _ error = &Error{}

// Error implements the error interface.
func (v *Error) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.ErrorBody())
}

// ErrorBody returns the error message without the field name.  This is useful
// for building nice-looking higher-level error reporting.
func (v *Error) ErrorBody() string {
	var s string
	switch v.Type {
	case ErrorTypeRequired,  ErrorTypeTooLong:
		s = fmt.Sprintf("%s", v.Type)
	default:
		var bad string
		badBytes, err := json.Marshal(v.BadValue)
		if err != nil {
			bad = err.Error()
		} else {
			bad = string(badBytes)
		}
		s = fmt.Sprintf("%s: %s", v.Type, bad)
	}
	if len(v.Detail) != 0 {
		s += fmt.Sprintf(": %s", v.Detail)
	}
	return s
}

// ErrorType is a machine readable value providing more detail about why
// a field is invalid.
type ErrorType string

const (
	ErrorTypeRequired ErrorType = "FieldValueRequired"
	ErrorTypeInvalid ErrorType = "FieldValueInvalid"
	ErrorTypeTooLong ErrorType = "FieldValueTooLong"
)

// String converts a ErrorType into its corresponding canonical error message.
func (t ErrorType) String() string {
	switch t {
	case ErrorTypeRequired:
		return "Required value"
	case ErrorTypeInvalid:
		return "Invalid value"
	case ErrorTypeTooLong:
		return "Too long"
	default:
		panic(fmt.Sprintf("unrecognized validation error: %q", string(t)))
	}
}

// Required returns a *Error indicating "value required".
func Required(field *Path, detail string) *Error {
	return &Error{ErrorTypeRequired, field.String(), "", detail}
}

// Invalid returns a *Error indicating "invalid value".
func Invalid(field *Path, value interface{}, detail string) *Error {
	return &Error{ErrorTypeInvalid, field.String(), value, detail}
}

// TooLong returns a *Error indicating "too long".  This is used to
// report that the given value is too long.
func TooLong(field *Path, value interface{}, maxLength int) *Error {
	return &Error{ErrorTypeTooLong, field.String(), value, fmt.Sprintf("must have at most %d characters", maxLength)}
}

// ErrorList holds a set of Errors.
type ErrorList []*Error

// ToAggregate converts the ErrorList into an errors.Aggregate.
func (list ErrorList) ToAggregate() Aggregate {
	errs := make([]error, len(list))
	for i := range list {
		errs[i] = list[i]
	}
	return NewAggregate(errs)
}

func fromAggregate(agg Aggregate) ErrorList {
	errs := agg.Errors()
	list := make(ErrorList, len(errs))
	for i := range errs {
		list[i] = errs[i].(*Error)
	}
	return list
}
