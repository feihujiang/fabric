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
	"bytes"
	"fmt"
)

// Path represents the path from some root to a particular field.
type Path struct {
	name   string // the name of this field or "" if this is an index
	index  string 
	parent *Path  // nil if this is the root element
}

// NewPath creates a root Path object.
func NewPath(name string, moreNames ...string) *Path {
	r := &Path{name: name, parent: nil}
	for _, anotherName := range moreNames {
		r = &Path{name: anotherName, parent: r}
	}
	return r
}

// Root returns the root element of this Path.
func (p *Path) Root() *Path {
	for ; p.parent != nil; p = p.parent {
		// Do nothing.
	}
	return p
}

// Child creates a new Path that is a child of the method receiver.
func (p *Path) Child(name string, moreNames ...string) *Path {
	r := NewPath(name, moreNames...)
	r.Root().parent = p
	return r
}

// String produces a string representation of the Path.
func (p *Path) String() string {
	// make a slice to iterate
	elems := []*Path{}
	for ; p != nil; p = p.parent {
		elems = append(elems, p)
	}

	// iterate, but it has to be backwards
	buf := bytes.NewBuffer(nil)
	for i := range elems {
		p := elems[len(elems)-1-i]
		if p.parent != nil && len(p.name) > 0 {
			// This is either the root or it is a subscript.
			buf.WriteString(".")
		}
		if len(p.name) > 0 {
			buf.WriteString(p.name)
		} else {
			fmt.Fprintf(buf, "[%s]", p.index)
		}
	}
	return buf.String()
}
