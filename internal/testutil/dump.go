// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package testutil

import (
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tpm/legacy/tpm2"
)

// Dump describes the layout of serialized information from the dump command.
type Dump struct {
	Log struct {
		PCRs   []register.PCR
		PCRAlg tpm2.Algorithm
		Raw    []byte // The measured boot log in binary form.
	}
}
