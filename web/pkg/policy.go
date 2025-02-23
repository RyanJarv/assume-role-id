package pkg

type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

type PolicyDocument2 struct {
	Version   string             `json:"Version"`
	Statement []PolicyStatement2 `json:"Statement"`
}

type PolicyStatement struct {
	Sid         string           `json:"Sid"`
	Effect      string           `json:"Effect"`
	Principal   *PolicyPrincipal `json:"Principal,omitempty"`
	Action      string           `json:"Action,omitempty"`
	NotAction   string           `json:"NotAction,omitempty"`
	Resource    string           `json:"Resource,omitempty"`
	NotResource string           `json:"NotResource,omitempty"`
}

type PolicyStatement2 struct {
	Sid         string           `json:"Sid"`
	Effect      string           `json:"Effect"`
	Principal   *PolicyPrincipal `json:"Principal,omitempty"`
	Action      []string         `json:"Action,omitempty"`
	NotAction   []string         `json:"NotAction,omitempty"`
	Resource    []string         `json:"Resource,omitempty"`
	NotResource []string         `json:"NotResource,omitempty"`
}

type PolicyPrincipal struct {
	AWS string `json:"AWS"`
}

type Info struct {
	Comment string
	Exists  bool
}
