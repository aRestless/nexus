package cmd

type TLSInput struct {
	Key                string
	Cert               string
	Name               string
	InsecureSkipVerify bool
}

type ClientInput struct {
	Server string
	TLS    TLSInput
}

type ClientWhoamiInput ClientInput
type ClientListInput ClientInput

type ClientDeleteInput struct {
	*ClientInput
	Client string
}

type ClientCertificateInput struct {
	*ClientInput
	Network string
}

type ClientCertificateCreateInput struct {
	*ClientCertificateInput
	In struct {
		PubKey string
	}
	Out struct {
		Cert string
	}
}

type NetworkInput ClientInput

type NetworkClientInput struct {
	*NetworkInput
	Network string
}

type NetworkCreateInput struct {
	*NetworkInput
	Network struct {
		Name   string
		Subnet string
	}
}

type NetworkClientDeleteInput struct {
	*NetworkClientInput
	Client string
}

type NetworkClientCreateInput struct {
	*NetworkClientInput
	Client       string
	Address      string
	Groups       []string
	IsLighthouse bool
	Subnets      []string
}
