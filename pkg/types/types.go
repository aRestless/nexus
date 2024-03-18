package types

type HardwareInfo struct {
	Network NetworkInfo `json:"network"`
}

type NetworkInfo struct {
	NICs []NIC `json:"nics"`
}

type NIC struct {
	Name       string `json:"name"`
	MACAddress string `json:"macaddress"`
}

type Client struct {
	ID            string
	Name          string `json:"name"`
	PublicKeyHash string `json:"publicKeyHash"`
}
