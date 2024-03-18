package cmd

import (
	"fmt"
	"github.com/aRestless/nexus/pkg/client"
	"github.com/aRestless/nexus/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"log"
	"os"
	"strings"
)

func initClientCmd() *cobra.Command {
	result := &cobra.Command{
		Use: "client",
	}

	input := &ClientInput{}
	result.PersistentFlags().StringVar(&input.Server, "server", "https://localhost:3000", "")
	bindTLSInput(result, &input.TLS)

	commands := []*cobra.Command{
		{
			Use: "whoami",
			Run: func(cmd *cobra.Command, args []string) {
				clientWhoami((*ClientWhoamiInput)(input))
			},
		},
		{
			Use: "list",
			Run: func(cmd *cobra.Command, args []string) {
				clientList((*ClientListInput)(input))
			},
		},
		initClientDeleteCmd(input),
		initClientNetworkCmd(input),
	}

	result.AddCommand(
		commands...,
	)

	return result
}

func bindTLSInput(cmd *cobra.Command, input *TLSInput) {
	cmd.PersistentFlags().StringVar(&input.Name, "tls.name", "", "")
	cmd.MarkPersistentFlagRequired("tls.name")

	cmd.PersistentFlags().StringVar(&input.Key, "tls.key", "cert/client.key.pem", "")
	cmd.PersistentFlags().StringVar(&input.Cert, "tls.cert", "cert/client.cert.pem", "")
	cmd.PersistentFlags().BoolVar(&input.InsecureSkipVerify, "tls.insecureSkipVerify", false, "")
}

func initClientDeleteCmd(clientIn *ClientInput) *cobra.Command {
	in := &ClientDeleteInput{
		ClientInput: clientIn,
	}

	cmd := &cobra.Command{
		Use: "delete",
		Run: func(cmd *cobra.Command, args []string) {
			clientDelete(in)
		},
	}

	cmd.Flags().StringVar(&in.Client, "client", "", "")
	cmd.MarkFlagRequired("client")

	return cmd
}

func initClientNetworkCmd(in *ClientInput) *cobra.Command {
	cmd := &cobra.Command{
		Use: "network",
	}

	cmd.AddCommand(
		initClientCertificateCmd(in),
	)

	return cmd
}

func initClientCertificateCmd(clientIn *ClientInput) *cobra.Command {
	in := &ClientCertificateInput{
		ClientInput: clientIn,
	}

	cmd := &cobra.Command{
		Use: "certificate",
	}

	cmd.PersistentFlags().StringVar(&in.Network, "network", "default", "")
	_ = cmd.MarkPersistentFlagRequired("network")

	listCmd := &cobra.Command{
		Use: "list",
		Run: func(cmd *cobra.Command, args []string) {
			clientCertificateList(in)
		},
	}
	cmd.AddCommand(listCmd)

	cmd.AddCommand(initClientCertificateCreateCommand(in))

	return cmd
}

func initClientCertificateCreateCommand(certIn *ClientCertificateInput) *cobra.Command {
	in := &ClientCertificateCreateInput{
		ClientCertificateInput: certIn,
	}

	createCmd := &cobra.Command{
		Use: "create",
		Run: func(cmd *cobra.Command, args []string) {
			clientCertificateCreate(in)
		},
	}

	createCmd.Flags().StringVar(&in.In.PubKey, "in.pubkey", "nexus.pub.pem", "")
	createCmd.Flags().StringVar(&in.Out.Cert, "out.cert", "nexus.cert.pem", "")

	return createCmd
}

func clientWhoami(in *ClientWhoamiInput) {
	mustCreateTLSCertificateFromInput(in.TLS)
	c, err := getHTTPClient((*ClientInput)(in))
	if err != nil {
		log.Fatal(err)
	}

	clientID, err := c.GetClientID()
	if err != nil {
		log.Fatal(err)
	}

	printTable(os.Stdout, []map[string]string{{"ClientID": clientID}}, []string{"ClientID"})
}

func clientList(input *ClientListInput) {
	mustCreateTLSCertificateFromInput(input.TLS)

	c, err := getHTTPClient((*ClientInput)(input))
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.ListClients()
	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"PublicKeyHash", "CommonName", "HardwareAddress", "Networks"}
	var output []map[string]string
	for _, cl := range resp.Items {
		output = append(output, map[string]string{
			"PublicKeyHash":   cl.PublicKeyHash,
			"CommonName":      cl.CommonName,
			"HardwareAddress": cl.HardwareAddress,
			"Networks":        strings.Join(cl.Networks, ","),
		})
	}

	printTable(os.Stdout, output, columns)
}

func clientDelete(input *ClientDeleteInput) {
	mustCreateTLSCertificateFromInput(input.TLS)

	c, err := getHTTPClient(input.ClientInput)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.DeleteClient(input.Client)
	if err != nil {
		log.Fatal(err)
	}

	columns := []string{"PublicKeyHash", "CommonName", "HardwareAddress", "Networks"}
	var output []map[string]string
	output = append(output, map[string]string{
		"PublicKeyHash":   resp.PublicKeyHash,
		"CommonName":      resp.CommonName,
		"HardwareAddress": resp.HardwareAddress,
		"Networks":        strings.Join(resp.Networks, ","),
	})

	printTable(os.Stdout, output, columns)
}

func clientCertificateList(in *ClientCertificateInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient(in.ClientInput)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.ListClientNetworkCertificates(in.Network)
	if err != nil {
		log.Fatalf("create client network certificate: %v", err)
	}

	columns := []string{"Address", "Hash", "Groups", "NotAfter", "RenewableAfter", "RevokedAfter"}
	var output []map[string]string
	for _, cert := range resp.Items {
		output = append(output, map[string]string{
			"Address":        cert.Address.String(),
			"Hash":           cert.Hash,
			"Groups":         strings.Join(cert.Groups, ","),
			"NotAfter":       cert.NotAfter.String(),
			"RenewableAfter": cert.RenewableAfter.String(),
			"RevokedAfter":   cert.RevokedAfter.String(),
		})
	}

	printTable(os.Stdout, output, columns)
}

func clientCertificateCreate(in *ClientCertificateCreateInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	b, err := os.ReadFile(in.In.PubKey)
	if err != nil {
		log.Fatal(err)
	}

	c, err := getHTTPClient(in.ClientInput)
	if err != nil {
		log.Fatal(err)
	}

	req := server.CreateCertificateRequest{
		PubPEM: b,
	}

	resp, err := c.CreateClientNetworkCertificate(in.Network, req)
	if err != nil {
		log.Fatalf("create client network certificate: %v", err)
	}

	err = os.WriteFile(in.Out.Cert, resp.PEM, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func getHTTPClient(in *ClientInput) (*client.Client, error) {
	c, err := client.New(
		in.Server,
		in.TLS.Cert,
		in.TLS.Key,
		in.TLS.InsecureSkipVerify,
		logrus.New(),
	)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	return c, nil
}

func mustCreateTLSCertificateFromInput(input TLSInput) {
	mustCreateTLSCertificate(input.Name, input.Cert, input.Key)
}
