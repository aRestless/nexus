package cmd

import (
	"fmt"
	"github.com/aRestless/nexus/pkg/server"
	"github.com/spf13/cobra"
	"log"
	"net/netip"
	"os"
	"strings"
)

func initNetworkCmd() *cobra.Command {
	in := &NetworkInput{}

	cmd := &cobra.Command{
		Use: "network",
	}

	bindTLSInput(cmd, &in.TLS)
	cmd.PersistentFlags().StringVar(&in.Server, "server", "https://localhost:3000", "")

	commands := []*cobra.Command{
		{
			Use: "list",
			Run: func(cmd *cobra.Command, args []string) {
				networkList(in)
			},
		},
	}

	cmd.AddCommand(
		commands...,
	)

	cmd.AddCommand(
		initNetworkCreateCmd(in),
		initNetworkClientCmd(in),
	)

	return cmd
}

func initNetworkClientCmd(networkIn *NetworkInput) *cobra.Command {
	in := &NetworkClientInput{
		NetworkInput: networkIn,
	}

	cmd := &cobra.Command{
		Use: "client",
	}

	cmd.PersistentFlags().StringVar(&in.Network, "network.name", "default", "")
	cmd.MarkFlagRequired("network.name")

	cmd.AddCommand(initNetworkClientCreateCmd(in))
	cmd.AddCommand(initNetworkClientUpdateCmd(in))
	cmd.AddCommand(initNetworkClientDeleteCmd(in))
	cmd.AddCommand(initNetworkClientsListCmd(in))

	return cmd
}

func initNetworkCreateCmd(networkIn *NetworkInput) *cobra.Command {
	in := &NetworkCreateInput{
		NetworkInput: networkIn,
	}
	cmd := &cobra.Command{
		Use: "create",
		Run: func(cmd *cobra.Command, args []string) {
			networkCreate(in)
		},
	}

	cmd.PersistentFlags().StringVar(&in.Network.Name, "network.name", "default", "")
	cmd.MarkFlagRequired("network.name")

	cmd.Flags().StringVar(&in.Network.Subnet, "network.subnet", "10.10.0.0/16", "")
	cmd.MarkFlagRequired("network.subnet")

	return cmd
}

func initNetworkClientCreateCmd(networkClientIn *NetworkClientInput) *cobra.Command {
	in := &NetworkClientCreateInput{
		NetworkClientInput: networkClientIn,
	}
	cmd := &cobra.Command{
		Use: "create",
		Run: func(cmd *cobra.Command, args []string) {
			networkClientCreate(in)
		},
	}

	cmd.Flags().StringVar(&in.Client, "client", "", "")
	cmd.MarkFlagRequired("client")

	cmd.Flags().StringVar(&in.Address, "addr", "", "")
	cmd.Flags().StringArrayVar(&in.Groups, "groups", []string{}, "")

	cmd.Flags().BoolVar(&in.IsLighthouse, "isLighthouse", false, "")
	cmd.Flags().StringArrayVar(&in.Subnets, "subnets", nil, "")

	return cmd
}

func initNetworkClientUpdateCmd(networkClientIn *NetworkClientInput) *cobra.Command {
	in := &NetworkClientCreateInput{
		NetworkClientInput: networkClientIn,
	}
	cmd := &cobra.Command{
		Use: "update",
		Run: func(cmd *cobra.Command, args []string) {
			networkClientUpdate(in)
		},
	}

	cmd.Flags().StringVar(&in.Client, "client", "", "")
	cmd.MarkFlagRequired("client")

	cmd.Flags().StringVar(&in.Address, "addr", "", "")
	cmd.Flags().StringArrayVar(&in.Groups, "groups", []string{}, "")

	cmd.Flags().BoolVar(&in.IsLighthouse, "isLighthouse", false, "")
	cmd.Flags().StringArrayVar(&in.Subnets, "subnets", nil, "")

	return cmd
}

func initNetworkClientDeleteCmd(networkClientIn *NetworkClientInput) *cobra.Command {
	in := &NetworkClientDeleteInput{
		NetworkClientInput: networkClientIn,
	}
	cmd := &cobra.Command{
		Use: "delete",
		Run: func(cmd *cobra.Command, args []string) {
			networkClientDelete(in)
		},
	}

	cmd.Flags().StringVar(&in.Client, "client", "", "")
	cmd.MarkFlagRequired("client")

	return cmd
}

func initNetworkClientsListCmd(in *NetworkClientInput) *cobra.Command {
	cmd := &cobra.Command{
		Use: "list",
		Run: func(cmd *cobra.Command, args []string) {
			networkClientsList(in)
		},
	}

	return cmd
}

func networkList(in *NetworkInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient((*ClientInput)(in))
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.ListNetworks()
	if err != nil {
		log.Fatalf("list networks: %v", err)
	}

	columns := []string{"Name", "Prefix", "Groups"}
	var output []map[string]string
	for _, network := range resp.Items {
		output = append(output, map[string]string{
			"Name":   network.Name,
			"Prefix": network.Prefix.String(),
			"Groups": strings.Join(network.Groups, ","),
		})
	}

	printTable(os.Stdout, output, columns)
}

func networkCreate(in *NetworkCreateInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient((*ClientInput)(in.NetworkInput))
	if err != nil {
		log.Fatal(err)
	}

	ipnet, err := netip.ParsePrefix(in.Network.Subnet)
	if err != nil {
		log.Fatal(err)
	}

	req := server.CreateNetworkRequest{
		Name:    in.Network.Name,
		Network: ipnet,
	}

	resp, err := c.CreateNetwork(req)
	if err != nil {
		log.Fatalf("create network: %v", err)
	}

	columns := []string{"Name", "Prefix", "Groups"}
	output := []map[string]string{{
		"Name":   resp.Name,
		"Prefix": resp.Prefix.String(),
		"Groups": strings.Join(resp.Groups, ","),
	}}

	printTable(os.Stdout, output, columns)
}

func networkClientCreate(in *NetworkClientCreateInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient((*ClientInput)(in.NetworkInput))
	if err != nil {
		log.Fatal(err)
	}

	var subnets []netip.Prefix
	for _, str := range in.Subnets {
		subnet, err := netip.ParsePrefix(str)
		if err != nil {
			log.Fatal(err)
		}

		subnets = append(subnets, subnet)
	}

	req := server.CreateNetworkClientRequest{
		PublicKeyHash: in.Client,
		Groups:        in.Groups,
		IsLighthouse:  in.IsLighthouse,
		Subnets:       subnets,
	}

	if in.Address != "" {
		ip, err := netip.ParseAddr(in.Address)
		if err != nil {
			log.Fatal(err)
		}

		req.Address = &ip
	}

	resp, err := c.CreateNetworkClient(in.Network, req)
	if err != nil {
		log.Fatalf("create network client: %v", err)
	}

	columns := []string{"Network", "IsLighthouse", "Address", "Groups", "Subnets"}
	var outputSubnets []string
	for _, subnet := range resp.Subnets {
		outputSubnets = append(outputSubnets, subnet.String())
	}

	output := []map[string]string{{
		"Network":      resp.Network,
		"IsLighthouse": fmt.Sprintf("%t", resp.IsLighthouse),
		"Address":      resp.Address.String(),
		"Groups":       strings.Join(resp.Groups, ","),
		"Subnets":      strings.Join(outputSubnets, ","),
	}}

	printTable(os.Stdout, output, columns)
}

func networkClientUpdate(in *NetworkClientCreateInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient((*ClientInput)(in.NetworkInput))
	if err != nil {
		log.Fatal(err)
	}

	var addr *netip.Addr
	if in.Address != "" {
		a, err := netip.ParseAddr(in.Address)
		if err != nil {
			log.Fatal(err)
		}

		addr = &a
	}

	var subnets []netip.Prefix
	for _, str := range in.Subnets {
		subnet, err := netip.ParsePrefix(str)
		if err != nil {
			log.Fatal(err)
		}

		subnets = append(subnets, subnet)
	}

	req := server.UpdateNetworkClientRequest{
		Address:      addr,
		Groups:       in.Groups,
		IsLighthouse: in.IsLighthouse,
		Subnets:      subnets,
	}

	resp, err := c.UpdateNetworkClient(in.Network, in.Client, req)
	if err != nil {
		log.Fatalf("update network client: %v", err)
	}

	columns := []string{"Network", "IsLighthouse", "Address", "Groups", "Subnets"}
	var outputSubnets []string
	for _, subnet := range resp.Subnets {
		outputSubnets = append(outputSubnets, subnet.String())
	}

	output := []map[string]string{{
		"Network":      resp.Network,
		"IsLighthouse": fmt.Sprintf("%t", resp.IsLighthouse),
		"Address":      resp.Address.String(),
		"Groups":       strings.Join(resp.Groups, ","),
		"Subnets":      strings.Join(outputSubnets, ","),
	}}

	printTable(os.Stdout, output, columns)
}

func networkClientDelete(in *NetworkClientDeleteInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient((*ClientInput)(in.NetworkInput))
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.DeleteNetworkClient(in.Network, in.Client)
	if err != nil {
		log.Fatalf("delete network client: %v", err)
	}

	columns := []string{"Network", "IsLighthouse", "Address", "Groups", "Subnets"}
	var outputSubnets []string
	for _, subnet := range resp.Subnets {
		outputSubnets = append(outputSubnets, subnet.String())
	}

	output := []map[string]string{{
		"Network":      resp.Network,
		"IsLighthouse": fmt.Sprintf("%t", resp.IsLighthouse),
		"Address":      resp.Address.String(),
		"Groups":       strings.Join(resp.Groups, ","),
		"Subnets":      strings.Join(outputSubnets, ","),
	}}

	printTable(os.Stdout, output, columns)
}

func networkClientsList(in *NetworkClientInput) {
	mustCreateTLSCertificateFromInput(in.TLS)

	c, err := getHTTPClient((*ClientInput)(in.NetworkInput))
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.ListNetworkClients(in.Network)
	if err != nil {
		log.Fatalf("list network clients: %v", err)
	}

	columns := []string{"PublicKeyHash", "IsLighthouse", "Address", "Groups", "Subnets"}
	var output []map[string]string
	for _, networkClient := range resp.Items {
		var outputSubnets []string
		for _, subnet := range networkClient.Subnets {
			outputSubnets = append(outputSubnets, subnet.String())
		}

		output = append(output, map[string]string{
			"PublicKeyHash": networkClient.PublicKeyHash,
			"IsLighthouse":  fmt.Sprintf("%t", networkClient.IsLighthouse),
			"Address":       networkClient.Address.String(),
			"Groups":        strings.Join(networkClient.Groups, ","),
			"Subnets":       strings.Join(outputSubnets, ","),
		})
	}

	printTable(os.Stdout, output, columns)
}
