package cmd

import (
	"github.com/slackhq/nebula/cert"
	"github.com/spf13/cobra"
	"log"
	"os"
)

// TODO: probably obsolete because there's no reason to do this by hand
func initKeyCmd() *cobra.Command {
	result := &cobra.Command{
		Use: "key",
	}

	result.AddCommand(
		initKeyCreateCmd(),
	)

	return result
}

func initKeyCreateCmd() *cobra.Command {
	result := &cobra.Command{
		Use: "create",
		Run: keyCreate,
	}

	result.Flags().String("out.privkey", "./nexus.key.pem", "")
	result.Flags().String("out.pubkey", "./nexus.pub.pem", "")

	return result
}

func keyCreate(cmd *cobra.Command, args []string) {
	pub, priv := x25519Keypair()
	privkeyPath, _ := cmd.Flags().GetString("out.privkey")
	pubkeyPath, _ := cmd.Flags().GetString("out.pubkey")

	curve := cert.Curve_CURVE25519
	err := os.WriteFile(privkeyPath, cert.MarshalPrivateKey(curve, priv), 0600)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(pubkeyPath, cert.MarshalPublicKey(curve, pub), 0600)
	if err != nil {
		log.Fatal(err)
	}
}
