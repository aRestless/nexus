package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/curve25519"
	"io"
	"log"
	"net/http"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Used for flags.
	cfgFile     string
	userLicense string

	rootCmd = &cobra.Command{
		Use: "nexus",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initConfig(cmd)
		},
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "",
	Long:  "",
	Args:  nil,
	Run:   serve,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cobra.yaml)")

	serveCmd.Flags().Bool("tls", false, "")
	serveCmd.Flags().String("tls.key", "server.key.pem", "")
	serveCmd.Flags().String("tls.cert", "server.cert.pem", "")
	serveCmd.Flags().String("ca.key", "ca.key", "")
	serveCmd.Flags().String("ca.cert", "ca.crt", "")
	serveCmd.Flags().String("db.path", "file::memory:?cache=shared", "")
	serveCmd.Flags().String("addr", "", "")
	serveCmd.Flags().StringToString("admins", nil, "")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(initClientCmd())
	rootCmd.AddCommand(initNetworkCmd())
	rootCmd.AddCommand(initNebulaCmd())
}

func initConfig(cmd *cobra.Command) error {
	v := viper.New()

	// Set the base name of the config file, without the file extension.
	v.SetConfigName("nexus.config")

	// Set as many paths as you like where viper should look for the
	// config file. We are only looking in the current working directory.
	v.AddConfigPath(".")

	// Attempt to read the config file, gracefully ignoring errors
	// caused by a config file not being found. Return an error
	// if we cannot parse the config file.
	if err := v.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	// When we bind flags to environment variables expect that the
	// environment variables are prefixed, e.g. a flag like --number
	// binds to an environment variable STING_NUMBER. This helps
	// avoid conflicts.
	v.SetEnvPrefix("NEXUS")

	// Environment variables can't have dashes in them, so bind them to their equivalent
	// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Bind to environment variables
	// Works great for simple config names, but needs help for names
	// like --favorite-color which we fix in the bindFlags function
	v.AutomaticEnv()

	// Bind the current command's flags to viper
	bindFlags(cmd, v)

	return nil
}

func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Determine the naming convention of the flags when represented in the config file
		configName := f.Name
		// If using camelCase in the config file, replace hyphens with a camelCased string.
		// Since viper does case-insensitive comparisons, we don't need to bother fixing the case, and only need to remove the hyphens.
		configName = strings.ReplaceAll(f.Name, "-", "")

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(configName) {
			val := v.Get(configName)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}

func p256Keypair() ([]byte, []byte) {
	privkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := privkey.PublicKey()
	return pubkey.Bytes(), privkey.Bytes()
}

func x25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
}

func printResponse(resp *http.Response) {
	b, _ := io.ReadAll(resp.Body)
	log.Println(string(b))
}

func printTable(w io.Writer, rows []map[string]string, order []string) {
	tw := tabwriter.NewWriter(w, 4, 8, 1, '\t', 0)

	fmt.Fprintln(tw, strings.Join(order, "\t"))
	for _, row := range rows {
		var output []string
		for _, column := range order {
			output = append(output, row[column])
		}

		fmt.Fprintln(tw, strings.Join(output, "\t"))
	}

	tw.Flush()
}
