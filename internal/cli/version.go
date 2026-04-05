package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the plugger version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("plugger %s\n", Version)
		},
	}
}
