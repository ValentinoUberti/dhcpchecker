/*
Copyright © 2020 Valentino Uberti vuberti@redhat.com

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
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const sampleJSONConf = `
{
    "dns_data": [
        {
            "mac_address": "56:6f:9c:ac:00:06",
            "primary_ip": "172.17.1.3"
        },
        {
            "mac_address": "56:6f:9c:ac:00:09",
            "primary_ip": "172.17.1.4"
        },
        {
            "mac_address": "56:6f:9c:ac:00:08",
            "primary_ip": "172.17.1.5"
        },
        {
            "mac_address": "56:6f:9c:ac:00:07",
            "primary_ip": "172.17.1.6"
        },
        {
            "mac_address": "56:6f:9c:ac:00:0c",
            "primary_ip": "172.17.1.7"
        },
        {
            "mac_address": "56:6f:9c:ac:00:0b",
            "primary_ip": "172.17.1.8"
        },
        {
            "mac_address": "56:6f:9c:ac:00:0a",
            "primary_ip": "172.17.1.9"
        }
    ],
    "dns_server": "172.17.1.1"
}

`

// sampleConfigCmd represents the sampleConfig command
var sampleConfigCmd = &cobra.Command{
	Use:   "sample-config",
	Short: "Write to stdout a sample config file",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(sampleJSONConf)
	},
}

func init() {
	rootCmd.AddCommand(sampleConfigCmd)
}
