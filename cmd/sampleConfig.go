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
            "fqdn": "bootstrap.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:06",
            "primary_ip": "172.17.1.3",
            "reverse_dns": "3.1.17.172.in-addr.arpa."
        },
        {
            "fqdn": "worker-2.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:09",
            "primary_ip": "172.17.1.4",
            "reverse_dns": "4.1.17.172.in-addr.arpa."
        },
        {
            "fqdn": "worker-1.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:08",
            "primary_ip": "172.17.1.5",
            "reverse_dns": "5.1.17.172.in-addr.arpa."
        },
        {
            "fqdn": "worker-0.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:07",
            "primary_ip": "172.17.1.6",
            "reverse_dns": "6.1.17.172.in-addr.arpa."
        },
        {
            "fqdn": "master-2.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:0c",
            "primary_ip": "172.17.1.7",
            "reverse_dns": "7.1.17.172.in-addr.arpa."
        },
        {
            "fqdn": "master-1.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:0b",
            "primary_ip": "172.17.1.8",
            "reverse_dns": "8.1.17.172.in-addr.arpa."
        },
        {
            "fqdn": "master-0.myocp.example.com",
            "mac_address": "56:6f:9c:ac:00:0a",
            "primary_ip": "172.17.1.9",
            "reverse_dns": "9.1.17.172.in-addr.arpa."
        }
    ],
    "dns_server": "172.17.1.1",
    "domain_data": ".myocp.example.com"
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
