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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"

	"github.com/ValentinoUberti/dhcpchecker/macsniffer"
)

// multipleMacCmd represents the multipleMac command
var multipleMacCmd = &cobra.Command{
	Use:   "multiple-mac --ifname <interface name> --config-file  <config-file>",
	Short: "Test for dhcp server ip response from multiple mac addresses json config file",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := multipleMac(cmd)
		if err != nil {
			fmt.Println(err)
			fmt.Println("run `dhcpchecker multiple-mac --help` for help")
		}
	},
}

func multipleMac(cmd *cobra.Command) error {

	interfaceName, err := cmd.Flags().GetString("ifname")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	if interfaceName == "" {
		return errors.New("An interface name is required")
	}

	jsonFile, err := cmd.Flags().GetString("config-file")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	jsonDataFile, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return errors.New("Cannot open json file")
	}

	jsonDataStruct := macsniffer.ClusterNetData{}
	err = json.Unmarshal([]byte(jsonDataFile), &jsonDataStruct)

	if err != nil {
		return errors.New("Json file format not correct")
	}

	ifname := interfaceName
	hostname := ""
	macs := []string{}
	dataReceivedFromDhcp := []macsniffer.SingleTest{}

	for _, mac := range jsonDataStruct.DNSData {
		macs = append(macs, mac.MacAddress)
	}

	singleTestChan := make(chan macsniffer.SingleTest) // Ingress channel
	status := make(chan int)                           // Test Status

	dhcpClient, err := macsniffer.NewClient(macs, ifname, hostname)
	if err != nil {
		log.Fatalln(err)
	}

	go dhcpClient.Start(singleTestChan, status)

dhcploop:
	for {
		select {
		case msg := <-singleTestChan:

			dataReceivedFromDhcp = append(dataReceivedFromDhcp, macsniffer.SingleTest(msg))

		case status := <-status:

			if status > 0 {
				log.Println("Timeout reached")
			} else {
				log.Println("Test finished")
			}

			break dhcploop
		}
	}

	log.Println("Closing channels")
	close(singleTestChan)
	close(status)

	macsniffer.MultipleIpTest(dataReceivedFromDhcp, jsonDataStruct)
	return nil

}

func init() {
	rootCmd.AddCommand(multipleMacCmd)
	//mactestCmd.PersistentFlags().StringP("ifname", "", "", "Name of the interface to use.")
	multipleMacCmd.PersistentFlags().StringP("config-file", "", "", "Config file full path")

}
