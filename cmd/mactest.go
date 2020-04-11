/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

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
	"github.com/kr/pretty"
)

type DNSDataStruct struct {
	Fqdn       string `json:"fqdn"`
	MacAddress string `json:"mac_address"`
	PrimaryIP  string `json:"primary_ip"`
	ReverseDNS string `json:"reverse_dns"`
}

type ClusterNetData struct {
	DNSData    []DNSDataStruct `json:"dns_data"`
	DNSServer  string          `json:"dns_server"`
	DomainData string          `json:"domain_data"`
}

// mactestCmd represents the mactest command
var mactestCmd = &cobra.Command{
	Use:   "mactest --ifname <interface name> (--mac | --config)",
	Short: "Test for dhcp server ip response from different mac addresses",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(mactest(cmd))
	},
}

func mactest(cmd *cobra.Command) error {

	interfaceName, err := cmd.Flags().GetString("ifname")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	if interfaceName == "" {
		return errors.New("An interface name is required")
	}

	// Check if single-test is defined
	singleMac, err := cmd.Flags().GetString("mac")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	jsonFile, err := cmd.Flags().GetString("config-file")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	if singleMac == "" && jsonFile == "" {
		return errors.New("A config file or a single mac address is required")
	}

	jsonDataStruct := ClusterNetData{}
	if len(jsonFile) > 0 {
		jsonDataFile, err := ioutil.ReadFile(jsonFile)
		if err != nil {
			return errors.New("Cannot open json file")
		}

		_ = json.Unmarshal([]byte(jsonDataFile), &jsonDataStruct)
	} else {

		data := DNSDataStruct{
			MacAddress: singleMac,
		}
		jsonDataStruct.DNSData = append(jsonDataStruct.DNSData, data)
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
				log.Println("Mac test finished")
			}

			break dhcploop
		}
	}

	log.Println("Closing channels")
	close(singleTestChan)
	close(status)

	fmt.Printf("%# v", pretty.Formatter(dataReceivedFromDhcp))

	return nil
}

func init() {
	rootCmd.AddCommand(mactestCmd)
	//mactestCmd.Flags().StringP("ifname", "", "", "Name of the interface to test.")
	mactestCmd.PersistentFlags().StringP("ifname", "", "", "Name of the interface to test.")
	mactestCmd.PersistentFlags().StringP("config-file", "", "", "Config file full path")
	mactestCmd.PersistentFlags().StringP("mac", "", "", "Single mac address to test")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// mactestCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// mactestCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
