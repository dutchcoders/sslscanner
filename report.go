package main

import "net"

type Report struct {
	IP        net.IP
	Hostnames []string
	Ports     map[int]PortStatus
}

func NewReport(ip net.IP) Report {
	return Report{Hostnames: []string{}, Ports: map[int]PortStatus{}, IP: ip}
}
