package config

import (
	"encoding/json"
	"os"
)

// InboundOptions holds the configuration for an inbound service.
type InboundOptions struct {
	Type    string                 `json:"type"`
	Tag     string                 `json:"tag"`
	Options map[string]interface{} `json:"options"`
}

// TransportOptions holds the configuration for a transport (outbound) service.
type TransportOptions struct {
	Type    string                 `json:"type"`
	Tag     string                 `json:"tag"`
	Options map[string]interface{} `json:"options"`
}

// RuleOptions defines a single routing rule.
type RuleOptions struct {
	InboundTag   []string `json:"inbound_tag"`
	Destination  string   `json:"destination"` // Example: "tcp:80,443"
	TransportTag string   `json:"transport_tag"`
}

// RoutingOptions holds the routing configuration.
type RoutingOptions struct {
	Rules []RuleOptions `json:"rules"`
}

// Config is the main configuration structure for the application.
type Config struct {
	Inbounds   []InboundOptions   `json:"inbounds"`
	Transports []TransportOptions `json:"transports"`
	Routing    RoutingOptions     `json:"routing"`
}

// LoadNewConfig parses the JSON configuration file into the new Config struct.
func LoadNewConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
