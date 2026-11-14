// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func TestAgentsConfig(t *testing.T) {
	if c, err := parse(Template("h.db")); err != nil || len(c.Agents) != 0 {
		t.Fatalf("agents should be off by default: %+v %v", c.Agents, err)
	}
	c, err := parse([]byte(`
[[agents]]
name = "pr-bot"
discord_user_id = "123456789012345678"
destination = "discord:agents"

[[agents]]
name = "other-bot"
discord_user_id = "98765432109876543"
destination = "discord:agents"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil || len(c.Agents) != 2 || !c.AgentUsesDestination("discord:agents") || c.AgentUsesDestination("discord:alerts") {
		t.Fatalf("agents: %+v %v", c.Agents, err)
	}
	for _, bad := range []Agent{
		{Name: "Pr Bot", DiscordUserID: "123456789012345678", Destination: "discord:agents"},
		{Name: "pr-bot", DiscordUserID: "1234", Destination: "discord:agents"},
		{Name: "pr-bot", DiscordUserID: "<@123456789012345678>", Destination: "discord:agents"},
		{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "slack:agents"},
		{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "https://discord.com/api/webhooks/1/x"},
	} {
		c := Default()
		c.Agents = []Agent{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	c = Default()
	a := Agent{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "discord:agents"}
	c.Agents = []Agent{a, {Name: "amp", Kind: "amp"}, {Name: "amp-2", Kind: "amp", AmpPath: "/opt/amp/bin/amp"}}
	if err := c.Validate(); err != nil || !c.Agents[1].IsAmp() || c.Agents[1].Amp() != DefaultAmpPath || c.Agents[2].Amp() != "/opt/amp/bin/amp" || c.Agents[0].IsAmp() {
		t.Errorf("amp agents: %v", err)
	}
	for _, bad := range []Agent{
		{Name: "amp", Kind: "amp", DiscordUserID: "123456789012345678"},
		{Name: "amp", Kind: "amp", Destination: "discord:agents"},
		{Name: "amp", Kind: "amp", AmpPath: "amp"},
		{Name: "amp", Kind: "amp", AmpPath: "/home/me/.amp/bin/amp"},
		{Name: "amp", Kind: "amp", AmpPath: "/usr/local/bin/../bin/amp"},
		{Name: "amp", Kind: "copilot"},
		{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "discord:agents", AmpPath: "/usr/local/bin/amp"},
	} {
		c := Default()
		c.Agents = []Agent{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	c = Default()
	c.Agents = []Agent{a, a}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate agent: %v", err)
	}
}

// One agent can be marked the default; two can't.
func TestAgentsDefault(t *testing.T) {
	c, err := parse([]byte(`
[[agents]]
name = "pr-bot"
discord_user_id = "123456789012345678"
destination = "discord:agents"

[[agents]]
name = "amp"
kind = "amp"
default = true
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil || c.Agents[0].Default || !c.Agents[1].Default {
		t.Fatalf("default agent: %+v %v", c.Agents, err)
	}
	c.Agents[0].Default = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "agents[1].default: only one agent can be the default") {
		t.Errorf("two defaults: %v", err)
	}
}
