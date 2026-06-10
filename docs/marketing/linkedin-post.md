# LinkedIn Post

---

If you run Illumio PCE, you've probably hit the wall: the platform does segmentation well, but every org has five more things they need on top of it — firewall rule exports, time-based policy scheduling, ZTNA sync, or a way to manage policy as code across multiple teams.

I've been building Plugger, an open-source plugin framework that extends PCE without touching your production config. Each plugin runs as a Docker container. One command to install, one to start everything.

A few things worth calling out:

**Policy Resolver** — translates label-based policy into IP-level firewall rules. Export as Palo Alto CLI, Cisco ACL, or iptables commands. Your network team gets copy-paste ready rules for path firewalls. Handles allow, deny, and override-deny with proper ordering.

**Rule Scheduler** — time-based policy automation. Business hours access Mon-Fri 09:00-17:00, maintenance windows Saturday 02:00-06:00, weekend lockdowns. YAML config, immediate reconciliation, auto-provision.

**ZTNA Sync** — syncs Illumio workloads to Zscaler ZPA, Netskope, Cloudflare Access, or Cisco Secure Access as application definitions. Labels → ZTNA app segments with IPs and ports. Analytics mode to preview, sync mode to push.

**Policy GitOps** — policy-as-code with Git. CODEOWNERS enforces multi-team review for cross-scope rules. Security pipeline checks for any-to-any, insecure protocols. Traffic evidence proves each rule is needed. Provision on merge.

20 plugins total, covering monitoring, AI analysis, integrations (Palo Alto, Infoblox, ZTNA, CMDB), and operations.

Open source, community-driven. Would love to hear what you'd want to see next.

GitHub: https://github.com/alexgoller/illumio-plugger
Portal: https://alexgoller.github.io/illumio-plugger/
Policy GitOps: https://github.com/alexgoller/illumio-policy-gitops

#Illumio #ZeroTrust #NetworkSecurity #MicroSegmentation #SecOps #SecurityAutomation #PolicyAsCode #OpenSource
