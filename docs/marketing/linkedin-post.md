# LinkedIn Post

---

If you run Illumio PCE, you've probably hit the wall: the platform does segmentation well, but every org has five more things they need on top of it — incident response hooks, CMDB sync, firewall rule exports, a way to prove posture to auditors, or just a dashboard the network team will actually open.

I've been building Plugger, an open-source plugin framework that extends PCE without touching your production config. Each plugin runs as a Docker container. One command to install, one to start everything.

A few things worth calling out:

**AI Security Report** — analyzes your PCE, scores posture across 10 security dimensions, maps to NIST CSF and PCI-DSS, and generates a prioritized remediation roadmap. 30 seconds to a board-ready report.

**Workload Isolator** — webhook endpoint that quarantines a compromised workload in seconds. CrowdStrike or Splunk SOAR calls it; Illumio flips enforcement before lateral movement spreads.

**Policy Resolver** — translates label-based policy into IP-level firewall rules your network team can read. Useful for audits and firewall migrations.

**Policy GitOps** — policy-as-code with PR review, drift detection, and traffic evidence gates before anything provisions.

20 plugins total, covering monitoring, AI analysis, integrations (Palo Alto, Infoblox, ZTNA platforms, CMDB), and operations.

Open source, community-driven. Would be glad to hear what you'd want to see next.

GitHub: https://github.com/alexgoller/illumio-plugger
Portal: https://alexgoller.github.io/illumio-plugger/

#Illumio #ZeroTrust #NetworkSecurity #MicroSegmentation #SecOps #SecurityAutomation #PolicyAsCode #OpenSource
