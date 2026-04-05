Build an Illumio Plugger plugin from a user description.

Ask the user what the plugin should do if not already clear from context. Then:

1. Ask whether they want a Go or shell plugin (recommend Go for anything with a UI or complex logic, shell for simple periodic scripts).

2. Run `plugger create <name> -t <go|shell>` to scaffold the project.

3. Edit the generated files based on what the plugin needs to do:
   - **main.go or entrypoint.sh**: Implement the actual plugin logic — PCE API calls, data processing, etc.
   - **plugin.yaml**: Set the correct schedule mode (daemon/cron/event), env vars, resource limits.
   - **.plugger/metadata.yaml**: Declare any ports, config requirements, volumes, and plugin info.
   - **Dockerfile**: Add any extra dependencies the plugin needs.

4. For PCE API calls, use these patterns:
   - Go: `net/http` with basic auth (`PCE_API_KEY:PCE_API_SECRET`), base URL `https://{PCE_HOST}:{PCE_PORT}/api/v2/orgs/{PCE_ORG_ID}`
   - Shell: the `pce_api` helper in the template already handles auth

5. Key PCE API endpoints to know:
   - `GET /workloads` — list workloads
   - `GET /labels` — list labels  
   - `GET /label_groups` — list label groups
   - `GET /sec_policy/draft/rule_sets` — list rulesets
   - `GET /events` — get audit events
   - `GET /traffic_flows/traffic_analysis_queries` — traffic flow queries

6. Build the Docker image: `docker build -t <name>:latest .`

7. Test it: `plugger install plugin.yaml && plugger start <name> && plugger logs <name> -f`

8. Show the user the final `plugger status <name>` output.

Always write clean, production-quality code. Include error handling, structured logging, and graceful shutdown for Go plugins.
