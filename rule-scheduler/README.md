# Rule Scheduler

Time-based rule and ruleset scheduling for Illumio PCE. Enable/disable rulesets or individual rules based on day-of-week and time-of-day windows.

## Install

```bash
plugger install rule-scheduler
```

## Use Cases

- **Business hours only** — enable access rules Mon-Fri 9:00-17:00, disable after hours
- **Maintenance windows** — enable maintenance rules Saturday 02:00-06:00
- **Weekend lockdown** — disable broad access rules on weekends
- **After-hours RDP** — allow RDP only outside business hours for maintenance

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_INTERVAL` | `60` | Seconds between schedule evaluations |
| `TZ` | `UTC` | Timezone (e.g. `America/New_York`, `Europe/Berlin`) |

## How It Works

1. Create schedules via the dashboard with day/time windows and target rulesets
2. Every `CHECK_INTERVAL` seconds, the scheduler evaluates each schedule
3. If current time is within the window → applies `action_in_window` (enable or disable)
4. If current time is outside the window → applies `action_outside`
5. Changes are applied via PCE API (PUT to ruleset/rule with `enabled: true/false`)
6. A comment is added to the ruleset description for tracking

## Schedule Properties

| Field | Description |
|-------|-------------|
| `name` | Schedule name |
| `targets` | List of ruleset/rule HREFs to control |
| `target_type` | `ruleset` or `rule` |
| `days` | Days of week: `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun` |
| `start_time` | Window start (HH:MM, 24h format) |
| `end_time` | Window end (HH:MM) |
| `action_in_window` | `enable` or `disable` |
| `action_outside` | `enable`, `disable`, or empty (no action) |
| `comment` | Added to ruleset description |

## Features

- Multiple independent schedules running simultaneously
- Day-of-week selection (weekdays, weekends, specific days)
- Time window with overnight support (e.g. 22:00-06:00)
- Dashboard with live clock, schedule status, and change history
- Create/enable/disable/delete schedules from the web UI
- Persistent schedule storage in `/data` volume
- Configurable timezone
