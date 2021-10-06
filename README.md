# ZTE F680 presence detection

This is a [Device Tracker](https://www.home-assistant.io/components/device_tracker/) for [Home Assistant](https://github.com/home-assistant/home-assistant/). Currently in its early infancy.

Feedback and bug reports welcome. PRs even more welcome.

## This device tracker

- [x] Connects to a local ZTE F680 router over HTTP
- [ ] Lists currently connected lan and wlan devices
  - [x] about half the time
  - [ ] consistently
- [x] Supports basic configuration options (password, host, etc.)
- [ ] Uses a continuous integration tool for unit testing and linting
- [ ] Has the core communications library properly detached from the Home Assistant component
- [ ] Has reliable, debuggable log output and error handling
- [ ] Has adequate unit test coverage
- [ ] Is ready for submission to the Home Assistant project

So there are still several things to do.

## Using this device tracker

*This device tracker is still a proof of concept for now, so don't hold your breath.*

You can [follow the dev docs](https://developers.home-assistant.io/docs/en/creating_component_loading.html) for help on how to load custom components. But the short version is:

1. Clone this repository into your Home Assistant's "custom_components" directory.
2. Add the ZTE platform as a Device Tracker component

For example, I would do this:
```bash
cd /home/homeassistant/.homeassistant
mkdir -p custom_components
cd custom_components
git clone https://github.com/mgp25/zte-f680-presence-detection zte
```

And then, inside `configuration.yml`, add something like:
```yml
device_tracker:
  - platform: zte
    password: !secret zte_password
    host: 192.168.1.1
```
(with `zte_password` defined in your `secrets.yml`, of course)