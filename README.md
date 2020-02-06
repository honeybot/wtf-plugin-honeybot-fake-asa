# Fake Cisco ASA plugin for wtf

## Policy example

Mandatory options:
- version: version of Cisco ASA to emulate. Currently only 9.12 supported.
- path: path to data folder (usually installed in /usr/local/share/wtf/data/)

```
{
    "name": "fake-asa",
    "version": "0.1",
    "storages": { },
    "plugins": {            
        "honeybot.fake.asa": [{
			"version": "9.12",
			"path":"/usr/local/share/wtf/data/honeybot/fake/asa/"
		}]
    },
    "actions": {},
    "solvers": {}
}
``` 
