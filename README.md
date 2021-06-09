# Detect Ransomware Filenames

This package/script watches SMB transactions to look for known bad filenames
that ransomware is known to use. It rides on top of the Anti-Ransomware File
System Resource Manager Lists maintained [here](https://fsrm.experiant.ca/).

## How to use

A Python script (`download-list.py`) is included to be able to refresh the
list periodically. By default, it will download the new file to the `inputs/`
folder.

## Installing

This package is available via `zkg`, however since it has two parts (the script
and the input file), it's often better to install it manually.

### For Zeek

For Zeek, place the `scripts/check-for-ransomware-filenames.zeek` script and
`inputs/fsrm_patterns_for_zeek.tsv` files into a directory together, then edit
your `local.zeek` file to add a line like the following:

`@load /path/to/check-for-ransomware-filenames.zeek`

### For Corelight

For a Corelight appliance, use `zkg` to add this repository to a custom bundle,
with any other custom packages that you want to load. Use `corelight-client` to
install this bundle.

Then, use `corelight-client` to load the Input file, like so:

`corelight-client -b <sensor IP> bro input upload --name fsrm_patterns_for_zeek.tsv --file fsrm_patterns_for_zeek.tsv`

## Sample Output

The script generates notices like the following:

```
{
  "_path": "notice",
  "_system_name": "bas-cl-swsensor-01",
  "_write_ts": "2020-04-27T21:40:10.494579Z",
  "_node": "worker-02",
  "ts": "2020-04-27T21:40:10.494579Z",
  "uid": "CNhUff2G2TzzRoQi45",
  "note": "Ransomware::KnownBadFilename",
  "msg": "Detected potential ransomware! Known bad file name: test3.hj36MM in use by client 10.0.2.51 on file server 172.16.4.66",
  "src": "10.0.2.51",
  "dst": "172.16.4.66",
  "peer_descr": "worker-02",
  "actions": [
    "Notice::ACTION_LOG"
  ],
  "suppress_for": 3600
}
```

If/when you get a notice, investigate, ideally as quickly as possible!

## License

Please read the license file [here](./LICENSE) for information about the license
for this software.
