# wofw

## Test (without install)

```bash
make

# start daemon
sudo ./wofwd

# add rule
sudo ./wofw rule add "drop tcp from any to any port 80"

# list rules
sudo ./wofw rule list

# check daemon
sudo ./wofw status
```

Stop daemon: `Ctrl-C` or `sudo pkill wofwd`

## Install & run as a service

```bash
sudo make install
sudo systemctl enable --now wofw
sudo wofw rule add "drop tcp from any to any port 443"
```

Rules file: `/etc/wofw/rules.conf` (loaded on daemon start; `wofw reload` re-reads it)