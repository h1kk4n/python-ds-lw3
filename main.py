from pprint import pprint

topology = {}
hosts = {}
vulns = {}

ROUTER_CON = "routers"
HOST_CON = "hosts"
DISCON_HOST = "unavailable"

def read_files():
    with open("topology.txt", "r") as topology_f:
        for line in topology_f:
            key, value = line.strip().split(":")
            topology[key] = value.strip().split(", ")

    with open("hosts.txt", "r") as hosts_f:
        current_key = ""
        for line in hosts_f:
            line = line.strip()
            if line.endswith(':'):
                current_key = line.replace(":", '')
                hosts[current_key] = {
                    ROUTER_CON: [],
                    HOST_CON: [],
                    DISCON_HOST: []
                }
            elif line.startswith('>') and current_key:
                router = line.replace(">", "")
                hosts[current_key][ROUTER_CON].append(router.strip())
            elif line.startswith('+') and current_key:
                host = line.replace("+", "")
                hosts[current_key][HOST_CON].append(host.strip())
            elif line.startswith("-") and current_key:
                host = line.replace("-", "")
                hosts[current_key][DISCON_HOST].append(host.strip())
            else:
                current_key = ""

    with open("vulnerabilities.txt", "r") as vulns_f:
        for line in vulns_f:
            host, value = line.strip().split(":")
            vulns[host] = value.strip()


def main():
    read_files()


if __name__ == "__main__":
    main()
    pprint(topology)
    print()

    pprint(hosts)
    print()

    pprint(vulns)