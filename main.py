from pprint import pprint
import re
import networkx as nx
import matplotlib.pyplot as plt

ROUTER_CON = "routers"
HOST_CON = "hosts"
DISCON_HOST = "unavailable"


topology = {}
hosts = {}
vulns = {}

access_table = {}

G = nx.DiGraph()
nodes = []


class InvalidIPException(Exception):
    message = 'IP in one of files is invalid'


def validate_ip(ip_string):
    ip_raw = r'25[0-5]|2[0-4]\d|1\d\d|\d\d|\d'
    result = re.findall(ip_raw, ip_string)
    if '.'.join(result) == ip_string.strip() and len(result) == 4:
        return '.'.join(result)
    else:
        raise InvalidIPException()


def read_files():
    with open("topology.txt", "r") as topology_f:
        for line in topology_f:
            key, value = line.strip().split(":")
            topology[validate_ip(key)] = value.strip().split(", ")

    with open("hosts.txt", "r") as hosts_f:
        current_key = ""
        for line in hosts_f:
            line = line.strip()
            if line.endswith(':'):
                current_key = validate_ip(line.replace(":", ''))
                hosts[current_key] = {
                    ROUTER_CON: [],
                    HOST_CON: [],
                    DISCON_HOST: []
                }
            elif line.startswith('>') and current_key:
                router = line.replace(">", "").strip()
                hosts[current_key][ROUTER_CON].append(validate_ip(router))
            elif line.startswith('+') and current_key:
                host = line.replace("+", "").strip()
                hosts[current_key][HOST_CON].append(validate_ip(host))
                if host not in nodes:
                    nodes.append(host)
            elif line.startswith("-") and current_key:
                host = line.replace("-", "").strip()
                hosts[current_key][DISCON_HOST].append(validate_ip(host.strip()))
                if host not in nodes:
                    nodes.append(host)
            else:
                current_key = ""

    with open("vulnerabilities.txt", "r") as vulns_f:
        for line in vulns_f:
            host, value = line.strip().split(":")
            vulns[host] = value.strip()


def draw_graph():
    G.add_nodes_from(nodes)

    for host in access_table.keys():
        for other_host in access_table[host]:
            G.add_edge(host, other_host)

    pos = nx.spring_layout(G)
    plt.figure(figsize=(len(nodes) * 2, len(nodes) * 2 - 2))
    nx.draw_networkx_nodes(G, pos, node_size=2000)
    # pprint(list(G.edges)[0])
    nx.draw_networkx_edges(G, pos, edgelist=G.edges)
    nx.draw_networkx_labels(G, pos)
    plt.axis('off')
    plt.show()


def create_access_table():
    for key in hosts.keys():
        for host in hosts[key][HOST_CON]:
            access_table[host] = []
            for other_host in hosts[key][HOST_CON]:
                if other_host not in access_table[host] and other_host != host:
                    access_table[host].append(other_host)
            for unavailable in hosts[key][DISCON_HOST]:
                access_table[host].append(unavailable)
            for router in hosts[key][ROUTER_CON]:
                for other_host in hosts[router][HOST_CON]:
                    access_table[host].append(other_host)
        for unavailable in hosts[key][DISCON_HOST]:
            access_table[unavailable] = []
            for other_host in hosts[key][HOST_CON]:
                access_table[unavailable].append(other_host)
            for other_unavailable in hosts[key][DISCON_HOST]:
                if other_unavailable not in access_table[unavailable] and other_unavailable != unavailable:
                    access_table[unavailable].append(other_unavailable)
            for router in hosts[key][ROUTER_CON]:
                for other_host in hosts[router][HOST_CON]:
                    access_table[unavailable].append(other_host)


def main():
    try:
        read_files()
        create_access_table()
        draw_graph()

    except InvalidIPException as e:
        print(e.message)


if __name__ == "__main__":
    main()
    create_access_table()

    pprint(access_table)

    # pprint(hosts)


