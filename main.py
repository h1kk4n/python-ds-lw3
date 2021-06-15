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
done_list = []

G = nx.Graph()
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
    with open("vulnerabilities.txt", "r") as vulns_f:
        for line in vulns_f:
            if line.strip():
                host, value = line.strip().split(":")
                vulns[host] = value.strip()

    with open("topology.txt", "r") as topology_f:
        for line in topology_f:
            if line.strip():
                key, value = line.strip().split(":")
                topology[validate_ip(key)] = 0
                for vuln in value.strip().split(", "):
                    vuln = vuln.strip()
                    if vulns[vuln] == 'root':
                        current_level = 4
                    elif vulns[vuln] == 'user':
                        current_level = 3
                    elif vulns[vuln] == 'doc':
                        current_level = 2
                    elif vulns[vuln] == 'other':
                        current_level = 1

                    if current_level > topology[validate_ip(key)]:
                        topology[validate_ip(key)] = current_level

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


def make_default_graph():
    G.add_nodes_from(nodes)

    for host in access_table.keys():
        for other_host in access_table[host]:
            G.add_edge(host, other_host, color='black')

    G.add_edge('192.168.134.1', '192.168.134.2', color='red')


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


def make_attack(init_host):
    if topology[init_host] >= 3:
        for host in access_table[init_host]:
            if host not in done_list and topology.get(host, False) and topology[host] >= 3:
                # print(init_host, host)
                G.add_edge(host, init_host, color='red')
        done_list.append(init_host)

        for host in access_table[init_host]:
            if host not in done_list and topology.get(host, False) and topology[host] >= 3:
                make_attack(host)
    return


def main():
    try:
        init_host = validate_ip(input())

        read_files()
        create_access_table()

        if init_host in access_table:
            make_default_graph()
            make_attack(init_host)

            pos = nx.circular_layout(G)
            plt.figure(figsize=(len(nodes) * 2, len(nodes) * 2 - 2))

            colors = [G[u][v]['color'] for u, v in G.edges]
            nx.draw_networkx_nodes(G, pos, node_size=2000)
            nx.draw_networkx_edges(G, pos, edgelist=G.edges, edge_color=colors)
            nx.draw_networkx_labels(G, pos)

            plt.axis('off')
            plt.show()
        else:
            print("Initial IP is not exist")

    except InvalidIPException as e:
        print(e.message)


if __name__ == "__main__":
    main()
    create_access_table()


