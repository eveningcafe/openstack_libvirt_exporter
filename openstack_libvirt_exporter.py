#!/usr/bin/python
from __future__ import print_function
import sys
import argparse
import libvirt
from lxml import etree
import sched
import time
from prometheus_client import start_http_server, Gauge
import six

parser = argparse.ArgumentParser(description='libvirt_exporter scrapes domains metrics from libvirt daemon')
parser.add_argument('-p', '--port_open',
                    help='exporter port ', default=9177)
parser.add_argument('-si', '--scrape_interval',
                    help='scrape interval for metrics in seconds', default=5)
parser.add_argument('-uri', '--uniform_resource_identifier',
                    help='Libvirt Uniform Resource Identifier', default="qemu:///system")

args = vars(parser.parse_args())
uri = args["uniform_resource_identifier"]


def connect_to_uri(libvirt_uri):
    conn = libvirt.open(uri)

    if conn is None:
        print('Failed to open connection to ' + libvirt_uri, file=sys.stderr)
    else:
        print('Successfully connected to ' + libvirt_uri)
    return conn


def get_domains(conn):

    domains = []

    for domain_id in conn.listDomainsID():
        dom = conn.lookupByID(domain_id)

        if dom is None:
            print('Failed to find the domain ' + dom.name(), file=sys.stderr)
        else:
            domains.append(dom)

    if len(domains) == 0:
        print('No running domains in URI')
        return None
    else:
        return domains


def get_metrics_collection_memory(metric_names, labels, stats, memory_allocation):
    dimensions = []
    metrics_collection = {}
    print (stats)
    if 'usable' in stats and 'available' in stats:
        used = (stats['available'] -
                       stats['usable'])
        util = 100 * (used / float(memory_allocation))
        stats['used'] = used
        stats['util'] = util
        metric_names.append('used')
        metric_names.append('util')

    elif 'available' in stats and 'unused' in stats:
        used = (stats['available'] -
                       stats['unused'])
        util = 100 * (used / float(memory_allocation))
        metric_names.append('used')
        metric_names.append('util')

    for mn in metric_names:
        if type(stats) is dict:
            dimensions = [[stats[mn], labels]]
        metrics_collection[mn] = dimensions

    return metrics_collection
previos_cpu_time = 0
def get_metrics_collection_cpu(metric_names, labels, stats):
    stats[0]['cpu_time'] /= float(10 ** 9)
    stats[0]['system_time'] /= float(10 ** 9)
    stats[0]['user_time'] /= float(10 ** 9)
    dimensions = []
    metrics_collection = {}
    for mn in metric_names:
        if type(stats) is list:
            dimensions = [[stats[0][mn], labels]]
        elif type(stats) is dict:
            dimensions = [[stats[mn], labels]]
        metrics_collection[mn] = dimensions

    return metrics_collection


def get_metrics_multidim_collections(dom, metric_names, instance_label, device):
    tree = etree.fromstring(dom.XMLDesc())
    targets = []

    for target in tree.findall("devices/" + device + "/target"):
        targets.append(target.get("dev"))

    metrics_collection = {}

    for mn in metric_names:
        dimensions = []
        for target in targets:
            labels = {}
            labels.update(instance_label)
            labels.update({'target_device': target})

            if device == "interface":
                stats = dom.interfaceStats(target)
                for mac in tree.findall("devices/interface/mac"):
                    mac_address = mac.get("address")
                labels.update({'mac_address': mac_address})
            elif device == "disk":
                stats = dom.blockStats(target)
            stats = dict(zip(metric_names, stats))
            dimension = [stats[mn], labels]
            dimensions.append(dimension)
        metrics_collection[mn] = dimensions
    return metrics_collection

# https://www.robustperception.io/understanding-machine-cpu-usage
def add_metrics(conn, dom, header_mn, g_dict):
    tree = etree.fromstring(dom.XMLDesc(0))
    uuid = tree.xpath('//domain/uuid/text()')[0]

    namespaces = {'nova': 'http://openstack.org/xmlns/libvirt/nova/1.0'}
    username = tree.xpath('//domain/metadata/nova:instance/nova:owner/nova:user/text()',
                          namespaces=namespaces)[0]
    instance_name = tree.xpath('//domain/metadata/nova:instance/nova:name/text()',
                                namespaces=namespaces)[0]
    project_name = tree.xpath('//domain/metadata/nova:instance/nova:owner/nova:project/text()',
                              namespaces=namespaces)[0]
    flavor_ram = tree.xpath('//domain/metadata/nova:instance/nova:flavor/nova:memory/text()',
                              namespaces=namespaces)[0]
    flavor_cpu = tree.xpath('//domain/metadata/nova:instance/nova:flavor/nova:vcpus/text()',
                            namespaces=namespaces)[0]
    flavor_disk = tree.xpath('//domain/metadata/nova:instance/nova:flavor/nova:disk/text()',
                            namespaces=namespaces)[0]
    labels = {'uuid': uuid, 'domain': dom.name(), 'username': username,
              'project_name': project_name, 'instance_name': instance_name,
              'flavor_ram': flavor_ram, 'flavor_cpu': flavor_cpu, 'flavor_disk': flavor_disk}
    print (labels)

    if header_mn == "libvirt_cpu_stats_":
        stats = dom.getCPUStats(True)
        metric_names = stats[0].keys()
        metrics_collection = get_metrics_collection_cpu(metric_names, labels, stats)
        unit = "_secs"

    elif header_mn == "libvirt_mem_stats_":
        stats = dom.memoryStats()
        metric_names = stats.keys()
        memory_allocation = int(tree.find('memory').text)
        metrics_collection = get_metrics_collection_memory(metric_names, labels, stats, memory_allocation)
        unit = ""

    elif header_mn == "libvirt_block_stats_":
        metric_names = \
                        ['read_requests_issued',
                         'read_bytes',
                         'write_requests_issued',
                         'write_bytes',
                         'errors_number']

        metrics_collection = get_metrics_multidim_collections(dom, metric_names, labels, device="disk")
        unit = ""

    elif header_mn == "libvirt_interface_":

        metric_names = \
                        ['read_bytes',
                         'read_packets',
                         'read_errors',
                         'read_drops',
                         'write_bytes',
                         'write_packets',
                         'write_errors',
                         'write_drops']

        metrics_collection = get_metrics_multidim_collections(dom, metric_names, labels, device="interface")
        unit = ""

    for mn in metrics_collection:
        metric_name = header_mn + mn + unit
        dimensions = metrics_collection[mn]

        if metric_name not in g_dict.keys():

            metric_help = 'help'
            labels_names = metrics_collection[mn][0][1].keys()

            g_dict[metric_name] = Gauge(metric_name, metric_help, labels_names)

            for dimension in dimensions:
                dimension_metric_value = dimension[0]
                dimension_label_values = dimension[1].values()
                g_dict[metric_name].labels(*dimension_label_values).set(dimension_metric_value)
        else:
            for dimension in dimensions:
                dimension_metric_value = dimension[0]
                dimension_label_values = dimension[1].values()
                g_dict[metric_name].labels(*dimension_label_values).set(dimension_metric_value)
    return g_dict


def job(libvirt_uri, g_dict, scheduler):
    print('BEGIN JOB :', time.time())
    conn = connect_to_uri(libvirt_uri)
    domains = get_domains(conn)


    while domains is None:
        domains = get_domains(conn)
        time.sleep(int(args["scrape_interval"]))

    headers_mn = ["libvirt_cpu_stats_", "libvirt_mem_stats_",
                  "libvirt_block_stats_", "libvirt_interface_"]

    for dom in domains:
        print(dom.name())

        for header_mn in headers_mn:
            g_dict = add_metrics(conn, dom, header_mn, g_dict)

    conn.close()
    print('FINISH JOB :', time.time())
    scheduler.enter((int(args["scrape_interval"])), 1, job, (libvirt_uri, g_dict, scheduler))


def main():
    print('PORT OPEN:', args["port_open"])
    print('START:', time.time())

    start_http_server(int(args["port_open"]))

    g_dict = {}

    scheduler = sched.scheduler(time.time, time.sleep)
    scheduler.enter(0, 1, job, (uri, g_dict, scheduler))
    scheduler.run()

if __name__ == '__main__':
    main()
