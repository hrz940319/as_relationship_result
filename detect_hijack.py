import os
import re
import sys
import radix
import shutil
import logging
import argparse
import itertools
sys.path.insert(0, '..')
import gzip
import datetime
import ipaddress
import subprocess
from pathlib import Path
#import establish_baseline
from BGPReader import BGPReader
from collections import defaultdict
import HelperModules.input_util as input_util
import HelperModules.get_assigned_autsys as get_assigned_autsys


class Hijack(object):

    def __init__(self, prefix, hijacked_prefix, current_origin, original_origin):
        self.prefix = prefix
        self.hijacked_prefix = hijacked_prefix
        self.current_origin = current_origin
        self.original_origin = original_origin
        self.start_ts = list()
        self.end_ts = list()
        self.visibility = set()

    def create_timeline(self):
        """
        Creates a timeline of the hijack by determining the start and end time

        :return: the start and end timestamps
        :rtype: (int, int)
        """
        if len(self.end_ts) == 0:
            self.end_ts.append(sys.maxsize)
        start_timestamps = set(self.start_ts.copy())
        end_timestamps = set(self.end_ts.copy())
        start_timeline = list()
        end_timeline = list()
        for ts in sorted(start_timestamps):
            if ts < min(end_timestamps):
                if len(start_timeline) == 0 or (len(end_timeline) > 0 and max(start_timeline) < max(end_timeline)):
                    start_timeline.append(ts)
                if max(start_timestamps) < max(end_timestamps):
                    end_timeline.append(max(end_timestamps))
                    break
            elif ts == min(end_timestamps):
                start_timeline.append(ts)
                end_timeline.append(min(end_timestamps))
                end_timestamps.remove(min(end_timestamps))
            elif len(end_timeline) > 0 and len(start_timeline) > 0 and max(start_timeline) > max(end_timeline):
                end_timeline.append(min(end_timestamps))
                end_timestamps.remove(min(end_timestamps))
                if len(end_timestamps) == 0:
                    break
        return start_timeline, end_timeline


    def __str__(self):
        """
        Creates a string representation of the object

        :return: the string with the attributes of the object
        :rtype: str
        """
        start_timeline, end_timeline = self.create_timeline()
        start_ts_str = ','.join([str(int(t)) for t in start_timeline])
        end_ts_str = ','.join([str(int(t)) for t in end_timeline])
        rtn = "{}\t{}\t{}\t{}\t{}\t{}\t{}".format(self.prefix,
                                                  self.hijacked_prefix,
                                                  ','.join(self.current_origin),
                                                  ','.join(self.original_origin),
                                                  start_ts_str,
                                                  end_ts_str,
                                                  len(self.visibility))
        return rtn


class PrefixOrigin(object):

    def __init__(self):
        self.asn = None
        self.last_snapshot = None
        self.snapshots = 0
        self.visibility = 0
        #begin: deleted by liumin 2020-12-1
        #self.baseline_origin = None
        #self.siblings = None
        #self.whois_siblings = None
        #self.relationships = None
        #end
        #begin:added by liumin 2020-12-1
        self.snapshots_dict = dict()
        self.first_snapshot = None
        self.confidence_value = 0
        #end: added by liumin 2020-12-1
    def __eq__(self, other):
        return self.asn == other.asn

    def __hash__(self):
        return hash(self.asn)

    def __repr__(self):
        return '<PrefixOrigin {}>'.format(self.asn)
    
    #begin:added by liumin 2020-12-1
    def get_totalsnapshots(self):
        if len(self.snapshots_dict)==0:
            print("PrefixOrigin {} should be deleted !".format(self.asn))
        else :
            self.snapshots = len(self.snapshots_dict)   
    def get_totalvisibility(self):
        for key,value in sorted(self.snapshots_dict.keys(),reverse=true):
            self.visibility += value
    def refresh_first_snapshot(self):
        snapshots_list = sorted(self.snapshots_dict.keys())
        self.firt_snapshot = list[0]
    def refresh_last_snapshot(self):
        list = sorted(self.snapshots_dict.keys())
        self.last_snapshot = list[-1]
    def set_confidence_value(self,credit=False):
        if credit == "sibligns" or self.confidence_value == 100:
            self.confidence_value = 100
        elif credit == "transit":
            self.confidence_value = 100
        elif credit == False:
            if self.snapshots > 5 and self.visibility > 10 and self.snapshots < 50:
                self.confidence_value = 50
            elif self.snapshots > 100:
                self.confidence_value = 100
            else:
                self.confidence_value = self.snapshots%100
    def snapshots_dict_aging(self):
        #snapshots_list = sorted(self.snapshots_dict.keys())
        
        
    #end: added by liumin 2020-12-1


class Monitor(object):
    """
    Class that includes the monitoring functionality for Hijack detection
    """

    def __init__(self, start):
        self.hijacks = dict()
        self.target_date = start
        #begin: added by liumin 2020-12-03 
        self.aging_interval = datetime.timedelta(days=150)
        self.bgp_rtree = radix.Radix()
        #end
        self.target_datetime = datetime.datetime.strptime(user_args.startdate + " 00:00:00", "%Y%m%d %H:%M:%S")
        self.assigned_autsys = set()
        self.bogon_prefixes = set()
        self.FNULL = open(os.devnull, 'w')
        self.irr_rtree = radix.Radix()
        self.irr_data_dir = "irr_prefix_origins"
        self.rpki_rtree = radix.Radix()
        logging.basicConfig(level=os.environ.get("LOGLEVEL", "WARNING"))
        self.initialize_data()

    def initialize_data(self):
        """
        Initializes the input data

        :return: None
        """
        self.get_roa_objects()  #RPKI 写入self。rpki_rtree
        iso_date = "{}-{}-{}".format(self.target_date[0:4], self.target_date[4:6], self.target_date[6:8])
        self.assigned_autsys = get_assigned_autsys.main(iso_date)  #返回RIR已分配的ASN
        self.bogon_prefixes = input_util.get_bogon_prefixes()
        self.siblings = input_util.load_siblings(user_args.siblings)
        #self.whois_siblings = input_util.extract_whois_siblings("/home/vgiotsas/bdrmapit/routeleaks/rpsl/whois_data_2020-11-19.txt")
        self.whois_siblings = input_util.extract_whois_siblings("/rpsl/whois_data_2020-11-19.txt")
        self.relationships = input_util.read_relationships(user_args.rel_dir, user_args.stability,
                                                              user_args.startdate)

    def get_roa_objects(self):
        """
        Ingests ROA objects from the VRP file
        """
        vrp_filepath = self.get_vrp_file()
        if vrp_filepath:
            with gzip.open(vrp_filepath, "rt") as fin:
                for line in fin:
                    if not line.startswith("URI"):
                        uri, autsys, prefix, longest_pfx, min_date, max_date = line.strip().split(",")
                        rnode = self.rpki_rtree.search_exact(prefix)
                        if not rnode:
                            rnode = self.rpki_rtree.add(prefix)
                            rnode.data["asn"] = set()
                            rnode.data["longest_pfx"] = set()
                        rnode.data["asn"].add(autsys)
                        rnode.data["longest_pfx"].add(longest_pfx)

    def get_vrp_file(self):
        """
        Checks if the VRP file for the requested date is available, if it's not it generates it
        
        :return: the filepath of the VRP file
        :rtype: str
        """
        vrp_filepath = False
        roa_dir = "../ground_truth/rpki/data/historical_roas/"
        iso_date = "{}-{}-{}".format(self.target_date[0:4], self.target_date[4:6], self.target_date[6:8])
        year, month, day = self.target_date[0:4], self.target_date[4:6], self.target_date[6:]
        target_filename = "vrps-{}.csv.gz".format(iso_date)
        target_filepath = os.path.join(roa_dir, target_filename)
        if os.path.isfile(target_filepath):
            vrp_filepath = target_filepath
        else:
            ziggy_conf = "../ground_truth/rpki/ziggy.conf"
            if not os.path.isfile(ziggy_conf):
                logging.warning("The Ziggy configuration file is missing. RPKI checks will be skipped ...")
            else:
                command = ["ziggy.py", "-c", ziggy_conf, "-d", "{}-{}-{}".format(year, month, day)]
                print(' '.join(command))
                try:
                    p = subprocess.Popen(' '.join(command), stdout=subprocess.PIPE, shell=True)
                    if os.path.isfile(target_filename):
                        shutil.move(target_filename, target_filepath)
                        vrp_filepath = target_filepath
                    else:
                        logging.warning("Failed to generate vrp file. RPKI checks will be skipped")
                except FileNotFoundError:
                    logging.warning("Ziggy is not installed. RPKI checks will be skipped ...")
        return vrp_filepath

    def load_irr_origins(self):
        """
        Loads the IRR prefix origin ASNs in a Radix tree
        """
        irr_filepath = self.get_irr_origins_file()
        with gzip.open(irr_filepath, "rt") as fin:
            for line in fin:
                if not line.startswith("#"):
                    lf = line.strip().split("\t")
                    if len(lf) > 2:
                        rnode = self.irr_rtree.add(lf[0])
                        rnode.data["origin"] = lf[1]

    def get_irr_origins_file(self):
        """
        Finds the IRR prefix origins file with the closest date to our target date

        :return: The file path to the IRR prefix origins file
        :rtype: str
        """
        min_date = sys.maxsize
        irr_origins_filename = None
        for filename in os.listdir(self.irr_data_dir):
            if filename.endswith(".gz") and filename.startswith("irr_prefix"):
                file_date = filename.split(".")[0].split("_")[3]
                file_datetime = datetime.datetime.strptime(file_date, "%Y-%m-%d")
                days_diff = abs(file_datetime - self.target_datetime)
                if days_diff < min_date:
                    min_date = days_diff
                    irr_origins_filename = filename

        filepath = os.path.join(self.irr_data_dir, irr_origins_filename)
        return filepath

    def is_legit(self, baseline_autsys, current_autsys, hijacked_prefix):
        """
        If the ASN that currently advertises a prefix isn't the same as the baseline ASNs,
        check if it can be considered a legitimate origin. Legitimate origins are one of the following categories:

        * Siblings of the baseline ASNs

        * Customers/Providers of the baseline ASNs

        * DDoS Mitigation providers

        :param baseline_autsys: The set of baseline ASNs
        :type baseline_autsys: set
        :param current_autsys: The set of current origin ASNs
        :type current_autsys: set
        :param hijacked_prefix: The hijacked prefix
        :type hijacked_prefix: str
        :return: False if the current ASN is not a legitimate origin, otherwise the type of legitimate origin
        :rtype: bool or str
        """
        legit = False
        baseline_siblings = set()
        for asn in baseline_autsys:
            if asn in self.siblings:
                baseline_siblings |= self.siblings[asn]
        siblings_overlap = baseline_siblings & current_autsys

        irr_rnode = self.irr_rtree.search_best(hijacked_prefix)
        if irr_rnode and irr_rnode.data["origin"] in current_autsys:
            legit = "irr"
        elif len(siblings_overlap) > 0:
            legit = "sibligns"
        else:
            for element in itertools.product(list(baseline_autsys), list(current_autsys)):
                l = ' '.join(element)
                if l in self.whois_siblings:
                    legit = "sibligns"
                    break
        if not legit:
            for baseline_asn in (baseline_autsys | baseline_siblings):
                for current_asn in current_autsys:
                    link = "{} {}".format(baseline_asn, current_asn)
                    if link in self.relationships and len(self.relationships[link] & {1, -1}) > 0:
                        legit = "transit"
        return legit

    # begin: added by liumin 2020-11-28
    def set_baseline_confidence_value(self,baseline_rtree):
        """
        Function that sets PO pairs'confidence value in baseline_rtree and 
                 filters out the PO pairs with confidence value less than the threshhold and rnodes without any origins 
        :param
        :type
        returen:None
        """
        covering_prefixes = defaultdict(list)
        for rnode in baseline_rtree:
            if len(rnode.data["origin"]) == 0:
                continue
            prefix = rnode.prefix
            #Begin:To set each node PO pairs' confidence value
            #print("To set each node PO pairs' confidence value!")
            autsys_set = set(rnode.data["origin"].keys())
            rnode_origins = rnode.data["origin"]
            
            for asn in rnode_origins:
                legit_type = False
                po_object = rnode_origins[asn]               
                legit_type = self.is_legit(autsys_set,set(po_object.asn),prefix)
                print("{}->{} legit_type = {}".format(prefix,po_object.asn,legit_type))
                po_object.set_confidence_value(legit_type)
            #End:                          
            if not (('.' in prefix and prefix.endswith("\24")) or (':' in prefix and prefix.endswith("\64"))):
                covered_rnodes = baseline_rtree.search_covered(prefix)
                if len(covered_rnodes) > 1:
                    covering_prefixes[prefix] = [covered_rnode.prefix for covered_rnode in covered_rnodes
                                         if (covered_rnode.prefix != prefix and len(covered_rnode.data["origin"]) > 0)]
            
        filtered_POs_counter = 0
        filtered_rnode_counter = 0 
        for prefix, covered_prefixes in covering_prefixes.items():
            covering_rnode = baseline_rtree.search_exact(prefix)
            if covering_rnode:
                covering_autsys = set(covering_rnode.data["origin"].keys())
                covering_origins = covering_rnode.data["origin"]
               
                #Begin:To set covered node PO pairs' confidence value                                   
                for covered_prefix in covered_prefixes:
                    covered_rnode = baseline_rtree.search_exact(covered_prefix)
                    if covered_rnode:  
                        covered_autsys=set(covered_rnode.data["origin"].keys())
                        covered_origins = covered_rnode.data["origin"]
                        
                        for covered_object in covered_origins:
                            covered_legit_type = False
                            if covered_object.confidence_value != 100:
                                covered_legit_type = self.is_legit(covering_autsys, set(covered_object.asn), covered_prefix)
                                covered_object.set_confidence_value(legit_type)
                            #Begin: to filter PO pair if confidence_value less than one threshhold 50 and lastsnapshot before last 
                            current_timestamp = int(current_datetime.replace(tzinfo=datetime.timezone.utc).timestamp())
                            if covered_object.confidence_value < 50 :
                                if covered_object.last_snapshot < current_timestamp-8*3600:
                                    covered_origins.pop(covered_object.asn)
                                    filtered_POs_counter += 1
                                    #dt_obj=datetime.datetime.fromtimestamp(covered_object.last_snapshot)
                                    print("No.{}:{}->{} is filtered with visibility = {} ,\
                                         snapshots {} and last_snapshot{}".format(filtered_POs_counter,
                                                                    covered_prefix,
                                                                    covered_object.asn,
                                                                    covered_object.visibility,
                                                                    covered_object.snapshots,
                                                                    covered_object.last_snapshot))
                        if len(covered_origins) == 0:
                            baseline_rtree.delete(covered_prefix)
                            filtered_rnode_counter += 1
                            print("No.{}:{} node is filtered. ".format(filtered_rnode_counter,
                                                         covered_prefix))
                #End:                      
    # end: added by liumin 2020-11-28
    
    # begin: added by liumin 2020-12-04
    def read_bgp_update(self,start_timestamp, end_timestamp,baseline_rtree):
        """
        Function that
        
        :param
        :type
        :return
        
        """
        
        prefix_origins = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        bgp_reader = BGPReader("bgpstream")
        for bgp_elem, bgp_rec in bgp_reader.get_bgp_data(start_timestamp,
                                                         end_timestamp,
                                                         collectors= "all",
                                                         record_type="updates"):
            if 'prefix' in bgp_elem.fields and \
                    bgp_elem.fields['prefix'] != '0.0.0.0/0' and \
                    bgp_elem.fields['prefix'] != "::/0":
                hijacked_prefix = False
                legit_prefix = False
                hijacked_ended = False
                if 'as-path' in bgp_elem.fields:
                    prefix = bgp_elem.fields["prefix"]
                    vantage_point_asn = bgp_elem.fields['as-path'].split()[0]
                    as_path = bgp_elem.fields['as-path'].split()
                    origin_asn = as_path[-1]
                    if origin_asn.startswith("{"):
                        as_set = set(origin_asn[1:-1].split(","))
                    else:
                        as_set = {origin_asn}
                    rnode_rpki = self.rpki_rtree.search_best(prefix)
                    if rnode_rpki:
                        legit_prefix = True
                        baseline_autsys = rnode_rpki.data["origin"]
                        if len(baseline_autsys & (set(as_path) | as_set)) == 0:
                            if not self.is_legit(baseline_autsys, as_set, prefix):
                                hijacked_prefix = "RPKI"
                                legit_prefix = False
                    if not hijacked_prefix and not legit_prefix:
                        rnode = baseline_rtree.search_best(prefix)
                        if rnode:
                            baseline_autsys = set(rnode.data["origin"].keys())
                            if len(baseline_autsys & (set(as_path) | as_set)) == 0:
                                if not self.is_legit(baseline_autsys, as_set, prefix):
                                    hijacked_prefix = "Baseline"  
                            #else:
                                # to filter the Prefix-origin according to the confidence value
                    
                        if hijacked_prefix:
                            if prefix not in self.hijacks:
                                print("{} Hijack: {}->{} advertised by {} instead of {} at {}".format(hijacked_prefix,
                                                                               prefix,
                                                                               rnode.prefix,
                                                                               as_set,
                                                                               ','.join(rnode.data["origin"]),
                                                                               bgp_rec.time))
                                print(bgp_elem.fields)
                                hijack = self.hijacks.get(prefix, Hijack(prefix, rnode.prefix, as_set, baseline_autsys))
                                hijack.start_ts.append(bgp_rec.time)
                                hijack.visibility.add(vantage_point_asn)
                                self.hijacks[prefix] = hijack
                            #elif prefix in self.hijacks and vantage_point_asn in self.hijacks[prefix].visibility:
                                #hijacked_ended = True
                elif bgp_elem.type == "W" and bgp_elem.fields["prefix"] in self.hijacks:
                    hijacked_ended = True
                if hijacked_ended:
                    hijack = self.hijacks[bgp_elem.fields['prefix']]
                    vantage_point_asn = str(bgp_elem.peer_asn)
                    if str(bgp_elem.peer_asn) in hijack.visibility:
                        hijack.end_ts.append(bgp_rec.time)
                        hijack.visibility.remove(vantage_point_asn)
                        self.hijacks[bgp_elem.fields['prefix']] = hijack
                        print("Hijack ended: {}->{} by {} instead of {} at {}".format(bgp_elem.fields['prefix'],
                                                                                  hijack.hijacked_prefix,
                                                                                  ','.join(hijack.current_origin),
                                                                                  ','.join(hijack.original_origin),
                                                                                   bgp_rec.time))
                else if hijacked_prefix == False and legit_prefix == False:
                    print("New prefix:{}->{} advertised by {} at {}".format(prefix,
                                                              as_set,
                                                              vantage_point_asn,
                                                              bgp_rec.time))
                                        
    # end:added by liumin 2020-12-04
    
    def read_bgp_paths(self, start_timestamp, end_timestamp, collectors, target_prefixes, baseline_rtree):
        """
        Function that reads the BGP paths from BGP stream feeds from a specific BGP collector and a given IP prefix

        :param start_timestamp: the start timestamp of the BGP data feed
        :type start_timestamp: int
        :param end_timestamp: the end timestamp of the BGP data feed
        :type end_timestamp: int
        :param collectors: the comma-separated list of collector names from which to get BGP data
        :type collectors: str
        :param target_prefixes: IP prefixes for which to get the BGP paths, or for its sub-prefixes
        :type target_prefixes: set
        :return: None
        """
        prefix_origins = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        bgp_reader = BGPReader("bgpstream")
        collectors_arg = []
        if "all" != collectors:
            for collector in collectors.split(","):
                collectors_arg.append(collector)
        for bgp_elem, bgp_rec in bgp_reader.get_bgp_data(start_timestamp,
                                                         end_timestamp,
                                                         collectors=collectors_arg,
                                                         record_type="ribs",
                                                         prefixes=target_prefixes):
            if 'prefix' in bgp_elem.fields and \
                    bgp_elem.fields['prefix'] != '0.0.0.0/0' and \
                    bgp_elem.fields['prefix'] != "::/0":
                hijacked_prefix = False
                legit_prefix = False
                hijacked_ended = False
                if 'as-path' in bgp_elem.fields:
                    prefix = bgp_elem.fields["prefix"]
                    vantage_point_asn = bgp_elem.fields['as-path'].split()[0]
                    as_path = bgp_elem.fields['as-path'].split()
                    origin_asn = as_path[-1]
                    rnode = baseline_rtree.search_best(prefix)
                    if rnode:
                        baseline_autsys = set(rnode.data["origin"].keys())
                        if len(baseline_autsys & set(as_path)) == 0:
                            if origin_asn.startswith("{"):
                                as_set = set(origin_asn[1:-1].split(","))
                                overlapping_autsys = baseline_autsys & as_set
                                if len(overlapping_autsys) == 0 and not self.is_legit(baseline_autsys, as_set, prefix):
                                    hijacked_prefix = True
                            elif origin_asn not in baseline_autsys and not self.is_legit(baseline_autsys, {origin_asn}, prefix):
                                as_set = {origin_asn}
                                hijacked_prefix = True
                        if hijacked_prefix:
                            if prefix not in self.hijacks:
                                print(
                                    "Hijack: {}->{} advertised by {} instead of {} at {}".format(prefix,
                                                                                                 rnode.prefix,
                                                                                                 as_set, ','.join(
                                            rnode.data["origin"]),
                                                                                                 bgp_rec.time))
                                print(bgp_elem.fields)
                            hijack = self.hijacks.get(prefix, Hijack(prefix, rnode.prefix, as_set, baseline_autsys))
                            hijack.start_ts.append(bgp_rec.time)
                            hijack.visibility.add(vantage_point_asn)
                            self.hijacks[prefix] = hijack
                        elif prefix in self.hijacks and vantage_point_asn in self.hijacks[prefix].visibility:
                           hijacked_ended = True
                elif bgp_elem.type == "W" and bgp_elem.fields["prefix"] in self.hijacks:
                    hijacked_ended = True
                if hijacked_ended:
                    hijack = self.hijacks[bgp_elem.fields['prefix']]
                    vantage_point_asn = str(bgp_elem.peer_asn)
                    if str(bgp_elem.peer_asn) in hijack.visibility:
                        hijack.end_ts.append(bgp_rec.time)
                        hijack.visibility.remove(vantage_point_asn)
                        self.hijacks[bgp_elem.fields['prefix']] = hijack
                        print("Hijack ended: {}->{} by {} instead of {} at {}".format(bgp_elem.fields['prefix'],
                                                                                  hijack.hijacked_prefix,
                                                                                  ','.join(hijack.current_origin),
                                                                                  ','.join(hijack.original_origin),
                                                                                   bgp_rec.time))


def update_origin(snapshot, origin_object, visibility):
    """
    Function that updates the data for a given prefix origin

    :param snapshot: the current BGP snapshot
    :type snapshot: int
    :param origin_object: the prefix origin object
    :type origin_object: PrefixOrigin
    :param visibility: the number of BGP peers that view a prefix announcement with the given origin ASN
    :type visibility: int
    :return: the updated prefix origin object
    :rtype: PrefixOrigin
    """
    #begin: only keep the PO snapshots in the valid aging time window and delete the aged snapshots 
    #origin_object.refresh_first_snapshot()
    
    #end
    if snapshot != origin_object.last_snapshot:
        origin_object.snapshots += 1
        origin_object.last_snapshot = snapshot
    origin_object.visibility += int(visibility)
    # begin: added by liumin 2020-11-28
    origin_object.snapshots_dict[snapshot]= int(visibility)
    origin_object.set_confidence_value()
    # end: added by liumin 2020-11-28
    return origin_object

def new_origin(snapshot, asn, visibility):
    """
    Function that updates the data for a given prefix origin

    :param snapshot: the current BGP snapshot timestamp
    :type snapshot: int
    :param asn: the ASN of the prefix origin
    :type asn: str
    :param visibility: the number of BGP peers that view a prefix announcement with the given origin ASN
    :type visibility: int
    :return: the updated prefix origin object
    :rtype: PrefixOrigin
    """
    origin_object = PrefixOrigin()
    origin_object.asn = asn
    origin_object.snapshots = 1
    origin_object.last_snapshot = snapshot
    origin_object.visibility += int(visibility)
    # begin: added by liumin 2020-11-28
    origin_object.snapshots_dict[snapshot]= int(visibility)
    origin_object.first_snapshot = snapshot
    # end: added by liumin 2020-11-28
    return origin_object
                        
def set_origin(asn, existing_origins, snapshot_date, visibility):
    """
    Sets the origin ASNs of a prefix

    :param asn: the ASN of the prefix origin
    :type asn: str
    :param existing_origins: dictionary that maps ASNs to PrefixOrigin objects
    :type existing_origins: defaultdict
    :param snapshot_date: The date of the snapshot that is being parsed
    :type snapshot_date: int
    :param visibility: The date of the snapshot that is being parsed
    :type visibility: int
    :return: the updated existing_origins dictionary
    :rtype: defaultdict
    """
    # if int(asn) in monitor.assigned_autsys:
    if asn in existing_origins:
        pfx_origin_object = existing_origins[asn]
        pfx_origin_object = update_origin(snapshot_date, pfx_origin_object, visibility)
        existing_origins[asn] = pfx_origin_object
        
    else:
        pfx_origin_object = new_origin(snapshot_date, asn, visibility)
        existing_origins[asn] = pfx_origin_object
    return existing_origins


def get_baseline(baseline_dates_files, start=False):
    """
    Function that aggregates the prefix origins from each BGP snapshot in a radix tree

    :param baseline_dates_files: paths of baseline files per collection date
    :type baseline_dates_files: defaultdict<set>
    :param start: The start date of the parsing period
    :type start: str
    :return: the radix tree with the IP prefixes and their corresponding origin ASNs
    :rtype: radix.Radix
    """

    baseline_files = []
    if start is False:
        start = max(baseline_dates_files.keys())
        baseline_files = baseline_dates_files[start]
    elif start in baseline_dates_files:
        baseline_files = baseline_dates_files[start]
    else:
        logging.error("The baseline files for the requested date do not exist...")
    
    rtree = radix.Radix()
    for filepath in baseline_files:
        print("Filepath {}".format(filepath))
        try:
            with gzip.open(filepath, "rt") as fin:
                for line in fin:
                    lf = line.strip().split()
                    if len(lf) > 1:
                        prefix = lf[0]
                        if prefix not in monitor.bogon_prefixes and prefix != "::/0":
                            rnode = rtree.search_exact(prefix)
                            if not rnode:
                                rnode = rtree.add(prefix)
                                rnode.data["origin"] = defaultdict(PrefixOrigin)
                            asn = lf[1]
                            visibility = int(lf[2])

                            if "{" not in asn:
                                set_origin(asn, rnode.data["origin"], start, visibility)
                            # Handle sets of agreegate origins
                            else:
                                as_set = asn[1:-1].split(",")
                                for asn in as_set:
                                    set_origin(asn, rnode.data["origin"], start, visibility)
                            if len(rnode.data["origin"]) == 0:
                                rtree.delete(prefix)
        except gzip.BadGzipFile as e:
            logging.warning("Skipping file {} due to gzip.BadGzipFile error".format(os.path.basename(filepath)))

    return rtree


def get_baseline_file_dates(input_dir):
    """
    Returns the baseline path ordered by the date of the BGP snapshot based on which they were created
    
    :param input_dir: the path to the directory with the prefix origin data for each BGP snapshot
    :type input_dir: str
    :return:
    :rtype:
    """
    filename_dates = defaultdict(set)
    baseline_files = os.listdir(input_dir)
    for filename in sorted(baseline_files):
        filedate = int(filename.split(".")[0].split("_")[2])
        filepath = os.path.join(input_dir, filename)
        filename_dates[filedate].add(filepath)
    return filename_dates

# begin: added by liumin 2020-11-28
#import mySQL       
def get_prefix_origins_fromRIB(ts_start,ts_end,rtree):
    """
    Function that get the prefix origins from SQL PO tables in which PO mappings have be extracted from RIB snapshots 
    during the time interval from ts_start to ts_end.
    
    :param ts_start,ts_end: the time interval from ts_start to ts_end
    :type ts_start,ts_end: datetime
    :param : the radix tree with the IP prefixes and their corresponding origin ASNs
    :type: radix.Radix
    :return: the radix tree with the IP prefixes and their corresponding origin ASNs
    :rtype: radix.Radix    
    """
    
    prefix_origin_list = [("20200501 08:00:00","216.79.46.0/24","30550",25),("20200501 08:00:00","45.67.216.0/23","61317",20)]
    #prefix_origin_list = GetDataFromTablePo(ts_start,ts_end)
    #print("To get prefix origins from RIB dumps in Mysql from {} to {} ".format(ts_start,ts_end)))
    if len(prefix_origin_list)==0:
        print("There is no available prefix origins in RIB SQLDB over the period from {} to {}! ".format(ts_start,ts_end))
        return rtree
    for po_mapping in prefix_origin_list:
        if len(po_mapping) > 1:
            ts_datetime = datetime.datetime.strptime(po_mapping[0], "%Y%m%d %H:%M:%S")
            snapshot_ts = int(ts_datetime.replace(tzinfo=datetime.timezone.utc).timestamp())
            prefix = po_mapping[1]
            asn = po_mapping[2]
            visibility = po_mapping[3]
            if prefix in monitor.bogon_prefixes or prefix == "::/0":
                continue
            if asn not in monitor.assigned_autsys:
                print("Unassigned AS {} with {}".format(asn,prefix))
                continue
            rnode = rtree.search_exact(prefix)
            if not rnode:
                rnode = rtree.add(prefix)
                rnode.data["origin"] = defaultdict(PrefixOrigin) 
            #set_origin(asn,rnode.data["origin"],snapshot_ts,visibility,assigned_autsys)            
            set_origin(asn,rnode.data["origin"],snapshot_ts,visibility)
    return rtree
#end : added by liumin 2020-11-28 

# begin: added by liumin 2020-11-28
import threading
from threading import Timer

class RepeatingTimer(Timer):
    def run(self):
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)            

def update_prefix_originsfromRIB(rtree):
    """
    Function to update the RIB PO pairs in the radix tree periodically 
    :param rtree: The last radix tree that maps prefixes to origin ASNs before start_ts
    :type rtree: radix.Radix
    :param start_ts: the last time of rtree in memory
    :type start_ts: int
    
    """

    rib_tdelta = datetime.timedelta(hours = 8)
    
    now = datetime.datetime.now()
    update_start = now-rib_tdelta

    
    #rtree_lock.acquire()
    #print("update timer is running at {}".format(now.strftime("%Y-%M-%D %H:%M:%S")))
    rtree = get_prefix_origins_fromRIB(update_start.strftime("%Y%m%d %H:%M:%S"),now.strftime("%Y%m%d %H:%M:%S"),rtree)
    monitor.set_baseline_confidence_value(rtree)
    #rtree_lock.release() 


def detect_hijacks(rtree):
    """
    Function to detect the hijacked prefixes events from BGP update periodically
    :param rtree:
    :type rtree:
    
    """
        
    now = datetime.datetime.now()
    
    update_end_ts = int(now.replace(tzinfo=datetime.timezone.utc).timestamp())
    update_start_ts = update_end_ts - 15*60
    #print("detect timer is running at {}".format(now.strftime("%Y-%M-%D %H:%M:%S")))
    monitor.read_bgp_update(update_start_ts,update_end_ts,rtree)

# end: added by liumin 2020-11-28

def valid_date(s):
    try:
        dt = datetime.datetime.strptime(s, "%Y%m%d")
        if dt.year < 2015:
            msg = "Please select a date after 2015"
            raise argparse.ArgumentTypeError(msg)
        return s
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)
        
def get_user_input():
    """
    Function that gets and parses the input arguments from the user

    :return: the user arguments
    :rtype: an ArgumentParser object
    """
    # Initialize the argument parser
    description = 'Inference of valley-free violations based on AS relationships'
    parser = argparse.ArgumentParser(description=description)
    # Add the permitted arguments
    """
    Begin: deleted by liumin 20201207
    parser.add_argument('-o', '--origins_dir',
                        type=str,
                        required=True,
                        help="The directory that contains the prefix origin files")
    End: 
    """
    parser.add_argument('-r', '--rel_dir',
                        type=str,
                        required=True,
                        help="The directory that contains the AS relationships files")
    parser.add_argument('-s', '--siblings',
                        type=str,
                        required=True,
                        help="The file that contains the siblings ASes")
    parser.add_argument("-d",
                        "--startdate",
                        help="The Start Date - format: YYYYMMDD (min. date: 20150101)",
                        required=True,
                        type=valid_date)
    parser.add_argument("--stability",
                        help="The stability threshold of AS relationships",
                        required=False,
                        default=1,
                        type=int)
    parser.add_argument("-c",
                        "--collectors",
                        help="Comma-separated list of BGP collectors or 'all' to select all collectors",
                        required=False,
                        default='all',
                        type=str)
    args = parser.parse_args()

    if not os.path.isdir(args.origins_dir):
        logging.error("The provided prefix origins directory does not exist!")
        sys.exit(-1)
    if not os.path.isdir(args.rel_dir):
        logging.error("The provided relationships directory does not exist!")
        sys.exit(-1)
    if not os.path.isfile(args.siblings):
        logging.error("The siblings file does not exist!")
        sys.exit(-1)

    return args

if __name__ == '__main__':
    user_args = get_user_input()
    monitor = Monitor(user_args.startdate)
#begin: deleted by liumin 2020-12-1
#baseline_dates_files = get_baseline_file_dates(user_args.origins_dir)
#rtree = get_baseline(baseline_dates_files, start=False)
#end: deleted by liumin 2020-12-1

    # begin: added by liumin 2020-11-28 for the establishment of POes baseline from BGP rib dumps
    rtree = monitor.bgp_rtree
    rtree = get_prefix_origins_fromRIB(monitor.target_datetime.strftime("%Y%m%d %H:%M:%S"),datetime.datetime.now().strftime("%Y%m%d %H:%M:%S"),rtree)
    monitor.set_baseline_confidence_value(rtree)
    # end: added by liumin 2020-11-28


    # begin: added by liumin 2020-11-28
    print("Threading No:{}".format(threading.active_count()))

    rib_tdelta = 8*3600
    update_tdelta = 15*60

    update_timer = RepeatingTimer(rib_tdelta,update_prefix_originsfromRIB,args=[rtree])
    detect_timer = RepeatingTimer(update_tdelta,detect_hijacks,args=[rtree])
    detect_timer.setDaemon(True)
    update_timer.setDaemon(True)
    update_timer.start()
    detect_timer.start()

    import time
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        update_timer.finished.set()
        detect_timer.finished.set()
        print("Ctrl+C interrupt!")
    
    # end: added by liumin 2020-11-28

# begin: deleted by liumin 2020-12-04
"""
prefixes = [ipaddress.IPv4Network(ipaddr) for ipaddr in rtree.prefixes() if '.' in ipaddr]
previous_len = -1
aggregated_prefixes = list()
while len(aggregated_prefixes) < previous_len or previous_len == -1:
    if len(aggregated_prefixes) > 0:
        previous_len = len(aggregated_prefixes)
    aggregated_prefixes = list()
    for aggregate_prefix in ipaddress.collapse_addresses(prefixes):
        aggregated_prefixes.append(aggregate_prefix)
    prefixes = aggregated_prefixes.copy()

target_prefixes = [str(ipaddr) for ipaddr in prefixes]
# target_prefixes = ['216.79.46.0/24']

delta_days = 1
increment_hours = delta_days * 2

delta = datetime.timedelta(days=delta_days)
end_delta = datetime.timedelta(days=28)
current_datetime = monitor.target_datetime
end_datetime = monitor.target_datetime + end_delta
while current_datetime <= end_datetime:
    current_timestamp = int(current_datetime.replace(tzinfo=datetime.timezone.utc).timestamp())
    end_timestamp = current_timestamp + (increment_hours * 3600)
    monitor.read_bgp_paths(current_timestamp, end_timestamp, user_args.collectors, target_prefixes, rtree)
    current_datetime += delta
    break

for hijacked_prefix in monitor.hijacks:
    print(str(monitor.hijacks[hijacked_prefix]))
"""
# end:
