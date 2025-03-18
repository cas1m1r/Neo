#
from vuln_explorer import unique
import pandas as pd
import datetime
import random
import json
import os

current = os.getcwd()

class DataLoader():
    def __init__(self, curDir=current):
        self.root_dir = curDir
        self.years = []
        for i in range(1999,2025,1):
            self.years.append(str(i))
        self.cve_data = self.create_cve_table()
        self.cve_data.to_csv('cve_data.csv',index=False)

    def create_cve_table(self):
        cve_dir = os.path.join(self.root_dir,'cvelistV5','cves')
        all_files = find_files(cve_dir,{})
        master_table = {'CVE':[],'date':[],'vendor':[],'product':[],'finder':[],'details': [], 'reference':[],
                        'vuln_class': [], 'Impact': [],'AttackVector':[],'Severity': [],'complexity':[],
                        'requiredPrivilege': []}
        cve_count = 0
        file_list = list(all_files.keys())
        random.shuffle(file_list)
        for year in file_list:
            parts = os.path.split(year)
            yr = os.path.split(parts[0])[1]
            if yr in self.years:
                cve_list = all_files[year]
                # clean_table = {}
                print(f'[+] Generating table of {len(cve_list)} CVEs in {yr}')
                for cve_loc in cve_list:
                    # Load the file
                    try:
                        cve_info = json.loads(open(cve_loc, 'r').read())
                    except UnicodeError:
                        print(f'[X] Unable to read {cve_loc}')
                        continue
                    # Get Date CVE Was Published
                    date_published = get_date_published(cve_info)

                    # pull CVE-ID
                    id = get_cve_id(cve_info)
                    finder = get_cve_finder(cve_info)
                    details = get_cve_details(cve_info)
                    product = get_cve_product(cve_info)
                    vendor  = get_cve_vendor(cve_info)
                    primary_reference = get_cve_reference(cve_info)

                    impact, vector, severity, complexity,privilege = get_attack_matrix(cve_info)
                    try:
                        # Add new row to table by adding each columns element individually
                        master_table['CVE'].append(id)
                        master_table['finder'].append(finder)
                        master_table['details'].append(details)
                        # attempt to loosely classify/categorize CVE by detail to add features
                        master_table['vuln_class'].append(classify_cve(details))
                        master_table['date'].append(date_published)
                        master_table['vendor'].append(vendor)
                        master_table['product'].append(product)
                        master_table['reference'].append(primary_reference)
                        master_table['Impact'].append(impact)
                        master_table['AttackVector'].append(vector)
                        master_table['Severity'].append(severity)
                        master_table['complexity'].append(complexity)
                        master_table['requiredPrivilege'].append(privilege)
                        cve_count += 1
                        if cve_count % 1000 == 0:
                            print(f'[+] {cve_count} CVEs Added to table')
                    except KeyError:
                        pass


        return pd.DataFrame(master_table)

def classify_cve(vuln_details):
    categories = {0: 'Unknown',
                  }

    words = vuln_details.lower()
    # DoS
    if contains(words,'denial of service') or contains(words,'crash') or contains(words,'flood') or contains(words, 'dos'):
        type = 1
    # Buffer/Stack overflows
    elif contains(words,'buffer overflow') or contains(words, 'Integer Overflow') or contains(words,'overflow'):
        type = 2
    # other memory safety
    elif contains(words,'memory leak') or contains(words,'memory') or contains(words,'corrupt') or contains(words, 'dereference'):
        type = 3
    # injections
    elif contains(words,'inject') or contains(words,'sqli') or contains(words, 'xxe'):
        type = 4
    # misconfigurations
    elif contains(words,'sensitive') or contains(words,'config') or contains(words,'information') or contains(words,'confidential') or contains(words, 'protection'):
        type = 5
    # crypto weaknesses
    elif contains(words,'encrypt') or contains(words,'decrypt') or contains(words, 'secret'):
        type = 6
    # access control bypass
    elif contains(words,'bypass') or contains(words, 'access') or (contains(words,'login') and contains(words, 'redirect')):
        type = 7
    # RCE
    elif contains(words,'execut') or contains(words,'command') or contains(words,'remote') and contains(words,'code'):
        type = 8
    # LFI
    # file creation/deletion
    elif contains(words,'delet') or contains(words,'upload') or contains(words,'file') or contains(words,'listing'):
        type = 9
    # LPE
    elif contains(words,'privilege') or contains(words, 'permission') or contains(words, 'escalation'):
        type = 10
    # spoofing?
    elif contains(words,'spoof') or contains(words,'connect') or contains(words,'modif') or contains(words, 'craft') or contains(words, 'packet lengths'):
        type = 11
    # cache poisoning
    elif contains(words, 'cache') and contains(words,'poison'):
        type = 12
    # identity/auth
    elif contains(words,'session') or contains(words,'key') or contains(words,'auth') or contains(words,'password'):
        type = 13
    # deserialization
    elif contains(words, 'deserial'):
        type = 14
    # csrf
    elif contains(words, 'csrf') or contains(words, 'request forgery'):
        type = 15
    # xss
    elif contains(words,'xss'):
        type=16

    # do not use
    elif contains(words, 'do not use'):
        type = 17
    elif contains(words, 'unspecified vulnerability'):
        type = 18
    else:
        type = 0
    return type


def contains(data, substr):
    return data.find(substr)>=0


def pull_metric_info(metric_data):
    impact = '';
    vector = '';
    severity = '';
    complexity = '';
    privilege = ''
    cvss_ver = ''
    for key in metric_data.keys():
        if key.find('cvs')>=0:
            cvss_ver = key
    if cvss_ver == '':
        return impact, vector, severity, complexity,privilege
    cve_breakdown = metric_data[cvss_ver]

    try:
        impact = cve_breakdown['baseScore']
        severity = cve_breakdown['baseSeverity']
        if 'attackVector' in cve_breakdown.keys():
            vector = cve_breakdown['attackVector']
        elif 'vectorString' in cve_breakdown.keys():
            vector = cve_breakdown['vectorString']
        complexity = cve_breakdown['attackComplexity']
        privilege = cve_breakdown['privilegesRequired']
    except KeyError:
        pass
    return impact, vector, severity, complexity,privilege

def find_files(path:str, dir_data:dict):
    if path not in dir_data.keys():
        dir_data[path] = []
    for element in os.listdir(path):
        loc = os.path.join(path, element)
        if os.path.isfile(loc):
            dir_data[path].append(loc)
        else: # recursiion
            dir_data= find_files(loc,dir_data)
    return dir_data


def get_date_published(cve_info):
    try:
        if 'datePublished' in cve_info['cveMetadata'].keys():
            date_published = datetime.datetime.fromisoformat(cve_info['cveMetadata']['datePublished'])
        else:
            date_published = '?'
    except ValueError:
        date_published = datetime.datetime.fromisoformat(cve_info['cveMetadata']['datePublished'].replace("Z", "+00:00"))
        pass
    return date_published


def get_cve_id(cve_info):
    if 'cveMetadata' in cve_info.keys():
        id = cve_info['cveMetadata']['cveId']
    else:
        id = ''
    return id


def get_cve_finder(cve_info):
    if 'cveMetadata' in cve_info.keys():
        if 'assignerShortName' in cve_info['cveMetadata'].keys():
            finder = cve_info['cveMetadata']['assignerShortName']
        elif 'adp' in cve_info['containers'].keys():
            adp = cve_info['containers']['adp']
            if type(adp) == list and 'providerMetadata' in adp[-1].keys():
                finder = adp[-1]['providerMetadata']['shortName']
            else:
                finder = ''
        else:
            finder = ''
    else:
        finder = '?'
    return finder

def get_cve_details(cve_info):
    cna = cve_info['containers']['cna']

    if type(cna)==dict and 'descriptions' in cna.keys():
        details = cna['descriptions'][0]['value']
    elif type(cna)==dict:
        if 'rejectedReasons' in cna.keys():
            details = cna['rejectedReasons'][0]['value']
        else:
            details = ''
    else:
        details = ''
    return details

def get_cve_product(cve_info):
    cna = cve_info['containers']['cna']

    if type(cna) == dict and 'affected' in cna.keys():
        try:
            product = cna['affected'][0]['product']
        except KeyError:
            if 'packageName' in cna['affected'][0].keys():
                product = cna['affected'][0]['packageName']
            else:
                product = ''
            pass
    else:
        product = '?'
    return product

def get_cve_vendor(cve_info):
    cna = cve_info['containers']['cna']
    if type(cna) == dict and 'affected' in cna.keys():
        try:
            vendor = cna['affected'][0]['vendor']
        except KeyError:
            if 'providerMetadata' in cna.keys():
                vendor = cna['providerMetadata']['shortName']
            else:
                vendor = ''
            pass
    else:
        vendor = '?'
    return vendor

def get_cve_reference(cve_info):
    cna = cve_info['containers']['cna']

    if type(cna) == dict and 'references' in cna.keys():
        reference = cna['references'][0]['url']
    else:
        reference = '?'
    return reference


def get_attack_matrix(cve_info):
    impact, vector, severity, complexity, privilege = '?','?','?','?','?'

    cna = cve_info['containers']['cna']
    if 'metrics' in cna.keys():
        if type(cna['metrics']) == list:
            metrics = cna['metrics'][0]
            impact, vector, severity, complexity,privilege = pull_metric_info(metrics)
        else:
            metrics = {}
    return impact, vector, severity, complexity, privilege

if __name__ == '__main__':
    cve_data_set = DataLoader()
    df = cve_data_set.cve_data
    df.to_csv('cve_data.csv')