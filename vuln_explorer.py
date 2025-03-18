import matplotlib.pyplot as plt
import datetime
import pandas as pd
import numpy as np


def count_by_vendor(cve_data):
    h = {}
    for val in cve_data['vendor']:
        if val != 'nan':
            if val not in h.keys():
                h[val] = 0
            h[val] += 1
    return h


def count_occurrences(d: pd.DataFrame, v: str):
    result = {}
    for val in d[v]:
        if val not in result.keys():
            result[val] = 0
        result[val] += 1
    return result


def vendor_cve_hist(vulns):
    # look at vendor statistics
    h = count_by_vendor(vulns)
    counts = np.array(list(h.values()))
    indices = np.where(counts > 200)[0]
    lookup = dict(zip(list(h.values()), list(h.keys())))
    labels = [str(lookup[list(h.values())[i]]) for i in indices]
    counts = counts[indices]
    df = pd.DataFrame({'Vendor': labels, 'Counts': counts})
    df = df.sort_values(by=['Counts'])
    plt.bar(df.Vendor[::-1][1:], df.Counts[::-1][1:])
    plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels by 45 degrees and align to the right
    plt.tight_layout()
    plt.xlabel('Brands', fontsize=6)
    plt.ylabel('Number of CVEs')
    plt.show()


def reporter_cve_hist(vulns):
    hunters = count_occurrences(vulns, 'finder')
    odays = np.array(list(hunters.values()))[1:]
    indices = np.where(odays > 100)
    researchers = np.array(list(hunters.keys()))[indices[0]]
    odays = odays[indices[0]]
    df = pd.DataFrame({'researchers': researchers, 'nfinds': odays})
    df = df.sort_values(by=['nfinds'])
    plt.bar(df.researchers[::-1][1:], df.nfinds[::-1][1:])
    plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels by 45 degrees and align to the right
    plt.tight_layout()
    plt.xlabel('Reporter', fontsize=6)
    plt.ylabel('Number of CVEs')
    plt.show()


def find_cves_by_vendor(vendor, vulns):
    indices = np.where(np.array(vulns['vendor']) == vendor)
    return vulns.iloc[indices]


def count_vulns(vulns):
    n_rows = vulns.shape[0]
    data = {}
    for ii in range(n_rows):
        row = vulns.iloc[ii]
        date = datetime.datetime.timestamp(datetime.datetime.fromisoformat(row[2]))
        product = row[4]
        reporter = row[5]
        details = row[6]
        if product not in data.keys():
            data[product] = {'dates': [date],
                             'detail': [details],
                             'total': [1]}
        else:
            data[product]['dates'].append(date)
            data[product]['detail'].append(details)
            data[product]['total'].append(data[product]['total'][-1]+1)
    return data


def find_most_vulns(vuln_counts):
    largest = 0
    most_vulns = []
    for product in vuln_counts.keys():
        nvulns = vuln_counts[product]['total'][-1]
        if nvulns > largest:
            largest = nvulns
            most_vulns.append(product)
    return most_vulns


def get_generic_product_vuln_slope(product, counts):
    x = counts[product]['dates']
    y = counts[product]['total']
    # linear fit
    # Linear fit
    linear_coefficients = np.polyfit(x, y, 1)
    linear_polynomial = np.poly1d(linear_coefficients)

    # Quadratic fit
    quadratic_coefficients = np.polyfit(x, y, 2)
    quadratic_polynomial = np.poly1d(quadratic_coefficients)

    # To get the y values for the fitted lines:
    linear_y = linear_polynomial(x)
    quadratic_y = quadratic_polynomial(x)

    linear = {'line': linear_y, 'coeff': linear_coefficients}
    quad = {'line': quadratic_y, 'coeff': quadratic_coefficients}
    return linear, quad, x, y


def examine_vuln_slope(most_issues, counts):
    x = counts[most_issues[-1]]['dates']
    y = counts[most_issues[-1]]['total']
    # Linear fit
    linear_coefficients = np.polyfit(x, y, 1)
    linear_polynomial = np.poly1d(linear_coefficients)

    # Quadratic fit
    quadratic_coefficients = np.polyfit(x, y, 2)
    quadratic_polynomial = np.poly1d(quadratic_coefficients)

    # To get the y values for the fitted lines:
    linear_y = linear_polynomial(x)
    quadratic_y = quadratic_polynomial(x)

    print("Linear coefficients:", linear_coefficients)
    print("Quadratic coefficients:", quadratic_coefficients)
    plt.plot(x, quadratic_y, color='k')
    plt.scatter(x, y, color='b')
    plt.show()
    linear = {'line': linear_y, 'coeff': linear_coefficients}
    quad = {'line': quadratic_y, 'coeff': quadratic_coefficients}
    return linear, quad


def unique(l: list):
    u = []
    for e in l:
        if e not in u:
            u.append(e)
    return u


def plot_cve_rates(products, brand_counts, brand_name):
    rates = {}
    for product in products:
        counts = brand_counts[product]
        linear_fit, quadratic_fit, x, y = get_generic_product_vuln_slope(product, brand_counts)
        plt.scatter(x, quadratic_fit['line'])
    plt.legend(products, fontsize=8)
    plt.xlabel('Time [long]')
    plt.ylabel('N CVEs')
    plt.title(f'{brand_name} CVEs over Time')
    plt.show()





if __name__ == '__main__':
    vulns = pd.read_csv('cve_data.csv')

    # vendors with most CVEs
    vendor_cve_hist(vulns)

    reporter_cve_hist(vulns)
    # look at who finds the most CVEs

    microsoft_vulns = find_cves_by_vendor('Microsoft', vulns)
    # look at number of CVEs over time
    microsoft_counts = count_vulns(microsoft_vulns)
    most_troubled_msft = find_most_vulns(microsoft_counts)
    msft_linear, msft_quadratic = examine_vuln_slope(most_troubled_msft, microsoft_counts)

    apple_vulns = find_cves_by_vendor('Apple', vulns)
    most_troubled_apple = find_most_vulns(apple_vulns)
    apple_counts = count_vulns(apple_vulns)
    apple_linear, apple_quadratic = examine_vuln_slope(most_troubled_apple, apple_counts)

    huawei_vulns = find_cves_by_vendor('Huawei', vulns)
    huawei_counts = count_vulns(huawei_vulns)
    most_troubled_huawei = find_most_vulns(huawei_counts)
    huawei_linear, huawei_quadratic = examine_vuln_slope(most_troubled_huawei, huawei_counts)

    plot_cve_rates(most_troubled_msft, microsoft_counts)
    plot_cve_rates(most_troubled_huawei, huawei_counts)
    plot_cve_rates(most_troubled_apple, apple_counts)

    #show them all
    # all_vendors = unique(vulns['vendor'])
    # for company in all_vendors[1:50]:
    #     misc_vulns = find_cves_by_vendor(company, vulns)
    #     misc_counts = count_vulns(misc_vulns)
    #     plot_cve_rates(most_troubled_misc, misc_counts, company)
    #     most_troubled_misc = find_most_vulns(misc_counts)
    from svm import *


