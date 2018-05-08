import csv
import requests
import argparse

parent = {}
status = {}
release_id = {}
cve_tickets = []


def read_cve_json_file():
    """
    Read CVE json data
    :return: json response
    """
    response = requests.get('https://security-tracker.debian.org/tracker/data/json')
    return response.json()


def read_cve_list_file(filepath):
    """
    :param filepath: file to read the CVE tickets
    :return:
    """
    lines = []
    with open(filepath) as fd:
        for line in fd:
            lines.append(line.strip())
    return lines


def update_data(filepath):
    """
    :return: Update dictionaries for each bugs number
    """
    cve_tickets.extend(read_cve_list_file(filepath))
    cve = read_cve_json_file()
    for ticket in cve_tickets:
        for cv in cve:
            for c in cve[cv]:
                if ticket == c:
                    for release in cve[cv][c]['releases']:
                        if release == 'stretch':
                            parent[ticket] = cv
                            status[ticket] = cve[cv][c]['releases'][release]['status']
                            release_id[ticket] = cve[cv][c]['releases'][release]['repositories']['stretch']


def write_data_to_csv():
    """
    Write data to CSV file
    :return:
    """
    with open('match_list.csv', 'w') as csvfile:
        data = csv.writer(csvfile, delimiter=',')
        data.writerow([
            'ticket', 'component', 'status', 'release_id', 'link'])
        for ticket in cve_tickets:
            link = 'https://security-tracker.debian.org/tracker/%s' % ticket
            if ticket in parent:
                data.writerow([ticket, parent[ticket], status[ticket], release_id[ticket], link])
            else:
                data.writerow([ticket, 'NA', 'NA', 'NA', link])


def parse_options():
    """
     Builds the options list.
    :return: parsed object
    """
    descr = "Get CVE bugs status and info"
    parser = argparse.ArgumentParser(
        description=descr,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '-file_path',
        '--file_name_and_path',
        dest="filepath",
        required=True,
        help="File name to read CVE bugs with absolute path")
    return parser.parse_args()


def main():
    args = parse_options()
    update_data(args.filepath)
    write_data_to_csv()


if __name__ == "__main__":
    main()
