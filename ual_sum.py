# UAL JSON Summary Generator

# Total count of operation, workload and recordtype

# For when conducting IR activities against M365, especially if you are pulling a scoped dataset using Powershell or one of the APIs, as the name suggests, it must be JSON.

import json
from collections import Counter, defaultdict
import argparse
from datetime import datetime
import sys

time_format = "%Y-%m-%dT%H:%M:%SZ"

def parse_args():
    parser = argparse.ArgumentParser(description="UAL Summary Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to the UAL JSON log file")
    parser.add_argument("-s", "--summary", action="store_true", help="Print summary of the data")
    parser.add_argument("-u", "--user", required=False, help="Provide a user email to summarize their activity")
    parser.add_argument("-qs", "--quicksummary", action="store_true", dest="quicksummary", help="Quick overview of data available")
    parser.add_argument('-o', '--outputfile', type=str, help="File to write the output. If omitted, prints to console.")
    parser.add_argument('-ignore', action="store_true",required=False,dest="ignore", help="Ignores the error for -s to console (small dataset?).")
    return parser.parse_args()

def main():
    args = parse_args()
    outfile = open(args.outputfile, 'w') if args.outputfile else None

    try:
        with open(args.file) as f:
            print(f"Found file: {args.file}")
            if not args.file.lower().endswith(".json"):
                print("Requires a .json file - yes requires extension")
                exit()
            data = json.load(f)
            # check for malformed
            for entry in data:
                if not entry.get("Workload") or not entry.get("Operation"):
                    print("Common fields not found, likely corrupt or incorrect format")
                    areUSure = input("Do you still want to try and parse the file? Likely it will fail [yes/no]: ").lower()
                    if areUSure not in ("yes", "y"):
                        exit()
                    else:
                        print("Ok, continuing parsing anyway")
                    break  # no need to check further once alerted

    except FileNotFoundError:
        print("Error: File not found")
        exit()
    except IOError as e:
        print(f"Error opening file: {e}")
        exit()
    except json.decoder.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON — {e}, doesn't appear to be a valid JSON file.")
        exit()
        
        
        ### AHHHH dodging ###
    if args.summary and not args.outputfile and not args.ignore:
        confirm = input(
            "WARNING: The detailed summary (-s) can output a LOT of data.\n"
            "Are you sure you want to continue printing to the console? (yes/no): "
        ).strip().lower()
        if confirm not in ('yes', 'y'):
            print("Aborting per user request.")
            if outfile:
                outfile.close()
            exit()
        
    ### HELPERS - to be enriched ###

    def ipSum(data, outfile=None):
        print("\nIPs:", file=outfile)
        ip_counts = Counter(entry["ClientIP"] for entry in data if "ClientIP" in entry)
        for ip, count in ip_counts.most_common():
            print(f"{ip:<20} Count: {count}", file=outfile)

    def pullWorkloadAndOperation(data, outfile=None):
        print("\nWorkloads:", file=outfile)
        workloads = Counter(entry.get("Workload") for entry in data if entry.get("Workload"))
        for workload, count in sorted(workloads.items(), key=lambda x: x[1], reverse=True):
            print(f"{workload:<20} Count: {count}", file=outfile)

        print("\nOperations:", file=outfile)
        operations = Counter(entry.get("Operation") for entry in data if entry.get("Operation"))
        for op, count in operations.most_common():
            print(f"{op:<20} Count: {count}", file=outfile)

    def userSum(data, outfile=None):
        print("\nUsers:", file=outfile)
        users = Counter(entry.get("UserId") for entry in data if entry.get("UserId"))
        for user, count in users.most_common():
            print(f"{user:<30} Count: {count}", file=outfile)

    def timeRange(scope_date, outfile=None):
        time_strings = [entry.get("CreationTime") for entry in scope_date if entry.get("CreationTime")]
        if not time_strings:
            print("No CreationTime values found.", file=outfile)
            return
        parsed_times = [datetime.strptime(t, time_format) for t in time_strings]
        earliest = min(parsed_times)
        latest = max(parsed_times)
        print(f"Earliest Event: {earliest}", file=outfile)
        print(f"Latest Event: {latest}", file=outfile)
    
   #### OVERVIEW SUMMARY ### 
    def overviewSummary(data,outfile=sys.stdout): #mby not needed
        #top talkers - op, wl (to be expanded so seperate functions for now)
        print("=== Summary of Data Available ===", file=outfile)
        timeRange(data, outfile)
        pullWorkloadAndOperation(data, outfile)
        userSum(data, outfile)
        ipSum(data, outfile)

    # anomalies such as 1 user with multiple IPs
    # 1 user performing a lot of activity
    # a rare user

#### DETAILED SUMMARY ####
    def detailedSummary(query, user_oi=None,outfile=sys.stdout):  # maybe needs to be split further
        workload_operations = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))
        
        for entry in data:
            if "Workload" in entry and "Operation" in entry:
                workload = entry["Workload"]
                operation = entry["Operation"]
                user = entry.get("UserId") or entry.get("Failover", "")
                cIp = entry.get("ClientIP", "")
                workload_operations[workload][user][cIp][operation] += 1

        if query == 1:
            print("\n=== Data Summary Statistics ===", file=outfile)
            timeRange(data, outfile)
            for workload, users in workload_operations.items():
                print(f"\nWorkload: {workload}", file=outfile)
                for user, ips in users.items():
                    print(f"  User: {user}", file=outfile)
                    for cIp, operations in ips.items():
                        print(f"    ClientIP: {cIp}", file=outfile)
                        for operation, count in operations.items():
                            print(f"      {operation}: {count}", file=outfile)
            findEvil(data, query,outfile=outfile)
  #### SPECIFIC USER QUERY ####          
        else:
            filtered_data = [entry for entry in data if entry.get("UserId") == user_oi]
            if not filtered_data:
                print(f"No data found for user: {user_oi}", file=outfile)
                return

            print(f"\nSummary of {user_oi} activities\n", file=outfile)
            timeRange(filtered_data, outfile=outfile)

            # Rebuild workload_operations but only for filtered_data
            workload_operations_filtered = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))
            for entry in filtered_data:
                if "Workload" in entry and "Operation" in entry:
                    workload = entry["Workload"]
                    operation = entry["Operation"]
                    user = entry.get("UserId") or entry.get("Failover", "")
                    cIp = entry.get("ClientIP", "")
                    workload_operations_filtered[workload][user][cIp][operation] += 1

            for workload, users in workload_operations_filtered.items():
                print(f"\nWorkload: {workload}", file=outfile)
                for user, ips in users.items():
                    # Should only be one user, but loop anyway
                    print(f"  User: {user}", file=outfile)
                    for cIp, operations in ips.items():
                        print(f"    ClientIP: {cIp}", file=outfile)
                        for operation, count in operations.items():
                            print(f"      {operation}: {count}", file=outfile)  # added file=outfile here

            ip_addresses = [entry.get("ClientIP") for entry in filtered_data if entry.get("ClientIP")]
            useragents = [entry.get("UserAgent") for entry in filtered_data if entry.get("UserAgent")]

            findEvil(filtered_data, query, ip_addresses, useragents, outfile)


#### FIND EVIL #### 
    def findEvil(data, query, ip_addresses=None, useragents=None,outfile=sys.stdout):
        print("\n=== FindEvil Summary Statistics ===", file=outfile)
        if query == 1:
            users = Counter(entry.get("UserId") for entry in data if entry.get("UserId"))
            ips = Counter(entry.get("ClientIP") for entry in data if entry.get("ClientIP"))
            agents = Counter(entry.get("UserAgent") for entry in data if entry.get("UserAgent"))

            print("\nBusiest Users:", file=outfile)
            for user, count in users.most_common(5):
                print(f"{user:<30} Events: {count}", file=outfile)

            print("\nRare Users:", file=outfile)
            for user, count in users.most_common()[-5:]:
                print(f"{user:<30} Events: {count}", file=outfile)

            print("\nNoisiest IPs:", file=outfile)
            for ip, count in ips.most_common(5):
                print(f"{ip:<20} Events: {count}", file=outfile)

            print("\nRare IPs:", file=outfile)
            for ip, count in ips.most_common()[-5:]:
                print(f"{ip:<20} Events: {count}", file=outfile)

            print("\nNoisiest User Agents:", file=outfile)
            for agent, count in agents.most_common(5):
                print(f"{agent:<60} Events: {count}", file=outfile)

            print("\nRare User Agents:", file=outfile)
            for agent, count in agents.most_common()[-5:]:
                print(f"{agent:<60} Events: {count}", file=outfile)
        else:
            print("\n--- IP Address Summary ---", file=outfile)
            ips = Counter(ip_addresses)
            for ip, count in ips.most_common():
                print(f"{ip:<20} Count: {count}", file=outfile)
            print(f"\nTotal unique IPs: {len(ips)}", file=outfile)

            print("\n--- User Agent Summary ---", file=outfile)
            uas = Counter(useragents)
            for ua, count in uas.most_common():
                print(f"{ua:<60} Count: {count}", file=outfile)
            print(f"\nTotal unique UAs: {len(uas)}", file=outfile)

    if args.quicksummary:
        overviewSummary(data, outfile)
        print(f"\n[Overview output generated at {datetime.now()}]", file=outfile)
        if outfile:
            print(f"Saved to {args.outputfile}")

    if args.summary:
        detailedSummary(1, outfile=outfile)
        print(f"\n[Detailed Summary output generated at {datetime.now()}]", file=outfile)
        if outfile:
            print(f"Saved to {args.outputfile}")

    if args.user:
        detailedSummary(0, args.user, outfile=outfile)
        print(f"\n[Summary for user {args.user}]", file=outfile)
        if outfile:
            print(f"Saved to {args.outputfile}")
        
    if args.outputfile:
        outfile.close()


if __name__ == "__main__":
    print("crazy ascii uwu")
    main()
