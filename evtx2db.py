import pandas
import os
import json
import sqlite3
import sys
import numpy as np
import subprocess
import shutil
from itertools import groupby
from operator import itemgetter
import argparse


def gen_command(indir):
    if not os.path.exists("utils/tmp"):
        os.mkdir("utils/tmp")
    intput_folder = os.path.abspath(indir)
    proc = subprocess.call(["./utils/dump_evtx.sh", str(intput_folder)])
    dfs = []
    for file in os.listdir("utils/tmp/"):
        dfs.append(get_event_records(file))
    return dfs


def get_event_records(filename):
    fpath = os.path.join("utils/tmp", filename)
    with open(fpath, "r") as f:
        file_content = f.readlines()
    fixed = []
    events = []
    d = " }{"
    for line in file_content:
        if d in line:
            new_line = line.replace(d, "}NEWJSON{")
            fixed.append(new_line)
        else:
            fixed.append(line)
    fixed_file = "".join(fixed)
    jsons = fixed_file.split("NEWJSON")
    for i in range(len(jsons)):
        json_dat = json.loads(jsons[i])
        json_dat["Filename"] = os.path.basename(filename).replace(".txt", "")
        events.append(json_dat)
    df = pandas.DataFrame(
        events, columns=["Filename", "System", "UserData", "EventData"]
    )
    return df


def events_to_data_frame(dfs):
    df = pandas.concat(dfs).reset_index(drop=True)
    df_sys = pandas.json_normalize(df["System"])
    df_sys = df_sys.applymap(lambda x: np.nan if isinstance(x, str) and x == "" else x)
    df_sys["Filename"] = df["Filename"]
    cols = ["Version", "Opcode", "Execution.ProcessID", "Execution.ThreadID"]
    df_sys[cols] = df_sys[cols].astype("Int64")
    df_sysinfo = df_sys[
        [
            "Version",
            "Level",
            "Task",
            "Opcode",
            "Keywords",
            "Provider.Guid",
            "Provider.Name",
        ]
    ]
    df_sys["Sysinfo"] = df_sysinfo.apply(
        lambda x: json.dumps(x.dropna().to_dict(), indent=4), axis=1
    )
    df_sys = df_sys.drop(
        ["Version", "Level", "Task", "Opcode", "Keywords", "Provider.Guid"], axis=1
    )
    df_sys = df_sys.rename(
        columns={
            "TimeCreated.SystemTime": "Timestamp",
            "Execution.ProcessID": "PID",
            "Execution.ThreadID": "ThreadID",
            "Security.UserID": "SID",
            "Provider.Name": "Provider",
            "EventID.Value": "EventID",
        }
    )
    df_sys["EventData"] = df["EventData"].apply(
        lambda x: json.dumps(x, indent=4) if type(x) != float else x
    )
    df_sys["UserData"] = df["UserData"].apply(
        lambda x: json.dumps(x, indent=4) if type(x) != float else x
    )
    df_sys["Timestamp"] = pandas.to_datetime(df_sys["Timestamp"], unit="s").dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    df_sys = df_sys[
        [
            "EventRecordID",
            "Timestamp",
            "EventID",
            "Computer",
            "EventData",
            "Sysinfo",
            "Provider",
            "SID",
            "UserData",
            "PID",
            "ThreadID",
            "Channel",
            "Filename",
        ]
    ]
    return df_sys


def event_descr(item, data):
    keys = list(data.keys())
    provx = item["Provider"]
    idx = item["EventID"]
    if provx in keys:
        if str(idx) in data[provx].keys():
            resu = data[provx][str(idx)]
            if resu == "":
                res_ = "NA"
            else:
                res_ = resu
            item["Description"] = res_
    elif provx.replace(" ", "-") in keys:
        if str(idx) in data[provx.replace(" ", "-")].keys():
            resu = data[provx.replace(" ", "-")][str(idx)]
            if resu == "":
                res_ = "NA"
            else:
                res_ = resu
            item["Description"] = res_
    return item


def parse_4104(df, output_dir):
    def key_func(k):
        return k["ScriptBlockId"]

    event_id_4104 = list(df.loc[df["EventID"] == 4104]["EventData"])
    if not event_id_4104:
        return
    scripts_4104 = [json.loads(x) for x in event_id_4104]
    scripts_ = {
        k: list(v) for k, v in groupby(sorted(scripts_4104, key=key_func), key_func)
    }
    for k, v in scripts_.items():
        script_val = sorted(scripts_[k], key=itemgetter("MessageNumber"))
        res = "".join([x["ScriptBlockText"] for x in script_val])
        fname = os.path.join(output_dir, "script_id_" + str(k) + ".txt")
        with open(fname, "w") as of:
            of.write(res)


def main():
    parser = argparse.ArgumentParser(
        description="Parse Windows Events to Sqlite DB",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        help="Path to Windows/Logs directory",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        help="Output Directory to save Files/DB to",
        required=True,
    )
    parser.add_argument(
        "-e",
        "--extract",
        required=False,
        help="If PowerShell event ID 4104 is in the Logs, rebuild the ScriptBlockTexts, this is saved to the directory you run the script from",
        action="store_true",
    )

    args = parser.parse_args()
    directory = args.input
    out_dir = args.output
    if not os.path.exists(out_dir):
        print("The output directory does not exist, creating now...")
        os.mkdir(out_dir)
    if not os.path.exists(directory):
        print("The input directory does not exist, exiting ...")
        sys.exit(1)
    output_dir = os.path.abspath(out_dir)
    db_name = os.path.join(output_dir, "timeline.db")
    json_name = "utils/win_11.json"
    event_records = gen_command(directory)
    df_evt = events_to_data_frame(event_records)
    print("Found " + str(len(df_evt)) + " records in the EventLogs!")
    shutil.rmtree("utils/tmp", ignore_errors=True)
    df_evt["Description"] = ""
    with open(json_name, "r") as inf:
        data = json.load(inf)
    df_evt = df_evt.apply(lambda r: event_descr(r, data), axis=1)
    if args.extract:
        parse_4104(df_evt, output_dir)
    connection = sqlite3.connect(db_name)
    df_evt.to_sql("Timeline", connection, if_exists="replace", index=False)
    print("Wrote records to " + str(db_name))
    connection.close()
    # df = pandas.read_sql("SELECT * FROM Timeline;", connection)


if __name__ == "__main__":
    main()
