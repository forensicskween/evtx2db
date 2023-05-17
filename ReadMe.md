===========

evtx2db
----------
This is a python script that parses Windows .evtx files and saves the records to a SQLite database. Where possible, the description of the Event ID is added, which can help understand what's happening. There is also an option of extracting and reconstructing the 'ScriptBlockText' associated with PowerShell event ID 4104.

Requirements
------------
The script uses the subprocess command to parse evtx files with 'dumpevtx', written in Go. Before anything, you must install dumpevtx and verify that it's in your path. Otherwise, it will fail. Secondly, the json.xz files in the utils directory need to be uncompressed, it can be done with the command:
 `unxz utils/*.xz ` . Finally, make sure you give execution permissions to dump_evtx.sh:  `chmod +x utils/dump_evtx.sh ` . Normally, it should work fine. 


Usage
------------
The -extract option is optional, this is if you want to try and rebuild PowerShell event ID 4104 Scripts. Otherwise, you must specify the input path to the Logs directory, and specify an output directory where to save the database.

    python3 evtxdb.py -i path/to/winevt/Logs -o path/to/output -e [optional]


Python Dependencies
------------
The libraries used can be installed with. Honestly, shutil is not 100% necessary, you can just remove the folder created by dumpevtx manually.

    pip install pandas numpy sqlite3 shutil
