#!/bin/bash
find "$@" -name "*.evtx" -size +69k -print0 | while read -d $'\0' file;
do dumpevtx parse "${file}" --output="${file}.txt" 2>/dev/null;
   mv "${file}.txt" utils/tmp/;
done
