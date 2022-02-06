
#! /usr/bin/python

import os
import csv
import random
from csv import reader, writer
import numpy as np


#### POWER ####----------------
csv_files = os.listdir('Power')
#To be understood by the algorithm the name of each file must have their numerical equivalent
names = "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15","16", "17","18", "19"
#names = ["E0101", "E0102", "E0103", "E0104", "E0105", "E0106", "E0201", "E0202", "E0203", "E0204", "E0205", "E0206","E0207", "E0208", "E0209", "E0210", "SUT00F", "SUT00I"]
#Here it is necessary to specify the number of traces for each file
traces = [108, 110, 108, 108, 108, 108, 108, 108, 108, 108, 108, 174, 108, 126, 125, 151, 161, 182, 194]
i = -1
#It is necessary to have every csv file in the same folder 
for file in csv_files:
    if file.endswith('.csv'):
        i = i + 1
        with open('Power\\'+str(file), 'a') as fa:
            for enum in range(traces[i]):
                fa.write(names[i]+',')
            fa.write(names[i])


#### EM ####----------------
csv_files = os.listdir('EM')
#To be understood by the algorithm the name of each file must have their numerical equivalent
names = "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19"
#Here it is necessary to specify the number of traces for each file
traces = [500, 500, 200, 200, 200, 200, 200, 200, 500, 500, 500, 160, 500, 184, 199, 73, 88, 92, 89, 500]
i = -1
#It is necessary to have every csv file in the same folder 
for file in csv_files:
    if file.endswith('.csv'):
        i = i + 1
        with open('EM\\'+str(file), 'a') as fa:
            for enum in range(traces[i]):
                fa.write(names[i]+',')
            fa.write(names[i])
