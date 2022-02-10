
#! /usr/bin/python

import os
import csv
from csv import reader, writer
import subprocess
import numpy as np

#### POWER ####----------------
#This function removes the time variable, it does a transpose and merge the all the  csv's of power data
csv_files = os.listdir('Power')
with open('Datasets\\Power_Traces_w_labels.csv', 'w') as fw:
    fw.close()
    #It reads how many lines are i each csv file, it colects and writes in the final csv 
for file in csv_files:
    if file.endswith('.csv'):
        with open('Power\\'+str(file), 'r') as fr:
            with open('Datasets\\trasp.txt', 'w') as ftw:
                writer(ftw, delimiter=',').writerows(zip(*reader(fr, delimiter=',')))
                ftw.close()
        with open('Datasets\\trasp.txt', 'r') as ftr:
            lineas = ftr.readlines()
            print((len(lineas)-2)/2)
            ftr.close()
        with open('Datasets\\Power_Traces_w_labels.csv', 'a') as fa:
            for i in range(len(lineas)):
                if i != 0:
                    fa.write(lineas[i])


#### EM ####----------------
#This function removes the time variable, it does a transpose and merge the all the  csv's of EM data
csv_files = os.listdir('EM')
with open('Datasets\\EM_Traces_w_labels.csv', 'w') as fw:
    fw.close()
for f, file in enumerate(csv_files):
    if file.endswith('.csv'):
        with open('EM\\'+str(file), 'r') as fr:
            with open('Datasets\\traspuesta.txt', 'w') as ftw:
                writer(ftw, delimiter=',').writerows(zip(*reader(fr, delimiter=',')))
        with open('Datasets\\traspuesta.txt', 'r') as ftr:
            lineas = ftr.readlines()
            print((len(lineas)-2)/2) #To is to know the number of traces: the length of the csv /2 (because there is a blank line between each line of data) and -2 to remove time value
            ftr.close()
        with open('Datasets\\EM_Traces_w_labels.csv', 'a') as fa:
            for i in range(len(lineas)):
                if i != 0 and i < 402:
                    fa.write(lineas[i])
