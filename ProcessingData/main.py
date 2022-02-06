import random
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import statistics
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn import metrics
from sklearn.metrics import confusion_matrix
from sklearn.decomposition import PCA
from sklearn.cluster import OPTICS
from sklearn.cluster import MeanShift, estimate_bandwidth
import scipy.cluster.hierarchy as shc
from sklearn.neighbors import NearestNeighbors
from scipy.fft import rfft, rfftfreq
from sklearn.metrics.cluster import normalized_mutual_info_score

#from sklearn.naive_bayes import GaussianNB
#from sklearn.neighbors import KNeighborsClassifier
#from sklearn.neural_network import MLPClassifier
#from sklearn.ensemble import RandomForestClassifier
#from sklearn.linear_model import LogisticRegression


warnings.filterwarnings('ignore')
plt.style.use('ggplot')

sca = ('Power', 'EM')
domains = ('temp', 'freq')
proportion = ('eq', '1:10', '1:100')

#To analize power data use sca[0] and for EM sca[1] 
sca = sca[0]
#To analize  data in temporal domain use domains[0] and to do in frequencial domain use domains[1] 
domain = domains[0]
proportion = proportion[2]


#This function returns the number of clusters and the coeficients 
def clustering(X, Y, cluster):
    labels = cluster.labels_
    n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
    # print("     Estimated number of clusters     = %d" % n_clusters_)
    if -1 in labels:
        n_noise_ = list(labels).count(-1)
        # print("     Estimated number of noise points = %d" % n_noise_)

    silhouette = metrics.silhouette_score(X, labels)
    mutual_info = normalized_mutual_info_score(Y, labels)
    '''print("     Silhouette Coefficient           = %0.3f" % silhouette)
    print("     Normalized_mutual_info           = %0.3f" % mutual_info)'''

    return labels, n_clusters_, silhouette, mutual_info


#To measure the AUC, this function is necessary (it is only used when they are two clusters) 
def clfmetrics(Y, y_pred):

    for i, y in enumerate(y_pred):
        if y == -1:
            y_pred[i] = 1

    '''tn, fp, fn, tp = confusion_matrix(Y, y_pred).ravel()

    fnr = fn / (fn + tp) if (fn + tp) != 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) != 0 else 0
    acc = (tp + tn) / (tp + tn + fp + fn)'''

    auc = metrics.roc_auc_score(Y, y_pred)

    return auc


if __name__ == '__main__':
    print(" ")
    print(">> IKERLAN Industrial Cybersecurity Team")
    print("   Main researcher  : Jose Luis Flores")
    print("   > Researcher     : Maialen Eceiza")
    print("   > Researcher     : Mariana Garcia")
    print("   > Researcher     : Unai Rioja")
    print("   > Researcher     : Ekain Azketa")
    print(" ")
    print(" ")
    if sca == 'Power':
        print("   Clustering analysis of power traces")
    elif sca == 'EM':
        print("   Clustering analysis of EM traces")
    print(" ")

    # ---------------------------------------------
    # ------- STAGE 1: Exploring datasets ---------
    # ---------------------------------------------

#Specify the path where are the datasets
    print(">> STAGE 1: Exploring datasets ")
    workDir = "C:\\Users\\Datasets\\"
    file_w_labels = 'null'

#set the name of the codes in the order that appear in the dataset
    names = ["SUT00F", "SUT00I", "E0101", "E0102", "E0103", "E0104", "E0105", "E0106", "E0201", "E0202", "E0203",
             "E0204", "E0205", "E0206", "E0207", "E0208_1st", "E0208_2nd", "E0209_1st", "E0209_2nd", "E0210"]

    # ---------------------------------------
    # --- Side Channel Analysis Datasets ----
    # ---------------------------------------

    if sca == 'Power':
        print("   > SCA        : Power")
        if proportion == 'eq':
            #power analysis with the same number of baseline traces and error traces 
            file_w_labels = 'Power_Traces_w_labels.csv'
        else:
            #power analysis with 1000 baseline traces and 100 error traces 
            file_w_labels = 'Power_Traces_w_labels_Realista.csv'
    elif sca == 'EM':
        print("   > SCA        : EM")
        if proportion == 'eq':
            #EM analysis with the same number of baseline traces and error traces 
            file_w_labels = 'EM_Traces_w_labels.csv'
        else:
            #EM analysis with 1000 baseline traces and 100 error traces 
            file_w_labels = 'EM_Traces_w_labels_Realista.csv'
    else:
        print(" Error: Select a correct data file")

    fqfn_w_labels = workDir + file_w_labels
    print("   > Filename   : " + "\"" + fqfn_w_labels + "\"")
    dataset_w_labels = np.genfromtxt(fqfn_w_labels, delimiter=",")

    X = dataset_w_labels[:, 0:50000]
    Y = dataset_w_labels[:, 50000]
    values, traces = np.unique(Y, return_counts=True)
    n_programs = 20

    for program, name, n_traces in zip(values[2:], names[2:], traces[2:]):

        print(" ")
        LB = 1 if program in [4, 5, 6] else 0
        LB_traces = traces[LB]
        program = int(program)
        print("   > Programs   : " + str(names[LB]) + ", " + str(name))

        for component in [8, 10]:
            n_clusters1, n_clusters2, n_clusters3 = [], [], []
            sil1, sil2, sil3 = [], [], []
            mutual1, mutual2, mutual3 = [], [], []
            auc1, auc2, auc3 = [],[],[]
            print(">> STAGE 2: PCA ")
            print(" ")
            print("  >   Components : " + str(component))

            print("   > Domain     : Mean Shift     --> Frequential")
            print("   > Domain     : DBSCAN, OPTICS --> Temporary")
            print(" ")

            executions = 100
            for execution in np.arange(executions):
                #print("   > Errors     : 1:100")
                n_errors = round(0.01 * LB_traces)
                positions = [i for i in range(len(Y)) if Y[i] == LB]
                e = 0
                while e < min(n_errors, 30):
                    trace = random.randint(sum(traces[:program]), sum(traces[:program + 1]) - 1)
                    if Y[trace] == program and trace not in positions:
                        positions.append(trace)
                        e = e + 1

                X_new = X[positions, :]
                Y_new = Y[positions]
                values_new, traces_new = np.unique(Y_new, return_counts=True)

                dic_Y = {LB: '0', program: '1'}
                for i, y in enumerate(Y_new):
                    if y in (LB, program):
                        Y_new[i] = dic_Y.get(y)
                    else:
                        print("Error")

                # ---------------------------------------
                # ------ Domain -------------------------
                # ---------------------------------------


                instances = X_new.shape[0]
                atributes = X_new.shape[1]
                # print("   > Instances  : " + str(instances))
                # print("   > Attributes : " + str(atributes))

                # ---------------------------------------------
                # ------- STAGE 2: PCA ------------------------
                # ---------------------------------------------

                min_samples = round(n_errors * 0.8)
                n_samples = round(statistics.mean(traces_new) * 0.9)
                q = 0.3

                # print(" ")
                # print(">> STAGE 2: PCA ")
                Xx = pd.DataFrame(X_new).values
                scaler = StandardScaler(with_mean=True, with_std=True)
                scaler.fit(Xx)
                XF_scaled = scaler.transform(Xx)

                pca = PCA(n_components=component)
                pca.fit(XF_scaled)
                XF_pca = pca.transform(XF_scaled)

                # ---------------------------------------------
                # ------- STAGE 3: Clustering -----------------
                # ---------------------------------------------
                #It is possible to change the number of components, here appear the numbers that we used
                '''print(" ")
                print(">> STAGE 3: Clustering")'''

                neighbors = NearestNeighbors(n_neighbors=n_errors).fit(XF_pca)
                distances, indices = neighbors.kneighbors(XF_pca)
                distances = np.sort(distances, axis=0)
                distances = distances[:, 1]
                eps = distances[instances - n_errors - 1]
                if n_errors == 0:
                    eps = distances[round(instances * 0.99)]

                if component == 8:
                    '''print(" ")
                    print("  >   Components : " + str(component))
                    print("       > Algorithm  : OPTICS")'''
                    opt = OPTICS(cluster_method='dbscan', max_eps=eps*1.5, min_samples=min_samples).fit(XF_pca)
                    # print("     " + str(opt))
                    y_opt, n_clusters, silhouette, mutual_info = clustering(XF_pca, Y_new, opt)
                    n_clusters2.append(n_clusters)
                    sil2.append(silhouette)
                    mutual2.append(mutual_info)
                    if n_clusters == 2:
                        auc = clfmetrics(Y_new, y_opt)
                        auc2.append(auc)
                    #if n_clusters != 0:
                        # acc, fnr, fpr = clfmetrics(Y_new, y_opt)

                elif component == 10:
                    '''print(" ")
                    print("  >   Components : " + str(component))
                    print("      > Algorithm  : DBSCAN")'''
                    db = DBSCAN(eps=eps, min_samples=min_samples).fit(XF_pca)
                    # print("     " + str(db))
                    y_db, n_clusters, silhouette, mutual_info = clustering(XF_pca, Y_new, db)
                    n_clusters1.append(n_clusters)
                    sil1.append(silhouette)
                    mutual1.append(mutual_info)
                    if n_clusters == 2:
                        auc = clfmetrics(Y_new, y_db)
                        auc1.append(auc)
                    #if n_clusters != 0:
                        # acc, fnr, fpr = clfmetrics(Y_new, y_db)

                    ############ -----------------------
                    # ms in FREQUENCY DOMAIN 
                    # ----------

                    N = 50000
                    SAMPLE_RATE = 1.0e9  # Hertz
                    DURATION = N / SAMPLE_RATE  # Seconds
                    yf = rfft(X_new)
                    xf = rfftfreq(N, 1 / SAMPLE_RATE)
                    X_new = np.abs(yf)

                    '''print(" ")
                    print("  >   Components : " + str(component))
                    print("       > Algorithm  : Mean Shift")'''
                    bandwidth = estimate_bandwidth(XF_pca, quantile=q, n_samples=n_samples)
                    if bandwidth == 0:
                        bandwidth = 1
                    ms = MeanShift(bandwidth=bandwidth, bin_seeding=True, cluster_all=True).fit(XF_pca)
                    # print("     " + str(ms))
                    y_ms, n_clusters, silhouette, mutual_info = clustering(XF_pca, Y_new, ms)
                    n_clusters3.append(n_clusters)
                    sil3.append(silhouette)
                    mutual3.append(mutual_info)
                    if n_clusters == 2:
                        auc = clfmetrics(Y_new, y_ms)
                        auc3.append(auc)
                    #if n_clusters != 0:
                        # acc, fnr, fpr = clfmetrics(Y_new, y_ms)

            #It draws the results in screen and measure the average and deviation 
            if component == 8 :
                n_clusters2, counts_clusters2 = np.unique(n_clusters2, return_counts=True)
                print("     Number of clusters OPTICS    : " + str(n_clusters2[[c for c, count in enumerate(counts_clusters2) if count == max(counts_clusters2)]]) + str(
                    max(counts_clusters2) * 100 / executions) + " %")
                print(f"     Silhouette Coefficient OPTICS    :  = {np.around(statistics.mean(sil2), 4)} +- {np.around(statistics.stdev(sil2), 4)}")
                print(f"     Normalized Mutual Information OPTICS    :  = {np.around(statistics.mean(mutual2), 4)} +- {np.around(statistics.stdev(mutual2), 4)}")
                if len(auc2) > 1:
                    print(f"     Area Under Curve OPTICS    :  = {np.around(statistics.mean(auc2), 4)} +- {np.around(statistics.stdev(auc2), 4)}")
                print(" ")

            elif component == 10:
                n_clusters1, counts_clusters1 = np.unique(n_clusters1, return_counts=True)
                print("     Number of clusters DBSCAN    : " + str(n_clusters1[[c for c, count in enumerate(counts_clusters1) if count == max(counts_clusters1)]]) + str(
                    max(counts_clusters1)*100/executions) + " %")
                print(f"     Silhouette Coefficient DBSCAN    :  = {np.around(statistics.mean(sil1), 4)} +- {np.around(statistics.stdev(sil1), 4)}")
                print(f"     Normalized Mutual Information DBSCAN    :  = {np.around(statistics.mean(mutual1), 4)} +- {np.around(statistics.stdev(mutual1), 4)}")
                if len(auc1) > 1:
                    print(f"     Area Under Curve DBSCAN    :  = {np.around(statistics.mean(auc1), 4)} +- {np.around(statistics.stdev(auc1), 4)}")
                print(" ")

                n_clusters3, counts_clusters3 = np.unique(n_clusters3, return_counts=True)
                print("     Number of clusters Mean Shift    : " + str(n_clusters3[[c for c, count in enumerate(counts_clusters3) if count == max(counts_clusters3)]]) + str(
                    max(counts_clusters3)*100/executions) + " %")
                print(f"     Silhouette Coefficient Mean Shift:  = {np.around(statistics.mean(sil3),4)} +- {np.around(statistics.stdev(sil3),4)}")
                print(f"     Normalized Mutual Information Mean Shift:  = {np.around(statistics.mean(mutual3),4)} +- {np.around(statistics.stdev(mutual3),4)}")
                if len(auc3) > 1:
                    print(f"     Area Under Curve Mean Shift:  = {np.around(statistics.mean(auc3),4)} +- {np.around(statistics.stdev(auc3),4)}")
                print(" ")



