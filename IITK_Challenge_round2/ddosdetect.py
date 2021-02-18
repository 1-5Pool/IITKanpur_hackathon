#!/usr/bin/env python
# coding: utf-8

# In[21]:


import pandas as pd
import numpy as np
import sklearn
import os
import dpkt
from pathlib import Path
import socket
import sys
from sklearn.ensemble import IsolationForest
import joblib
# np.seterr(divide="ignore",invalid="ignore")
# In[11]:


file_name = sys.argv[1]
print("File : {}".format(file_name))

# In[6]:


assert os.path.isfile(file_name),"This file does not exist"


# In[41]:


def get_timeperiod(ts_init,ts):
    return int((ts - ts_init))

def get_features(file_name):
    print("Extracting features")
    f= open(file_name,'rb')
    pcap=dpkt.pcap.Reader(f)
    count_frag=0
    count_public=0
    count_frag_public=0
    irregular_pkt = 0
    pkt_count = 0
    stats = {}
    for i,(ts,buf) in enumerate(pcap):
        if i==0:
            ts_init=ts
        eth=dpkt.ethernet.Ethernet(buf)
        #print(dir(eth))
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                continue
        try:
            if eth.type==dpkt.ethernet.ETH_TYPE_IP:
                ip=eth.data

                src_ip = socket.inet_ntoa(ip.src)
                dest_ip = socket.inet_ntoa(ip.dst)
                #print(dir(pkt.data))
                #proto=pkt.transport_layer  

                #print(dir(src))
                more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
                isFragmented = ip.off == more_fragments 

                if ip.p==dpkt.ip.IP_PROTO_TCP and hasattr(ip.data,"sport") : # Check for TCP packets
                    src_pt = ip.data.sport
                    bytes_string= ip.data.data
                    #print("byte:",byte_string)
                    ascii_string= bytes_string.decode("ascii",errors="backslashreplace")
                    #print("TCP",ascii_string)
                elif ip.p==dpkt.ip.IP_PROTO_UDP and  hasattr(ip.data,"sport"):
                    #print(ip.offset)# Check for UDP packets
                    src_pt = ip.data.sport
                    bytes_string= ip.data.data
                    ascii_string= bytes_string.decode("ascii",errors="backslashreplace")
                elif ip.p==dpkt.ip.IP_PROTO_UDP:
                    src_pt = "-100"
                    if hasattr(ip,"data"):
                        bytes_string = ip.data
                        ascii_string = bytes_string.decode("ascii",errors="backslashreplace")
                    else:
                        bytes_string = ""
                        ascii_string=""

                public_flag = ("public" in ascii_string) and ("MIB" in ascii_string)
                private_flag = "private" in ascii_string
                ts = get_timeperiod(ts_init, ts)
                stat = stats.get((src_ip,dest_ip,ts),{"File":file_name,"public_check":False,"payloads":set()})
                if public_flag:
                    stat["public_check"] = True
                stat["cnt"] = stat.get("cnt",0) + 1
                stat["payloads"].add(hash(ascii_string))
                stats[(src_ip,dest_ip,ts)] = stat
                pkt_count +=1
      ###print(i+1)
        except Exception as e:
    #         if ip.p == dpkt.ip.IP_PROTO_TCP:
            print(e)
            irregular_pkt += 1
            pass
    f.close()
    rows = []
    for i in stats:
        row = {"Connection":i}
        row.update(stats[i])
        rows.append(row)
    df = pd.DataFrame(rows)
    df["Payload_cnt"] = df["payloads"].apply(lambda x:len(x))
    df["Unique_ratio"] = df["cnt"]/df["Payload_cnt"]
    df.drop(columns=["payloads"],inplace=True)
    print("Finished extracting features")
    return df

def get_connections_df(file_name):
    f= open(file_name,'rb')
    pcap=dpkt.pcap.Reader(f)
    connections = []
    for i,(ts,buf) in enumerate(pcap):
        eth=dpkt.ethernet.Ethernet(buf)
        conn = {}
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                continue
        try:
            if eth.type==dpkt.ethernet.ETH_TYPE_IP:
                ip=eth.data

                src_ip = socket.inet_ntoa(ip.src)
                dest_ip = socket.inet_ntoa(ip.dst)
                #print(dir(pkt.data))
                #proto=pkt.transport_layer  

                #print(dir(src))
                more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
                isFragmented = ip.off == more_fragments 

                if ip.p==dpkt.ip.IP_PROTO_TCP and hasattr(ip.data,"sport") : # Check for TCP packets
                    src_pt = ip.data.sport
                    dst_pt = ip.data.dport
                elif ip.p==dpkt.ip.IP_PROTO_UDP and  hasattr(ip.data,"sport"):
                    #print(ip.offset)# Check for UDP packets
                    src_pt = ip.data.sport
                    dst_pt = ip.data.dport
                elif ip.p==dpkt.ip.IP_PROTO_UDP:
                    src_pt = "-1"
                    dst_pt = "-1"

                conn["Connection"] = (src_ip,dest_ip)
                conn["Connection_expanded"] = "Source: {}:{}->Dest:{}:{} ".format(src_ip,src_pt,dest_ip,dst_pt)
                connections.append(conn)
        except Exception as e:
            print(e)
            pass
    f.close()
    conn_df = pd.DataFrame(connections)
    conn_df = conn_df.drop_duplicates()
    return conn_df


# In[42]:


features = get_features(file_name)
conn_df = get_connections_df(file_name)


# In[48]:


def get_predictor(df):
    df["Connection"] = df["Connection"].apply(lambda x : (x[0],x[1]))
    print(df["Connection"])
    grouped = df.groupby('Connection')
    print("Loaded classifer")
    # clf = joblib.load("pcap_model.joblib")
    clf = IsolationForest(random_state=1234)
    clf.fit([group.median() for name,group in grouped])
    preds = {}
    print("No of data points : {}".format(len(df)))
    print("No of groups : {}".format(len(grouped)))
    for i,(name, group) in enumerate(grouped):
        predict = clf.predict([group.median()])
        if predict[0] == -1:
            preds[name] = "DDos"
        else:
            preds[name]  = "Benign"
        if i%5000 == 0:
            print(i)
    return preds

def output_results(features,conn_df):
    preds = get_predictor(features)
    conn_df["Result"] = conn_df["Connection"].map(preds)
    # conn_df["Result"].replace("DDos",np.nan).ffill().fillna("DDos")
    return conn_df

output_results(features,conn_df)


# In[49]:

print("Writing results to results.csv")
conn_df[["Connection_expanded","Result"]].to_csv("results.csv",index=False)


# In[ ]:




