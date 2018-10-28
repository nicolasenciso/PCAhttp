flag = []
anomalousRead = open("anomalousTrafficTest.txt","r")
for line in anomalousRead.readlines():
    if "GET" in line or "POST" in line or "PUT" in line:
        flag += "??? \n"
    flag += line

anomalousWrite = open("flaggedAnomalous.txt","w")
anomalousWrite.writelines(flag)

flag = []
normalTrainningRead = open("normalTrafficTraining.txt","r")
for line in normalTrainningRead.readlines():
    if "GET" in line or "POST" in line or "PUT" in line:
        flag += "??? \n"
    flag += line

normalTrainningWrite = open("flaggedNormalTrainning.txt","w")
normalTrainningWrite.writelines(flag)
