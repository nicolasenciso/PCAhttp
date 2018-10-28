#reading the flagged data, to extract the features to a new txt file which later, will be 
#used for the PCA algorithm
from scipy import stats
import numpy as np

def dataCatch(dataType):
    typeData = ""
    if dataType == 1:# 1 for anomalous, 0 for normal trainning data
        dataFlagged = open("flaggedAnomalous.txt","r")
        dataOut = open("outAnomalousM.txt","w")
        typeData = "anomalous"
    elif dataType == 0:
        dataFlagged = open("flaggedNormalTrainning.txt","r")
        dataOut = open("outNormalTrainningM.txt","w")
        typeData = "normal"
    for line in dataFlagged:
        if "GET" in line or "POST" in line or "PUT" in line: #taking the url from the data
            auxLine = line.split(" ")
            url = auxLine[1]
            auxurl = url.split("localhost:8080")#taking away the domain that its localhost
            URLfeatures = auxurl[1]
            URL = urlExtractFeatures(URLfeatures)+","+typeData#function to extract features from the url
            dataOut.writelines(URL+"\n")
    dataFlagged.close()
    dataOut.close()


def urlExtractFeatures(url):#builds the feature array from the given url
    urlong = len(url)
    urlong = str(urlong)
    characters = charactersExtraction(url)
    suspicious = suspiciousWords(url)
    sql = sqlInjection(url)
    xss = xssAttack(url)
    crlf = crlfAttack(url)
    kolmogorov = kolmogorovStatistics(url)
    kullback = kullbackDivergence(url)

    #finalFeatures = urlong+","+characters+","+suspicious+","+sql+","+xss+","+crlf+","+kolmogorov+","+kullback
    #print(finalFeatures)
    finalFeatures = kolmogorov+","+suspicious+","+sql+","+kullback+","+urlong
    return finalFeatures

def charactersExtraction(url):
    arrobaCount, minusCount, pointCount, admirationCount, sharpCount, apostropheCount = 0,0,0,0,0,0
    pesosCount, percentCount, ampersandCount, commaCount, pointcommaCount = 0,0,0,0,0
    for character in url:#extraction of characters from the url
        if character == "@":
            arrobaCount += 1
        elif character == "-":
            minusCount += 1
        elif character == ".":
            pointCount += 1
        elif character == "!":
            admirationCount += 1
        elif character == "#":
            sharpCount += 1
        elif character == "'":
            apostropheCount += 1
        elif character == "$":
            pesosCount += 1
        elif character == "&":
            ampersandCount += 1
        elif character == ",":
            commaCount += 1
        elif character == ";":
            pointcommaCount += 1

    meanCharactersMeasure = arrobaCount+minusCount+pointCount+admirationCount+sharpCount+apostropheCount+pesosCount+percentCount+ampersandCount+commaCount+pointcommaCount
    return str(meanCharactersMeasure)

def wordSearcher(word,url):
    firstLetter = word[0]
    lastLetter = word[len(word)-1]
    count = 0
    i = 0
    for character in url:   
        if url[i] == firstLetter:
            newIndex = i+(len(word)-1)
            if newIndex <= (len(url)-1):
                if url[newIndex] == lastLetter:
                    count += 1
        i += 1
    return count
    

def suspiciousWords(url):
    confirmCount, accountCount, secureCount, webscrCount, loginCount, adminCount = 0,0,0,0,0,0
    signinCount, submitCount, updateCount, loginCount, wpCount, cmdCount, hackCount = 0,0,0,0,0,0,0
    autenticarCount, entrarCount, errorCount, password, registroCount, registrarCount, editarCount = 0,0,0,0,0,0,0
    if "confirm" in url: #extraction of suspicious word from the url
        confirmCount = wordSearcher("confirm",url)
    if "account" in url:
        accountCount = wordSearcher("account",url)
    if "secure" in url:
        secureCount = wordSearcher("secure",url)
    if "webscr" in url:
        webscrCount = wordSearcher("webscr",url)
    if "login" in url:
        loginCount = wordSearcher("login",url)
    if "admin" in url:
        adminCount = wordSearcher("admin",url)
    if "signin" in url:
        signinCount = wordSearcher("signin",url)
    if "submit" in url:
        submitCount = wordSearcher("submit",url)
    if "update" in url:
        updateCount = wordSearcher("update",url)
    if "login" in url:
        loginCount = wordSearcher("login",url)
    if "wp" in url:
        wpCount = wordSearcher("wp",url)
    if "cmd" in url:
        cmdCount = wordSearcher("cmd",url)
    if "autenticar" in url:
        autenticarCount = wordSearcher("autenticar",url)
    if "Entrar" in url:
        entrarCount = wordSearcher("Entrar",url)
    if "error" in url:
        errorCount = wordSearcher("error",url)
    if "password" in url:
        password = wordSearcher("password",url)
    if "registro" in url:
        registroCount = wordSearcher("registro",url)
    if "Registrar" in url:
        registrarCount = wordSearcher("Registrar",url)
    if "editar" in url:
        editarCount = wordSearcher("editar",url)
    if "hack" in url:
        hackCount = wordSearcher("hack",url)

    meanSuspiciousWord = confirmCount+accountCount+secureCount+webscrCount+loginCount+adminCount+signinCount+submitCount+updateCount+loginCount+wpCount+cmdCount+autenticarCount+entrarCount+errorCount+password+registroCount
    return str(meanSuspiciousWord)

def sqlInjection(url):#extraction of common word in a SQL injection attack
    selectCount, whereCount, fromCount, dropCount, tableCount, likeCount = 0,0,0,0,0,0
    if "SELECT" in url:
        selectCount = wordSearcher("SELECT",url)
    if "WHERE" in url:
        whereCount = wordSearcher("WHERE",url)
    if "FROM" in url:
        fromCount = wordSearcher("FROM",url)
    if "DROP" in url:
        dropCount = wordSearcher("DROP",url)
    if "TABLE" in url:
        tableCount = wordSearcher("TABLE",url)
    if "LIKE" in url:
        likeCount = wordSearcher("LIKE",url)

    meanSQL = selectCount+whereCount+fromCount+dropCount+tableCount+likeCount 
    return str(meanSQL)

def xssAttack(url):#extraction of common characteristics in a cross script attack
    xss = "none"
    alertCount,paramCount,injectedCount,scriptCount = 0,0,0,0
    if "alert" in url:
        alertCount = wordSearcher("alert",url)
    if "PARAM" in url:
        paramCount = wordSearcher("PARAM",url)
    if "INJECTED" in url:
        injectedCount = wordSearcher("INJECTED",url)
    if "SCRipt" in url or "scrIPT" in url or "Script" in url or "SCRIPT" in url or "script" in url:
        scriptCount = scriptCount+wordSearcher("SCRipt",url)
        scriptCount = scriptCount+wordSearcher("scrIPT",url)
        scriptCount = scriptCount+wordSearcher("Script",url)
        scriptCount = scriptCount+wordSearcher("SCRIPT",url)
        scriptCount = scriptCount+wordSearcher("script",url)
    xss = alertCount+paramCount+injectedCount+scriptCount
    return str(xss)

def crlfAttack(url):#extraction of common characteristics in a CRLF attack
    crlf = "none"
    splitCount, zeroCount = 0,0
    for char in url:
        if char == "%":
            splitCount += 1
        if char == "0":
            zeroCount += 1
    crlf = splitCount
    return str(crlf)

def characterFrequency(url):#to count the frequency of each letter in the given URL
    abecedary = {'a':0,'b':0,'c':0,'d':0,'e':0,'f':0,'g':0,'h':0,'i':0,'j':0,'k':0,'l':0,
                'm':0,'n':0,'o':0,'p':0,'q':0,'r':0,'s':0,'t':0,'u':0,'v':0,'w':0,'x':0,'y':0,'z':0}
    flag = True
    for character in url:
        character = str(character).lower()
        if character in abecedary:
            abecedary[character] += 1
            flag = False #to know if there is a url without letters
    if flag:
        abecedary['a'] = 1
    valuesArray = []
    totalFreq = 1
    for letter in abecedary:
        totalFreq = totalFreq + abecedary[letter]
    for letter in abecedary:
        if totalFreq > 0:
            abecedary[letter] = (abecedary[letter] * 100)/totalFreq
            valuesArray.append(abecedary[letter])
    valuesArray = np.asarray(valuesArray)
    valuesArray = np.sort(valuesArray)
    return valuesArray

def spanishFrequency():#to return the frequency of each letter in the spanish abecedary
    spanishFreq = {'a':12.53,'b':1.42,'c':4.68,'d':5.86,'e':13.68,'f':0.69,'g':1.01,'h':0.7,'i':6.25,
                    'j':0.44,'k':0.01,'l':4.97,
                'm':3.15,'n':6.71,'o':8.68,'p':2.51,'q':0.88,'r':6.87,
                's':7.98,'t':4.63,'u':3.93,'v':0.9,'w':0.02,'x':0.22,'y':0.9,'z':0.52}
    valuesSpanish = []
    for letter in spanishFreq:
        valuesSpanish.append(spanishFreq[letter])
    valuesSpanish = np.asarray(valuesSpanish)
    valuesSpanish = np.sort(valuesSpanish)
    return valuesSpanish

def kolmogorovStatistics(url):
    kolmogorov = "none"
    frequencies = characterFrequency(url)
    valuesSpanish = spanishFrequency()
    ksTest = stats.ks_2samp(frequencies,valuesSpanish)
    kolmogorov = str(ksTest[0])
    return kolmogorov

def kullbackDivergence(url):
    kullback = "none"
    np.seterr(divide='ignore', invalid='ignore')#to avoid error from divided by zero
    frequencies = characterFrequency(url)
    valuesSpanish = spanishFrequency()
    klDiv = stats.entropy(frequencies,valuesSpanish)
    kullback = str(klDiv)
    return kullback


dataCatch(1)
dataCatch(0)

