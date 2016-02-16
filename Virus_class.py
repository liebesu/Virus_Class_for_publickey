__author__ = 'liebesu'
import urllib
import urllib2
import json
import re,datetime,os
import MySQLdb
from pprint import pprint
from lib.core.readcnf import read_conf
from lib.core.constants import ROOTPATH,VTAPIKEY,JSONPATH
inputpath,outputpath,Scantype,datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,md5filename=read_conf()


'''def check():
    if scantype=="md5":'''


'''def checkMd5file():

    lists=os.listdir(md5filedir)
    for list in lists:'''




class VTAPI():

    def __init__(self):
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    def getReport(self,md5,apikey):
        param = {'resource':md5,'apikey':apikey}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata
    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"
def readMd5file():
    count = 0
    i = 0
    t = 0
    keyfiles=os.listdir(VTAPIKEY)
    for keyfile in keyfiles:
        ApikeyList = os.path.join(VTAPIKEY,keyfile)
        ApikeyList_object = open(ApikeyList, "r").readlines()
        Apikeycount = len(ApikeyList_object)
        md5filedir = os.path.join(ROOTPATH,"md5file")
        allmd5file=os.path.join(md5filedir,md5filename)
        allmd5=open(allmd5file,"r").readlines()
        for md5 in allmd5:
            md5 = md5.replace('\n','').replace('\r', '')
            if re.match(r"([a-fA-F\d]{32})", md5) != None:
                count = count+1
                apikey=ApikeyList_object[i].replace('\n','').replace('\r', '')
                if count % 4 == 0:
                    i=i+1
                    apikey = ApikeyList_object[i].replace('\n','').replace('\r', '')
                    Apikeycount1=Apikeycount-1
                    if i >= Apikeycount1:
                        t = t+1
                        i = 0

                parse(vt.getReport(md5,apikey),md5)
                cmd="sed -i '1d' "+allmd5file
                os.system(cmd)
                #removeLine(allmd5file,md5)

def parse(it, md5):
    md5filedir = os.path.join(ROOTPATH,"md5file")
    allmd5file=os.path.join(md5filedir,md5filename)

    if it['response_code'] == 0:
        mark = 0
        virusname="null"
        kaspersky_result = "null"
        kaspersky_update = "null"
        kaspersky_version = "null"
        clamav_result= "null"
        clamav_update = "null"
        clamav_version = "null"
        sha1=sha256=AVG_result=AhnLab_V3_result=Avast_result=BitDefender_result=CAT_QuickHeal_result=Commtouch_result=Comodo_result=\
        DrWeb_result=eSafe_result=F_Secure_result=Fortinet_result=GData_result=Ikarus_result=Jiangmin_result=K7AntiVirus_result=\
        McAfee_result=Microsoft_result=NOD32_result=Norman_result=PCTools_result=Panda_result=Prevx_result=Rising_result=\
        SUPERAntiSpyware_result=Sophos_result=Symantec_result=TheHacker_result=VBA32_result=ViRobot_result=VirusBuster_result=\
        eTrust_Vet_result=nProtect_result=VIPRE_result=F_Prot_result=TrendMicro_result="null"


    else:
        mark='0'
        if 'positives' in it:
            mark = it['positives']
        virusname="null"
        clamav_result= "null"
        clamav_update = "null"
        clamav_version = "null"
        kaspersky_result = "null"
        kaspersky_update = "null"
        kaspersky_version = "null"
        sha1=sha256=AVG_result=AhnLab_V3_result=Avast_result=BitDefender_result=CAT_QuickHeal_result=Commtouch_result=Comodo_result=\
        DrWeb_result=eSafe_result=F_Secure_result=Fortinet_result=GData_result=Ikarus_result=Jiangmin_result=K7AntiVirus_result=\
        McAfee_result=Microsoft_result=NOD32_result=Norman_result=PCTools_result=Panda_result=Prevx_result=Rising_result=\
        SUPERAntiSpyware_result=Sophos_result=Symantec_result=TheHacker_result=VBA32_result=ViRobot_result=VirusBuster_result=\
        eTrust_Vet_result=nProtect_result=VIPRE_result=F_Prot_result=TrendMicro_result="null"
        '''jsonpath=os.path.join(JSONPATH,md5filename[:-4])
        filejsonpath= os.path.join(jsonpath,md5+".json")
        if os.path.exists(jsonpath):
            jsondumpfile=open(filejsonpath,"w")
            pprint(it,jsondumpfile)
            jsondumpfile.close()
        else:
            os.makedirs(jsonpath)
            jsondumpfile=open(filejsonpath,"w")
            pprint(it,jsondumpfile)
            jsondumpfile.close()'''
        sha1=it['sha1']
        sha256=it['sha256']
        if 'Kaspersky' in it['scans'] :
            if it['scans']['Kaspersky']['detected']:
                kaspersky_result = it['scans']['Kaspersky']['result']
                kaspersky_update = it['scans']['Kaspersky']['update']
                kaspersky_version = it['scans']['Kaspersky']['version']
                virusname=kaspersky_result
                if "Trojan-" in kaspersky_result:
                    virusname=kaspersky_result.replace('Trojan-','')
                    if "not-a-virus:" in virusname or "HEUR:" in virusname:
                        virusname=virusname.replace('not-a-virus:','')
                        virusname =virusname.replace('HEUR:','')
                if "not-a-virus:" in kaspersky_result or "HEUR:" in kaspersky_result:
                        virusname=kaspersky_result.replace('not-a-virus:','')
                        virusname =virusname.replace('HEUR:','')
        if 'ClamAV' in it['scans'] :
            if it['scans']['ClamAV']['detected']:
                clamav_result = it['scans']['ClamAV']['result']
                clamav_update = it['scans']['ClamAV']['update']
                clamav_version = it ['scans']['ClamAV']['version']
        if 'AVG' in it['scans'] :
            if it['scans']['AVG']['detected']:
                AVG_result = it['scans']['AVG']['result']

        if 'AhnLab-V3' in it['scans'] :
            if it['scans']['AhnLab-V3']['detected']:
                AhnLab_V3_result = it['scans']['AhnLab-V3']['result']
        if 'Avast' in it['scans'] :
            if it['scans']['Avast']['detected']:
                Avast_result = it['scans']['Avast']['result']
        if 'BitDefender' in it['scans'] :
            if it['scans']['BitDefender']['detected']:
                BitDefender_result = it['scans']['BitDefender']['result']
        if 'CAT-QuickHeal' in it['scans'] :
            if it['scans']['CAT-QuickHeal']['detected']:
                CAT_QuickHeal_result = it['scans']['CAT-QuickHeal']['result']
        if 'Commtouch' in it['scans'] :
            if it['scans']['Commtouch']['detected']:
                Commtouch_result = it['scans']['Commtouch']['result']
        if 'Comodo' in it['scans'] :
            if it['scans']['Comodo']['detected']:
                Comodo_result = it['scans']['Comodo']['result']
        if 'DrWeb' in it['scans'] :
            if it['scans']['DrWeb']['detected']:
                DrWeb_result = it['scans']['DrWeb']['result']
        if 'F-Prot' in it['scans'] :
            if it['scans']['F-Prot']['detected']:
                F_Prot_result = it['scans']['F-Prot']['result']
        if 'F-Secure' in it['scans'] :
            if it['scans']['F-Secure']['detected']:
                F_Secure_result = it['scans']['F-Secure']['result']
        if 'Fortinet' in it['scans'] :
            if it['scans']['Fortinet']['detected']:
                Fortinet_result = it['scans']['Fortinet']['result']
        if 'GData' in it['scans'] :
            if it['scans']['GData']['detected']:
                GData_result = it['scans']['GData']['result']
        if 'Ikarus' in it['scans'] :
            if it['scans']['Ikarus']['detected']:
                Ikarus_result = it['scans']['Ikarus']['result']
        if 'Jiangmin' in it['scans'] :
            if it['scans']['Jiangmin']['detected']:
                Jiangmin_result = it['scans']['Jiangmin']['result']
        if 'K7AntiVirus' in it['scans'] :
            if it['scans']['K7AntiVirus']['detected']:
                K7AntiVirus_result = it['scans']['K7AntiVirus']['result']
        if 'McAfee' in it['scans'] :
            if it['scans']['McAfee']['detected']:
                McAfee_result = it['scans']['McAfee']['result']
        if 'Microsoft' in it['scans'] :
            if it['scans']['Microsoft']['detected']:
                Microsoft_result = it['scans']['Microsoft']['result']
        if 'NOD32' in it['scans'] :
            if it['scans']['NOD32']['detected']:
                NOD32_result = it['scans']['NOD32']['result']
        if 'Norman' in it['scans'] :
            if it['scans']['Norman']['detected']:
                Norman_result = it['scans']['Norman']['result']
        if 'PCTools' in it['scans'] :
            if it['scans']['PCTools']['detected']:
                PCTools_result = it['scans']['PCTools']['result']
        if 'Panda' in it['scans'] :
            if it['scans']['Panda']['detected']:
                Panda_result = it['scans']['Panda']['result']
        if 'Prevx' in it['scans'] :
            if it['scans']['Prevx']['detected']:
                Prevx_result = it['scans']['Prevx']['result']
        if 'Rising' in it['scans'] :
            if it['scans']['Rising']['detected']:
                Rising_result = it['scans']['Rising']['result']
        if 'SUPERAntiSpyware' in it['scans'] :
            if it['scans']['SUPERAntiSpyware']['detected']:
                SUPERAntiSpyware_result = it['scans']['SUPERAntiSpyware']['result']
        if 'Sophos' in it['scans'] :
            if it['scans']['Sophos']['detected']:
                Sophos_result = it['scans']['Sophos']['result']
        if 'Symantec' in it['scans'] :
            if it['scans']['Symantec']['detected']:
                Symantec_result = it['scans']['Symantec']['result']
        if 'TheHacker' in it['scans'] :
            if it['scans']['TheHacker']['detected']:
                TheHacker_result = it['scans']['TheHacker']['result']
        if 'TrendMicro' in it['scans'] :
            if it['scans']['TrendMicro']['detected']:
                TrendMicro_result = it['scans']['TrendMicro']['result']
        if 'VBA32' in it['scans'] :
            if it['scans']['VBA32']['detected']:
                VBA32_result = it['scans']['VBA32']['result']
        if 'VIPRE' in it['scans'] :
            if it['scans']['VIPRE']['detected']:
                VIPRE_result = it['scans']['VIPRE']['result']
        if 'ViRobot' in it['scans'] :
            if it['scans']['ViRobot']['detected']:
                ViRobot_result = it['scans']['ViRobot']['result']
        if 'VirusBuster' in it['scans'] :
            if it['scans']['VirusBuster']['detected']:
                VirusBuster_result = it['scans']['VirusBuster']['result']
        if 'eSafe' in it['scans'] :
            if it['scans']['eSafe']['detected']:
                eSafe_result = it['scans']['eSafe']['result']
        if 'eTrust-Vet' in it['scans'] :
            if it['scans']['eTrust-Vet']['detected']:
                eTrust_Vet_result = it['scans']['eTrust-Vet']['result']
        if 'nProtect' in it['scans'] :
            if it['scans']['nProtect']['detected']:
                nProtect_result = it['scans']['nProtect']['result']



        #print kaspersky_result,kaspersky_update,kaspersky_version,clamav_result,clamav_update,clamav_version,virusname
    try:
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
        cursor = db.cursor()
        sqltime= datetime.datetime.now()
        #"+"'"+str(md5)+"'"+","
        sql="insert into "+datebasetable+" (Md5,Sha1,Sha256,Virus_Name,Kaspersky,Kaspersky_update,Kaspersky_version,ClamAV," \
                                         "ClamAV_update,ClamAV_version,Mark,Md5File,AVGSOFT,AhnLab_V3,Avast,BitDefentder," \
                                         "CAT_QuickHeal,Commtouch,Comodo,DrWeb,eSafe,F_Secure,Fortinet,GData,Ikarus,Jiangmin," \
                                         "K7AntiVirus,McAfee,Microsoft,NOD32, Norman,PCTools,Panda,Prevx,Rising,SUPERAntiSpyware," \
                                         "Sophos,Symantec,TheHacker,TrendMicro,VBA32,ViRobot,VirusBuster,eTrust_Vet,nProtect," \
                                         "VIPRE,F_Prot) values( "+"'"+str(md5)+"'"+","+"'"+str(sha1)+"'"+","+"'"+str(sha256)+"'"+","+"'"\
            +str(virusname)+"'"+","+"'"+kaspersky_result+"'"+","+"'"+str(kaspersky_update)+"'"+ ","+ "'"+str(kaspersky_version)\
            +"'"+","+"'"+str(clamav_result)+"'"+","+"'"+str(clamav_version)+"'"+","+"'"+str(clamav_update)+"'"+","+"'"+str(mark)+\
            "'"+","+"'"+str(md5filename)+"'"+","+"'"+AVG_result+"'"+","+"'"+AhnLab_V3_result+"'"+","+"'"+Avast_result+"'"+","\
            +"'"+BitDefender_result+"'"+","+"'"+CAT_QuickHeal_result+"'"+","+"'"+Commtouch_result+"'"+","+"'"+Comodo_result+"'"\
            +","+"'"+DrWeb_result+"'"+","+"'"+eSafe_result+"'"+","+"'"+F_Secure_result+"'"+","+"'"+Fortinet_result+"'"+","+"'"\
            +GData_result+"'"+","+"'"+Ikarus_result+"'"+","+"'"+Jiangmin_result+"'"+","+"'"+K7AntiVirus_result+"'"+","+"'"\
            +McAfee_result+"'"+","+"'"+Microsoft_result+"'"+","+"'"+NOD32_result+"'"+","+"'"+Norman_result+"'"+","+"'"+PCTools_result\
            +"'"+","+"'"+Panda_result+"'"+","+"'"+Prevx_result+"'"+","+"'"+Rising_result+"'"+","+"'"+SUPERAntiSpyware_result\
            +"'"+","+"'"+Sophos_result+"'"+","+"'"+Symantec_result+"'"+","+"'"+TheHacker_result+"'"+","+"'"+TrendMicro_result+"'"+","+"'"+VBA32_result+"'"+","\
            +"'"+ViRobot_result+"'"+","+"'"+VirusBuster_result+"'"+","+"'"+eTrust_Vet_result+"'"+","+"'"+nProtect_result+"'"+","+"'"+VIPRE_result+"'"\
            +","+"'"+F_Prot_result+"'"+")"
        cursor.execute(sql)
        db.commit()
        cursor.close()
        db.close()
    except:
        cursor.close()
        db.close()
        mark = "0"
        virusname="null"
        clamav_result= "null"
        clamav_update = "null"
        clamav_version = "null"
        kaspersky_result = "null"
        kaspersky_update = "null"
        kaspersky_version = "null"
        sha1=sha256=AVG_result=AhnLab_V3_result=Avast_result=BitDefender_result=CAT_QuickHeal_result=Commtouch_result=Comodo_result=\
        DrWeb_result=eSafe_result=F_Secure_result=Fortinet_result=GData_result=Ikarus_result=Jiangmin_result=K7AntiVirus_result=\
        McAfee_result=Microsoft_result=NOD32_result=Norman_result=PCTools_result=Panda_result=Prevx_result=Rising_result=\
        SUPERAntiSpyware_result=Sophos_result=Symantec_result=TheHacker_result=VBA32_result=ViRobot_result=VirusBuster_result=\
        eTrust_Vet_result=nProtect_result=VIPRE_result=F_Prot_result=TrendMicro_result="null"
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
        cursor = db.cursor()
        sqltime= datetime.datetime.now()
        #"+"'"+str(md5)+"'"+","
        sql="insert into "+datebasetable+" (Md5,Sha1,Sha256,Virus_Name,Kaspersky,Kaspersky_update,Kaspersky_version,ClamAV," \
                                         "ClamAV_update,ClamAV_version,Mark,Md5File,AVGSOFT,AhnLab_V3,Avast,BitDefentder," \
                                         "CAT_QuickHeal,Commtouch,Comodo,DrWeb,eSafe,F_Secure,Fortinet,GData,Ikarus,Jiangmin," \
                                         "K7AntiVirus,McAfee,Microsoft,NOD32, Norman,PCTools,Panda,Prevx,Rising,SUPERAntiSpyware," \
                                         "Sophos,Symantec,TheHacker,TrendMicro,VBA32,ViRobot,VirusBuster,eTrust_Vet,nProtect," \
                                         "VIPRE,F_Prot) values( "+"'"+str(md5)+"'"+","+"'"+str(sha1)+"'"+","+"'"+str(sha256)+"'"+","+"'"\
            +str(virusname)+"'"+","+"'"+kaspersky_result+"'"+","+"'"+str(kaspersky_update)+"'"+ ","+ "'"+str(kaspersky_version)\
            +"'"+","+"'"+str(clamav_result)+"'"+","+"'"+str(clamav_version)+"'"+","+"'"+str(clamav_update)+"'"+","+"'"+str(mark)+\
            "'"+","+"'"+str(md5filename)+"'"+","+"'"+AVG_result+"'"+","+"'"+AhnLab_V3_result+"'"+","+"'"+Avast_result+"'"+","\
            +"'"+BitDefender_result+"'"+","+"'"+CAT_QuickHeal_result+"'"+","+"'"+Commtouch_result+"'"+","+"'"+Comodo_result+"'"\
            +","+"'"+DrWeb_result+"'"+","+"'"+eSafe_result+"'"+","+"'"+F_Secure_result+"'"+","+"'"+Fortinet_result+"'"+","+"'"\
            +GData_result+"'"+","+"'"+Ikarus_result+"'"+","+"'"+Jiangmin_result+"'"+","+"'"+K7AntiVirus_result+"'"+","+"'"\
            +McAfee_result+"'"+","+"'"+Microsoft_result+"'"+","+"'"+NOD32_result+"'"+","+"'"+Norman_result+"'"+","+"'"+PCTools_result\
            +"'"+","+"'"+Panda_result+"'"+","+"'"+Prevx_result+"'"+","+"'"+Rising_result+"'"+","+"'"+SUPERAntiSpyware_result\
            +"'"+","+"'"+Sophos_result+"'"+","+"'"+Symantec_result+"'"+","+"'"+TheHacker_result+"'"+","+"'"+TrendMicro_result+"'"+","+"'"+VBA32_result+"'"+","\
            +"'"+ViRobot_result+"'"+","+"'"+VirusBuster_result+"'"+","+"'"+eTrust_Vet_result+"'"+","+"'"+nProtect_result+"'"+","+"'"+VIPRE_result+"'"\
            +","+"'"+F_Prot_result+"'"+")"
        cursor.execute(sql)
        db.commit()
        cursor.close()
        db.close()
    '''lock.acquire()

    cmd="sed -i '/"+md5+"/d' "+allmd5file
    os.system(cmd)
    lock.release()'''

def removeLine(filename, lineno):
    fro = open(filename, "rb")

    current_line = 0
    while current_line < lineno:
        fro.readline()
        current_line += 1

    seekpoint = fro.tell()
    frw = open(filename, "r+b")
    frw.seek(seekpoint, 0)

    # read the line we want to discard
    fro.readline()

    # now move the rest of the lines in the file
    # one line back
    chars = fro.readline()
    while chars:
        frw.writelines(chars)
        chars = fro.readline()

    fro.close()
    frw.truncate()
    frw.close()
'''def useVtkey():
    count = 0
    i = 0
    t = 0
    ApikeyList = VTAPIKEY+os.path.basename(VTAPIKEY)
    ApikeyList_object = open(ApikeyList, "r").readlines()
    Apikeycount = len(ApikeyList_object)
    TargetList = rootpath+'filepath.txt'
    TargetFile_object = open(TargetList, "r").readlines()
    for eachline in TargetFile_object:
        eachline = eachline.replace('\n','').replace('\r', '')
        filename = eachline.split('/')[-1]
        count=count+1
        apikey=ApikeyList_object[i].replace('\n','').replace('\r', '')
        if count % 4 == 0:
            i=i+1
            apikey = ApikeyList_object[i].replace('\n','').replace('\r', '')
            Apikeycount1=Apikeycount-1
            print '********   use    ' + str(i) + "    key**********"
            print "                  "
            if i >= Apikeycount1:
                runtime[t] = datetime.datetime.now()
                if t >= 1:
                    print (runtime[t] - runtime[t-1]).seconds
                    print "seconds                                                    LIEBESU"

                t = t+1
                i = 0
        print apikey
        apikey = str(apikey)

'''

'''def virustotalscan():
        md5'''
if __name__ == "__main__":
    vt=VTAPI()
    md5=readMd5file()





