export arToken
export arIp4QueryUrl="http://ipv4.rehi.org/ip"
export arIp6QueryUrl="http://ipv6.rehi.org/ip"
export arLastRecordFile=/tmp/ardnspod_last_record
export arErrCodeUnchanged=0
arLog(){
echo >&2 "$@"
}
arRequest(){
local url="$1"
local data="$2"
local params=""
local agent="AnripDdns/6.4.0(wang@rehiy.com)"
if type curl >/dev/null 2>&1;then
if echo $url|grep -q https;then
params="$params -k"
fi
if [ -n "$data" ];then
params="$params -d $data"
fi
curl -s -A "$agent" $params $url
return $?
fi
if type wget >/dev/null 2>&1;then
if echo $url|grep -q https;then
params="$params --no-check-certificate"
fi
if [ -n "$data" ];then
params="$params --post-data $data"
fi
wget -qO- -U "$agent" $params $url
return $?
fi
return 1
}
arLanIp4(){
local lanIps="^$"
echo $lanIps
}
arWanIp4(){
local hostIp
local lanIps=$(arLanIp4)
case $(uname) in
'Linux')hostIp=$(ip -o -4 route get 100.64.0.1|grep -oE 'src [0-9\.]+'|awk '{print $2}'|grep -Ev "$lanIps")
;;
Darwin|FreeBSD)hostIp=$(ifconfig|grep "inet "|grep -v 127.0.0.1|awk '{print $2}'|grep -Ev "$lanIps")
esac
if [ -z "$hostIp" ];then
hostIp=$(arRequest $arIp4QueryUrl)
fi
if [ -z "$hostIp" ];then
return 2
fi
if [ -z "$(echo $hostIp|grep -E '^[0-9\.]+$')" ];then
arLog "> arWanIp4 - Invalid ip address"
return 1
fi
echo $hostIp
}
arDevIp4(){
local hostIp
local lanIps=$(arLanIp4)
case $(uname) in
'Linux')hostIp=$(ip -o -4 addr show dev $1 primary|grep -oE 'inet [0-9.]+'|awk '{print $2}'|grep -Ev "$lanIps"|head -n 1)
esac
if [ -z "$hostIp" ];then
arLog "> arDevIp4 - Can't get ip address"
return 1
fi
if [ -z "$(echo $hostIp|grep -E '^[0-9\.]+$')" ];then
arLog "> arDevIp4 - Invalid ip address"
return 1
fi
echo $hostIp
}
arLanIp6(){
local lanIps="(^$)"
lanIps="$lanIps|(^::1$)"
lanIps="$lanIps|(^64:[fF][fF]9[bB]:)"
lanIps="$lanIps|(^100::)"
lanIps="$lanIps|(^2001:2:0?:)"
lanIps="$lanIps|(^2001:[dD][bB]8:)"
lanIps="$lanIps|(^[fF][cdCD][0-9a-fA-F]{2}:)"
lanIps="$lanIps|(^[fF][eE][8-9a-bA-B][0-9a-fA-F]:)"
echo $lanIps
}
arWanIp6(){
local hostIp
local lanIps=$(arLanIp6)
case $(uname) in
'Linux')hostIp=$(ip -o -6 route get 100::1|grep -oE 'src [0-9a-fA-F:]+'|awk '{print $2}'|grep -Ev "$lanIps")
esac
if [ -z "$hostIp" ];then
hostIp=$(arRequest $arIp6QueryUrl)
fi
if [ -z "$hostIp" ];then
arLog "> arWanIp6 - Can't get ip address"
return 1
fi
if [ -z "$(echo $hostIp|grep -E '^[0-9a-fA-F:]+$')" ];then
arLog "> arWanIp6 - Invalid ip address"
return 1
fi
echo $hostIp
}
arDevIp6(){
local hostIp
local lanIps=$(arLanIp6)
case $(uname) in
'Linux')hostIp=$(ip -o -6 addr show dev $1 scope global home|grep -oE 'inet6 [0-9a-fA-F:]+'|awk '{print $2}'|grep -Ev "$lanIps")
if [ -z "$hostIp" ];then
hostIp=$(ip -o -6 addr show dev $1 scope global permanent|grep -oE 'inet6 [0-9a-fA-F:]+'|awk '{print $2}'|grep -Ev "$lanIps")
fi
if [ -z "$hostIp" ];then
hostIp=$(ip -o -6 addr show dev $1 scope global -deprecated primary|grep -v mngtmpaddr|grep -oE 'inet6 [0-9a-fA-F:]+'|awk '{print $2}'|grep -Ev "$lanIps")
fi
if [ -z "$hostIp" ];then
hostIp=$(ip -o -6 addr show dev $1 scope global -deprecated primary|grep -oE 'inet6 [0-9a-fA-F:]+'|awk '{print $2}'|grep -Ev "$lanIps")
fi
if [ -z "$hostIp" ];then
hostIp=$(ip -o -6 addr show dev $1 scope global -deprecated|grep -oE 'inet6 [0-9a-fA-F:]+'|awk '{print $2}'|grep -Ev "$lanIps")
fi
hostIp=$(echo "$hostIp"|head -n 1)
esac
if [ -z "$hostIp" ];then
arLog "> arDevIp6 - Can't get ip address"
return 1
fi
if [ -z "$(echo $hostIp|grep -E '^[0-9a-fA-F:]+$')" ];then
arLog "> arDevIp6 - Invalid ip address"
return 1
fi
echo $hostIp
}
arDdnsApi(){
local dnsapi="https://dnsapi.cn/${1:?'Info.Version'}"
local params="login_token=$arToken&format=json&lang=en&$2"
arRequest "$dnsapi" "$params"
}
arDdnsLookup(){
local errMsg
local recordId
if [ "$2" != "@" ];then
subDomainRule="&sub_domain=$2"
fi
recordId=$(arDdnsApi "Record.List" "domain=$1$subDomainRule&record_type=$3")
recordId=$(echo $recordId|sed 's/.*"id":"\([0-9]*\)".*/\1/')
if ! [ "$recordId" -gt 0 ] 2>/dev/null;then
errMsg=$(echo $recordId|sed 's/.*"message":"\([^\"]*\)".*/\1/')
arLog "> arDdnsLookup - $errMsg"
return 1
fi
echo $recordId
}
arDdnsUpdate(){
local errMsg
local recordRs
local recordCd
local recordIp
local lastRecordIp
local lastRecordIpFile="$arLastRecordFile.$3"
if [ -f $lastRecordIpFile ];then
lastRecordIp=$(cat $lastRecordIpFile)
fi
if [ -z "$lastRecordIp" ];then
recordRs=$(arDdnsApi "Record.Info" "domain=$1&record_id=$3")
recordCd=$(echo $recordRs|sed 's/.*{"code":"\([0-9]*\)".*/\1/')
lastRecordIp=$(echo $recordRs|sed 's/.*,"value":"\([0-9a-fA-F\.\:]*\)".*/\1/')
fi
if [ -z "$5" ];then
recordRs=$(arDdnsApi "Record.Ddns" "domain=$1&sub_domain=$2&record_id=$3&record_type=$4&record_line=%e9%bb%98%e8%ae%a4")
else
if [ "$5" = "$lastRecordIp" ];then
arLog "> arDdnsUpdate - unchanged: $lastRecordIp"
return $arErrCodeUnchanged
fi
recordRs=$(arDdnsApi "Record.Ddns" "domain=$1&sub_domain=$2&record_id=$3&record_type=$4&value=$5&record_line=%e9%bb%98%e8%ae%a4")
fi
recordCd=$(echo $recordRs|sed 's/.*{"code":"\([0-9]*\)".*/\1/')
recordIp=$(echo $recordRs|sed 's/.*,"value":"\([0-9a-fA-F\.\:]*\)".*/\1/')
if [ "$recordCd" != "1" ];then
errMsg=$(echo $recordRs|sed 's/.*,"message":"\([^"]*\)".*/\1/')
arLog "> arDdnsUpdate - error: $errMsg"
return 1
elif [ "$recordIp" = "$lastRecordIp" ];then
arLog "> arDdnsUpdate - unchanged: $recordIp"
return $arErrCodeUnchanged
else
arLog "> arDdnsUpdate - updated: $recordIp"
if [ -n "$lastRecordIpFile" ];then
echo $recordIp >$lastRecordIpFile
fi
return 0
fi
}
arDdnsCheck(){
local errCode
local hostIp
local recordId
local recordType
arLog "=== Check $2.$1 ==="
arLog "Fetching Host Ip"
if [ "$3" = "6" ]&&[ -n "$4" ];then
recordType=AAAA
hostIp=$(arDevIp6 "$4")
elif [ "$3" = "4" ]&&[ -n "$4" ];then
recordType=A
hostIp=$(arDevIp4 "$4")
elif [ "$3" = "6" ];then
recordType=AAAA
hostIp=$(arWanIp6)
else
recordType=A
hostIp=$(arWanIp4)
fi
errCode=$?
if [ $errCode -eq 0 ];then
arLog "> Host Ip: $hostIp"
arLog "> Record Type: $recordType"
elif [ $errCode -eq 2 ];then
arLog "> Host Ip: Auto"
arLog "> Record Type: $recordType"
else
arLog "$hostIp"
return $errCode
fi
arLog "Fetching RecordId"
recordId=$(arDdnsLookup "$1" "$2" "$recordType")
errCode=$?
if [ $errCode -eq 0 ];then
arLog "> Record Id: $recordId"
else
arLog "$recordId"
return $errCode
fi
arLog "Updating Record value"
arDdnsUpdate "$1" "$2" "$recordId" "$recordType" "$hostIp"
}
arToken="xxxx,xxxxxxxxxxxxxxxx"
arDdnsCheck "your.domain" "subdomain4"
arDdnsCheck "your.domain" "subdomain6" 6
