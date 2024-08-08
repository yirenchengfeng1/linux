#!/bin/bash
# REALITY一键安装脚本
# Author: YouTube频道<https://www.youtube.com/@aifenxiangdexiaoqie>

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

NAME="xray"
CONFIG_FILE="/usr/local/etc/${NAME}/config.json"
SERVICE_FILE="/etc/systemd/system/${NAME}.service"
DEFAULT_START_PORT=10000                      
IP_ADDRESSES=($(hostname -I))
declare -a USER_UUID PORT USER_NAME PRIVATE_KEY PUBLIC_KEY USER_DEST USER_SERVERNAME USER_SID LINK
	
colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

checkSystem() {
    result=$(id | awk '{print $1}')
    if [[ $result != "uid=0(root)" ]]; then
        colorEcho $RED " 请以root身份执行该脚本"
        exit 1
    fi

    res=`which yum 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        res=`which apt 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorEcho $RED " 不受支持的Linux系统"
            exit 1
        fi
        PMT="apt"
        CMD_INSTALL="apt install -y "
        CMD_REMOVE="apt remove -y "
        CMD_UPGRADE="apt update; apt upgrade -y; apt autoremove -y"
    else
        PMT="yum"
        CMD_INSTALL="yum install -y "
        CMD_REMOVE="yum remove -y "
        CMD_UPGRADE="yum update -y"
    fi
    res=`which systemctl 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        colorEcho $RED " 系统版本过低，请升级到最新版本"
        exit 1
    fi
}

status() {
    export PATH=/usr/local/bin:$PATH
    cmd="$(command -v xray)"
    if [[ "$cmd" = "" ]]; then
        echo 0
        return
    fi
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    fi
    port=`grep -o '"port": [0-9]*' $CONFIG_FILE | awk '{print $2}' | head -n 1`
	if [[ -n "$port" ]]; then
        res=`ss -ntlp| grep ${port} | grep xray`
        if [[ -z "$res" ]]; then
            echo 2
        else
            echo 3
        fi
	else
	    echo 2
	fi
}

statusText() {
    res=`status`
    case $res in
        2)
            echo -e ${GREEN}已安装xray${PLAIN} ${RED}未运行${PLAIN}
            ;;
        3)
            echo -e ${GREEN}已安装xray${PLAIN} ${GREEN}正在运行${PLAIN}
            ;;
        *)
            echo -e ${RED}未安装xray${PLAIN}
            ;;
    esac
}



preinstall() {
    $PMT clean all
    [[ "$PMT" = "apt" ]] && $PMT update
    echo ""
    echo "安装必要软件，请等待..."
    if [[ "$PMT" = "apt" ]]; then
		res=`which ufw 2>/dev/null`
        [[ "$?" != "0" ]] && $CMD_INSTALL ufw
	fi	
    res=`which curl 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL curl
    res=`which openssl 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL openssl
	res=`which qrencode 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL qrencode
	res=`which jq 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL jq

    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}

# 定义函数，返回随机选择的域名
random_website() {
    domains=(
        "one-piece.com"
        "www.lovelive-anime.jp"
        "www.swift.com"
        "academy.nvidia.com"
        "www.cisco.com"
        "www.samsung.com"
        "www.amd.com"
        "www.apple.com"
        "music.apple.com"
        "www.amazon.com"		
        "www.fandom.com"
        "tidal.com"
        "zoro.to"
        "www.pixiv.co.jp"
        "mxj.myanimelist.net"
        "mora.jp"
        "www.j-wave.co.jp"
        "www.dmm.com"
        "booth.pm"
        "www.ivi.tv"
        "www.leercapitulo.com"
        "www.sky.com"
        "itunes.apple.com"
        "download-installer.cdn.mozilla.net"	
    )

    total_domains=${#domains[@]}
    random_index=$((RANDOM % total_domains))
    
    # 输出选择的域名
    echo "${domains[random_index]}"
}


# 安装 Xray内核
installXray() {
    echo ""
    echo "正在安装Xray..."
    bash -c "$(curl -s -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" > /dev/null 2>&1
	colorEcho $BLUE "xray内核已安装完成"
	sleep 5
}

# 更新 Xray内核
updateXray() {
    echo ""
    echo "正在更新Xray..."
    bash -c "$(curl -s -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" > /dev/null 2>&1
	colorEcho $BLUE "xray内核已更新完成"
	sleep 5
}

removeXray() {
    echo ""
    echo "正在卸载Xray..."
    #systemctl stop xray
	#systemctl disable xray > /dev/null 2>&1
	#rm -rf /etc/systemd/system/xray*
	#rm /usr/local/bin/xray
    bash -c "$(curl -s -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge > /dev/null 2>&1
    rm -rf /etc/systemd/system/xray.service > /dev/null 2>&1
    rm -rf /etc/systemd/system/xray@.service > /dev/null 2>&1
    rm -rf /usr/local/bin/xray > /dev/null 2>&1
    rm -rf /usr/local/etc/xray > /dev/null 2>&1
    rm -rf /usr/local/share/xray > /dev/null 2>&1
    rm -rf /var/log/xray > /dev/null 2>&1
	colorEcho $RED "已完成xray卸载"
	sleep 5
}


# 创建配置文件 config.json
config_nodes() {

    read -p "起始端口 (默认 $DEFAULT_START_PORT): " START_PORT
	START_PORT=${START_PORT:-$DEFAULT_START_PORT}
	
    # 开始生成 JSON 配置
    cat > /usr/local/etc/xray/config.json <<EOF
{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
EOF

	# 循环遍历 IP 和端口
	for ((i = 0; i < ${#IP_ADDRESSES[@]}; i++)); do
		# 生成 UUID
		/usr/local/bin/xray uuid > /usr/local/etc/xray/uuid
		USER_UUID[$i]=`cat /usr/local/etc/xray/uuid`

		# 生成节点名称
		USER_NAME[$i]="Reality(by小企鹅)_$i"	

		# 生成私钥和公钥
		/usr/local/bin/xray x25519 > /usr/local/etc/xray/key
		PRIVATE_KEY[$i]=$(cat /usr/local/etc/xray/key | head -n 1 | awk '{print $3}')
		PUBLIC_KEY[$i]=$(cat /usr/local/etc/xray/key | sed -n '2p' | awk '{print $3}')

        # 开启端口
		PORT[$i]=$((START_PORT + i))
		echo "正在开启${PORT[$i]}端口..."	
		if [ -x "$(command -v firewall-cmd)" ]; then							  
			firewall-cmd --permanent --add-port=${PORT[$i]}/tcp > /dev/null 2>&1
			firewall-cmd --permanent --add-port=${PORT[$i]}/udp > /dev/null 2>&1
			firewall-cmd --reload > /dev/null 2>&1
			colorEcho $YELLOW "$PORT[$i]端口已成功开启"
		elif [ -x "$(command -v ufw)" ]; then								  
			ufw allow ${PORT[$i]}/tcp > /dev/null 2>&1
			ufw allow ${PORT[$i]}/udp > /dev/null 2>&1
			ufw reload > /dev/null 2>&1
			colorEcho $YELLOW "${PORT[$i]}端口已成功开启"
		else
			echo "无法配置防火墙规则。请手动配置以确保新xray端口可用!"
		fi

		# 生成或获取 dest
		# 反复随机选择域名，直到符合条件
		while true; do
			# 调用函数获取随机域名
			domain=$(random_website)
			# 使用 OpenSSL 检查域名的 TLS 信息
			check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
			# 如果 check_num 等于 3，表示符合条件，跳出循环
			if [ "$check_num" -eq 3 ]; then
				USER_SERVERNAME[$i]="$domain"
				break
			fi
		done	
		USER_DEST[$i]=${USER_SERVERNAME[i]}:443


		# 生成 short ID
        USER_SID[$i]=$(openssl rand -hex 8)

		echo "    {" >> /usr/local/etc/xray/config.json
		echo "      \"port\": ${PORT[$i]}," >> /usr/local/etc/xray/config.json
		echo "      \"protocol\": \"vless\"," >> /usr/local/etc/xray/config.json
		echo "      \"settings\": {" >> /usr/local/etc/xray/config.json
		echo "        \"clients\": [" >> /usr/local/etc/xray/config.json	
		echo "          {" >> /usr/local/etc/xray/config.json	
		echo "            \"id\": \"${USER_UUID[$i]}\"," >> /usr/local/etc/xray/config.json
		echo "            \"flow\": \"xtls-rprx-vision\"" >> /usr/local/etc/xray/config.json
		echo "          }" >> /usr/local/etc/xray/config.json	
		echo "        ]," >> /usr/local/etc/xray/config.json	
		echo "        \"decryption\": \"none\""  >> /usr/local/etc/xray/config.json
		echo "       },"  >> /usr/local/etc/xray/config.json
		echo "        \"streamSettings\": {"  >> /usr/local/etc/xray/config.json
		echo "            \"network\": \"tcp\","  >> /usr/local/etc/xray/config.json
		echo "            \"security\": \"reality\","  >> /usr/local/etc/xray/config.json
		echo "            \"realitySettings\": {"  >> /usr/local/etc/xray/config.json
		echo "                \"dest\": \"${USER_DEST[$i]}\","  >> /usr/local/etc/xray/config.json
		echo "                \"serverNames\": ["  >> /usr/local/etc/xray/config.json
		echo "                    \"${USER_SERVERNAME[$i]}\""  >> /usr/local/etc/xray/config.json
		echo "                ],"  >> /usr/local/etc/xray/config.json
		echo "                \"privateKey\": \"${PRIVATE_KEY[$i]}\","  >> /usr/local/etc/xray/config.json
		echo "                \"shortIds\": ["  >> /usr/local/etc/xray/config.json
		echo "                    \"\","  >> /usr/local/etc/xray/config.json
		echo "                    \"${USER_SID[$i]}\""  >> /usr/local/etc/xray/config.json
		echo "                ]"  >> /usr/local/etc/xray/config.json
		echo "            }"  >> /usr/local/etc/xray/config.json
		echo "        },"  >> /usr/local/etc/xray/config.json
		echo "        \"sniffing\": {"  >> /usr/local/etc/xray/config.json
		echo "            \"enabled\": true,"  >> /usr/local/etc/xray/config.json
		echo "            \"destOverride\": ["  >> /usr/local/etc/xray/config.json
		echo "                \"http\","  >> /usr/local/etc/xray/config.json
		echo "                \"tls\","  >> /usr/local/etc/xray/config.json
		echo "                \"quic\""  >> /usr/local/etc/xray/config.json
		echo "            ],"  >> /usr/local/etc/xray/config.json
		echo "            \"routeOnly\": true"  >> /usr/local/etc/xray/config.json
		echo "        }"  >> /usr/local/etc/xray/config.json
		# 如果不是最后一个元素，就加逗号
		if [ $i -lt $((${#IP_ADDRESSES[@]}-1)) ]; then
			echo "    }," >> /usr/local/etc/xray/config.json
		else
			echo "    }" >> /usr/local/etc/xray/config.json
		fi
    done
	    # 结束 JSON 配置
	    cat >> /usr/local/etc/xray/config.json <<EOF
	],
	"outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
  ]
}
EOF
	
    restart
	generate_link	




}


# 输出 VLESS 链接
generate_link() {
    > /root/link.txt
    colorEcho $BLUE "${BLUE}reality订阅链接${PLAIN}："
	# 循环遍历 IP 和端口
	for ((i = 0; i < ${#IP_ADDRESSES[@]}; i++)); do
		if [[ "${IP_ADDRESSES[$i]}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			LINK[$i]="vless://${USER_UUID[$i]}@${IP_ADDRESSES[$i]}:${PORT[$i]}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${USER_SERVERNAME[$i]}&fp=chrome&pbk=${PUBLIC_KEY[$i]}&sid=${USER_SID[$i]}&type=tcp&headerType=none#${USER_NAME[$i]}"
		elif [[ "${IP_ADDRESSES[$i]}" =~ ^([0-9a-fA-F:]+)$ ]]; then 
			LINK[$i]="vless://${USER_UUID[$i]}@[${IP_ADDRESSES[$i]}]:${PORT[$i]}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${USER_SERVERNAME[$i]}&fp=chrome&pbk=${PUBLIC_KEY[$i]}&sid=${USER_SID[$i]}&type=tcp&headerType=none#${USER_NAME[$i]}"
		else
			colorEcho $RED "没有获取到有效ip！"
		fi
	colorEcho $YELLOW ${LINK[$i]}
	echo ${LINK[$i]} >> /root/link.txt
	done
}	

start() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl restart ${NAME}
    sleep 2
    port=`grep -o '"port": [0-9]*' $CONFIG_FILE | awk '{print $2}' | head -n 1`
    res=`ss -ntlp| grep ${port} | grep xray`
    if [[ "$res" = "" ]]; then
        colorEcho $RED "xray启动失败，请检查端口是否被占用！"
    else
        colorEcho $BLUE "xray启动成功！"
    fi
}

restart() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi

    stop
    start
}

stop() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl stop ${NAME}
    colorEcho $BLUE "xray停止成功"
}



menu() {
    clear
    bash -c "$(curl -s -L https://raw.githubusercontent.com/yirenchengfeng1/linux/main/reality.sh)"
}

Xray() {
    clear
    echo "##################################################################"
    echo -e "#                   ${RED}Reality一键安装脚本${PLAIN}                                    #"
    echo -e "# ${GREEN}作者${PLAIN}: 爱分享的小企鹅                                                     #"
    echo -e "# ${GREEN}网址${PLAIN}: hhttp://www.youtube.com/@aifenxiangdexiaoqie                       #"
	echo -e "# ${GREEN}VPS选购攻略${PLAIN}：https://lovetoshare.top/archives/3.html                     #"
	echo -e "# ${GREEN}年付10美金VPS推荐${PLAIN}：https://my.racknerd.com/aff.php?aff=9734&pid=838      #"	
    echo "##################################################################"

    echo -e "  ${GREEN}  <Xray内核版本>  ${YELLOW}"	
    echo -e "  ${GREEN}1.${PLAIN}  安装xray"	
    echo -e "  ${GREEN}2.${PLAIN}  更新xray"
    echo -e "  ${GREEN}3.${RED}  卸载ray${PLAIN}"
    echo " -------------"	
    echo -e "  ${GREEN}4.${PLAIN}  搭建VLESS-Vision-uTLS-REALITY（xray）"
    echo -e "  ${GREEN}5.${PLAIN}  查看reality链接"
    echo " -------------"
    echo -e "  ${GREEN}6.${PLAIN}  启动xray"
    echo -e "  ${GREEN}7.${PLAIN}  重启xray"
    echo -e "  ${GREEN}8.${PLAIN}  停止xray"
    echo " -------------"
    echo -e "  ${GREEN}9.${PLAIN}  返回上一级菜单"	
    echo -e "  ${GREEN}0.${PLAIN}  退出"
    echo -n " 当前xray状态："
	statusText
    echo 

    read -p " 请选择操作[0-10]：" answer
    case $answer in
        0)
            exit 0
            ;;
        1)
		    checkSystem
            preinstall
	        installXray
			Xray
            ;;
        2)
	        updateXray
			Xray
            ;;	
        3)
            removeXray
            ;;			
		4)
            config_nodes
            ;;
        5)
			cat /root/link.txt 
            ;;
        6)
            start
			Xray
            ;;
        7)
            restart
			Xray
            ;;
        8)
            stop
			Xray
            ;;
		9)
			menu
            ;;
        *)
            echo " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

Xray
