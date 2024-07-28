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
    port=`grep -o '"port": [0-9]*' $CONFIG_FILE | awk '{print $2}'`
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


# 填写或生成 UUID
getuuid() {
    echo ""
    echo "正在生成UUID..." 
	/usr/local/bin/xray uuid > /usr/local/etc/xray/uuid
	USER_UUID=`cat /usr/local/etc/xray/uuid`
    colorEcho $BLUE "UUID：$USER_UUID"
	echo ""
}

# 指定节点名称
getname() {
	read -p "请输入您的节点名称，如果留空将保持默认：" USER_NAME
	[[ -z "$USER_NAME" ]] && USER_NAME="Reality(by小企鹅)"
    colorEcho $BLUE "节点名称：$USER_NAME"
	echo "$USER_NAME" > /usr/local/etc/xray/name
	echo ""
		
}

# 生成私钥和公钥
getkey() {
    echo "正在生成私钥和公钥，请妥善保管好..."
	/usr/local/bin/xray x25519 > /usr/local/etc/xray/key
	private_key=$(cat /usr/local/etc/xray/key | head -n 1 | awk '{print $3}')
	public_key=$(cat /usr/local/etc/xray/key | sed -n '2p' | awk '{print $3}')
	echo "$private_key" > /usr/local/etc/xray/privatekey
	echo "$public_key" > /usr/local/etc/xray/publickey
	KEY=`cat /usr/local/etc/xray/key`
	colorEcho $BLUE "$KEY"
    echo ""
}

getip() {
	
	# 尝试获取 IP 地址
    LOCAL_IPv4=$(curl -s -4 https://api.ipify.org)
    LOCAL_IPv6=$(curl -s -6 https://api64.ipify.org)

    # 检查 IPv是否存在且合法
    if [[ -n "$LOCAL_IPv4" && "$LOCAL_IPv4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        # 检查 IPv6 是否存在且合法
        if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
            colorEcho $YELLOW "本机 IPv4 地址："$LOCAL_IPv4""		    
            colorEcho $YELLOW "本机 IPv6 地址："$LOCAL_IPv6""
	        read -p "请确定你的节点ip，默认ipv4（0：ipv4；1：ipv6）:" USER_IP
	        if [[ $USER_IP == 1 ]]; then
                LOCAL_IP=$LOCAL_IPv6
	            colorEcho $BLUE "节点ip："$LOCAL_IP""				
            else
                LOCAL_IP=$LOCAL_IPv4
	            colorEcho $BLUE "节点ip："$LOCAL_IP""						
            fi								
        else
		    colorEcho $YELLOW "本机仅有 IPv4 地址："$LOCAL_IPv4""		
		    LOCAL_IP=$LOCAL_IPv4
            colorEcho $BLUE "节点ip："$LOCAL_IP""
        fi
    else
	    if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
	        colorEcho $YELLOW "本机仅有 IPv6 地址："$LOCAL_IPv6""		
		    LOCAL_IP=$LOCAL_IPv6
            colorEcho $BLUE "节点ip："$LOCAL_IP""
		else
            colorEcho $RED "未能获取到有效的公网 IP 地址。"		
		fi
    fi
    # 将 IP 地址写入文件
    echo "$LOCAL_IP" > /usr/local/etc/xray/ip
	
}

getport() {
    echo ""
    while true
    do
        read -p "请设置XRAY的端口号[1025-65535]，不输入则随机生成:" PORT
        [[ -z "$PORT" ]] && PORT=`shuf -i1025-65000 -n1`
        if [[ "${PORT:0:1}" = "0" ]]; then
            echo -e " ${RED}端口不能以0开头${PLAIN}"
            exit 1
        fi
        expr $PORT + 0 &>/dev/null
        if [[ $? -eq 0 ]]; then
            if [[ $PORT -ge 1025 ]] && [[ $PORT -le 65535 ]]; then
	            echo "$PORT" > /usr/local/etc/xray/port				
                colorEcho $BLUE "端口号：$PORT"
                break
            else
                colorEcho $RED "输入错误，端口号为1025-65535的数字"
            fi
        else
            colorEcho $RED "输入错误，端口号为1025-65535的数字"
        fi
    done
	
}

setFirewall() {
    echo ""
	echo "正在开启$PORT端口..."	
    if [ -x "$(command -v firewall-cmd)" ]; then							  
        firewall-cmd --permanent --add-port=${PORT}/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=${PORT}/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
		colorEcho $YELLOW "$PORT端口已成功开启"
	elif [ -x "$(command -v ufw)" ]; then								  
        ufw allow ${PORT}/tcp > /dev/null 2>&1
        ufw allow ${PORT}/udp > /dev/null 2>&1
	    ufw reload > /dev/null 2>&1
		colorEcho $YELLOW "$PORT端口已成功开启"
    else
	    echo "无法配置防火墙规则。请手动配置以确保新xray端口可用!"
    fi

}



# 生成或获取 dest
getdest() {
		
	echo ""
    read -p "请输入您的 dest 地址并确保该域名在国内的连通性（例如：www.amazon.com），如果留空将随机生成：" USER_DEST
	if [[ -z "$USER_DEST" ]]; then
		# 反复随机选择域名，直到符合条件
		while true; do
			# 调用函数获取随机域名
			domain=$(random_website)
			# 使用 OpenSSL 检查域名的 TLS 信息
			check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
			# 如果 check_num 等于 3，表示符合条件，跳出循环
			if [ "$check_num" -eq 3 ]; then
				USER_DEST="$domain"
				break
			fi
		done
		
		echo $USER_DEST:443 > /usr/local/etc/xray/dest
		echo $USER_DEST > /usr/local/etc/xray/servername
		colorEcho $BLUE "选中的符合条件的网站是： $USER_DEST"	
	else
		echo "正在检查 \"${USER_DEST}\" 是否支持 TLSv1.3与h2"
		# 检查是否支持 TLSv1.3与h2
        check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${USER_DEST}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
		if [[ ${check_num} -eq 3 ]]; then
		    echo $USER_DEST:443 > /usr/local/etc/xray/dest
		    echo $USER_DEST > /usr/local/etc/xray/servername		
			colorEcho $YELLOW "目标网址：\"${USER_DEST}\" 支持 TLSv1.3 与 h2"
		else
			colorEcho $YELLOW "目标网址：\"${USER_DEST}\" 不支持 TLSv1.3 与 h2，将在默认域名组中随机挑选域名"
			# 反复随机选择域名，直到符合条件
			while true; do
				# 调用函数获取随机域名
				domain=$(random_website)
				# 使用 OpenSSL 检查域名的 TLS 信息
				check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
				# 如果 check_num 等于 3，表示符合条件，跳出循环
				if [ "$check_num" -eq 3 ]; then
					USER_DEST="$domain"
					break
				fi
			done
			
		    echo $USER_DEST:443 > /usr/local/etc/xray/dest
		    echo $USER_DEST > /usr/local/etc/xray/servername
		    colorEcho $BLUE "选中的符合条件的网站是： $USER_DEST"				

		fi	   
	fi	
}



# 生成 short ID
getsid() {

    echo ""
    echo "正在生成shortID..."
    USER_SID=$(openssl rand -hex 8)
    echo $USER_SID > /usr/local/etc/xray/sid
    colorEcho $BLUE "shortID： $USER_SID"
    echo ""

}


# 创建配置文件 config.json
generate_config() {
    cat << EOF > /usr/local/etc/xray/config.json
{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
        {
            "port": $(cat /usr/local/etc/xray/port), 
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$(cat /usr/local/etc/xray/uuid)", 
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "$(cat /usr/local/etc/xray/dest)", 
                    "serverNames": [
                        "$(cat /usr/local/etc/xray/servername)"   
                    ],
                    "privateKey": "$(cat /usr/local/etc/xray/privatekey)",
                    "shortIds": [
                        "",
                        "$(cat /usr/local/etc/xray/sid)" 
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
    echo "创建配置文件完成..."
	echo ""
}

# 输出 VLESS 配置
print_config() {

    # Print the server details
    echo ""
    colorEcho $BLUE "reality节点配置信息如下："
    colorEcho $YELLOW "Server IP: ${PLAIN}$(cat /usr/local/etc/xray/ip)"
    colorEcho $YELLOW "Listen Port: ${PLAIN}$(cat /usr/local/etc/xray/port)"
    colorEcho $YELLOW "Server Name: ${PLAIN}$(cat /usr/local/etc/xray/servername)"
    colorEcho $YELLOW "Public Key: ${PLAIN}$(cat /usr/local/etc/xray/publickey)"
    colorEcho $YELLOW "Short ID: ${PLAIN}$(cat /usr/local/etc/xray/sid)"
    colorEcho $YELLOW "UUID: ${PLAIN}$(cat /usr/local/etc/xray/uuid)"
    echo ""
    echo ""

	
}	

# 输出 VLESS 链接
generate_link() {
	
    LOCAL_IP=`cat /usr/local/etc/xray/ip`
	if [[ "$LOCAL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LINK="vless://$(cat /usr/local/etc/xray/uuid)@$(cat /usr/local/etc/xray/ip):$(cat /usr/local/etc/xray/port)?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(cat /usr/local/etc/xray/servername)&fp=chrome&pbk=$(cat /usr/local/etc/xray/publickey)&sid=$(cat /usr/local/etc/xray/sid)&type=tcp&headerType=none#$(cat /usr/local/etc/xray/name)"
	elif [[ "$LOCAL_IP" =~ ^([0-9a-fA-F:]+)$ ]]; then 
        LINK="vless://$(cat /usr/local/etc/xray/uuid)@[$(cat /usr/local/etc/xray/ip)]:$(cat /usr/local/etc/xray/port)?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(cat /usr/local/etc/xray/servername)&fp=chrome&pbk=$(cat /usr/local/etc/xray/publickey)&sid=$(cat /usr/local/etc/xray/sid)&type=tcp&headerType=none#$(cat /usr/local/etc/xray/name)"
	else
	    colorEcho $RED "没有获取到有效ip！"
	fi
    colorEcho $BLUE "${BLUE}reality订阅链接${PLAIN}：${LINK}"
	echo ""
    echo ""	
	colorEcho $YELLOW "reality节点二维码（可直接扫码导入到v2rayN、shadowrocket等客户端...）："
	qrencode -o - -t utf8 -s 1 ${LINK}
    #qrencode -o /tmp/reality.png -s 10 ${LINK}
	#colorEcho $BLUE " 订阅二维码已保存在/tmp/reality.png，请下载使用..."	
}	


Modify_xrayconfig() {

    echo ""
	read -p "是否需要更换UUID（0：保持不变；1：重新生成）:" USER_UUID
	if [[ $USER_UUID == 1 ]]; then	
		echo ""	
		echo "正在重新生成UUID..."
		/usr/local/bin/xray uuid > /usr/local/etc/xray/uuid
		USER_UUID=`cat /usr/local/etc/xray/uuid`
		colorEcho $BLUE "UUID：$USER_UUID"
	else
	    colorEcho $BLUE "UUID保持不变!"  
	fi
	
	echo ""
	read -p "是否需要给节点重命名（0：保持不变；1：重新命名）:" USER_NAME
	if [[ $USER_NAME == 1 ]]; then	
		echo ""	
		read -p "请输入您的节点名称，如果留空将保持默认：" USER_NAME
		[[ -z "$USER_NAME" ]] && USER_NAME="Reality(by小企鹅)"
		colorEcho $BLUE "节点名称：$USER_NAME"
		echo "$USER_NAME" > /usr/local/etc/xray/name
	else
	    colorEcho $BLUE "节点名称保持不变!"  
	fi	

	echo ""		
	read -p "是否需要重新生成密钥（0：保持不变；1：重新生成）:" KEY
	if [[ $KEY == 1 ]]; then	
		echo ""		
		echo "正在生成私钥和公钥，请妥善保管好..."
		/usr/local/bin/xray x25519 > /usr/local/etc/xray/key
		private_key=$(cat /usr/local/etc/xray/key | head -n 1 | awk '{print $3}')
		public_key=$(cat /usr/local/etc/xray/key | sed -n '2p' | awk '{print $3}')
		echo "$private_key" > /usr/local/etc/xray/privatekey
		echo "$public_key" > /usr/local/etc/xray/publickey
		KEY=`cat /usr/local/etc/xray/key`
		colorEcho $BLUE "$KEY"
 	else
	    colorEcho $BLUE "密钥保持不变!"  
	fi	   
   
   
    echo ""

	read -p "是否需要更换节点ip（0：保持不变；1：重新选择）:" CHAIP
	if [[ $CHAIP == 1 ]]; then	    	
		# 尝试获取 IP 地址
		LOCAL_IPv4=$(curl -s -4 https://api.ipify.org)
		LOCAL_IPv6=$(curl -s -6 https://api64.ipify.org)

		# 检查 IPv是否存在且合法
		if [[ -n "$LOCAL_IPv4" && "$LOCAL_IPv4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

			# 检查 IPv6 是否存在且合法
			if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
				colorEcho $YELLOW "本机 IPv4 地址："$LOCAL_IPv4""		    
				colorEcho $YELLOW "本机 IPv6 地址："$LOCAL_IPv6""
				read -p "请确定你的节点ip，默认ipv4（0：ipv4；1：ipv6）:" USER_IP
				if [[ $USER_IP == 1 ]]; then
					LOCAL_IP=$LOCAL_IPv6
					colorEcho $BLUE "节点ip："$LOCAL_IP""				
				else
					LOCAL_IP=$LOCAL_IPv4
					colorEcho $BLUE "节点ip："$LOCAL_IP""						
				fi								
			else
				colorEcho $YELLOW "本机仅有 IPv4 地址："$LOCAL_IPv4""		
				LOCAL_IP=$LOCAL_IPv4
				colorEcho $BLUE "节点ip："$LOCAL_IP""
			fi
		else
			if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
				colorEcho $YELLOW "本机仅有 IPv6 地址："$LOCAL_IPv6""		
				LOCAL_IP=$LOCAL_IPv6
				colorEcho $BLUE "节点ip："$LOCAL_IP""
			else
				colorEcho $RED "未能获取到有效的公网 IP 地址。"		
			fi
		fi
		# 将 IP 地址写入文件
		echo "$LOCAL_IP" > /usr/local/etc/xray/ip
    else
	    colorEcho $BLUE "节点ip保持不变!"  		
    fi

    echo ""
	read -p "是否需要更换端口（0：保持不变；1：更换端口）:" PORT
	if [[ $PORT == 1 ]]; then	
		while true
		do
	        echo ""
			read -p "请设置XRAY的端口号[1025-65535]，不输入则随机生成:" PORT
			[[ -z "$PORT" ]] && PORT=`shuf -i1025-65000 -n1`
			if [[ "${PORT:0:1}" = "0" ]]; then
				echo -e " ${RED}端口不能以0开头${PLAIN}"
				exit 1
			fi
			expr $PORT + 0 &>/dev/null
			if [[ $? -eq 0 ]]; then
				if [[ $PORT -ge 1025 ]] && [[ $PORT -le 65535 ]]; then
					echo "$PORT" > /usr/local/etc/xray/port	
					colorEcho $BLUE "端口号：$PORT"	
					echo ""
					echo "正在开启$PORT端口..."
					if [ -x "$(command -v firewall-cmd)" ]; then							  
						firewall-cmd --permanent --add-port=${PORT}/tcp > /dev/null 2>&1
						firewall-cmd --permanent --add-port=${PORT}/udp > /dev/null 2>&1
						firewall-cmd --reload > /dev/null 2>&1
						colorEcho $YELLOW "$PORT端口已成功开启"
					elif [ -x "$(command -v ufw)" ]; then								  
						ufw allow ${PORT}/tcp > /dev/null 2>&1
						ufw allow ${PORT}/udp > /dev/null 2>&1
						ufw reload > /dev/null 2>&1
						colorEcho $YELLOW "$PORT端口已成功开启"
					else
						echo "无法配置防火墙规则。请手动配置以确保新xray端口可用!"
					fi                  					
					break
				else
					colorEcho $RED "输入错误，端口号为1025-65535的数字"
				fi
			else
				colorEcho $RED "输入错误，端口号为1025-65535的数字"
			fi
		done
 	else
	    colorEcho $BLUE "端口保持不变!"  
	fi	 	
	


    echo ""
	read -p "是否需要更换目标网站（0：保持不变；1：重新输入）:" USER_DEST
	if [[ $USER_DEST == 1 ]]; then	
		echo ""
		read -p "请输入您的 dest 地址并确保该域名在国内的连通性（例如：www.amazon.com），如果留空将随机生成：" USER_DEST
		if [[ -z "$USER_DEST" ]]; then
			# 反复随机选择域名，直到符合条件
			while true; do
				# 调用函数获取随机域名
				domain=$(random_website)
				# 使用 OpenSSL 检查域名的 TLS 信息
				check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
				# 如果 check_num 等于 3，表示符合条件，跳出循环
				if [ "$check_num" -eq 3 ]; then
					USER_DEST="$domain"
					break
				fi
			done
			
			echo $USER_DEST:443 > /usr/local/etc/xray/dest
			echo $USER_DEST > /usr/local/etc/xray/servername
			colorEcho $BLUE "选中的符合条件的网站是： $USER_DEST"	
		else
			echo "正在检查 \"${USER_DEST}\" 是否支持 TLSv1.3与h2"
			# 检查是否支持 TLSv1.3与h2
			check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${USER_DEST}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
			if [[ ${check_num} -eq 3 ]]; then
				echo $USER_DEST:443 > /usr/local/etc/xray/dest
				echo $USER_DEST > /usr/local/etc/xray/servername		
				colorEcho $YELLOW "目标网址：\"${USER_DEST}\" 支持 TLSv1.3 与 h2"
			else
				colorEcho $YELLOW "目标网址：\"${USER_DEST}\" 不支持 TLSv1.3 与 h2，将在默认域名组中随机挑选域名"
				# 反复随机选择域名，直到符合条件
				while true; do
					# 调用函数获取随机域名
					domain=$(random_website)
					# 使用 OpenSSL 检查域名的 TLS 信息
					check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
					# 如果 check_num 等于 3，表示符合条件，跳出循环
					if [ "$check_num" -eq 3 ]; then
						USER_DEST="$domain"
						break
					fi
				done
				
				echo $USER_DEST:443 > /usr/local/etc/xray/dest
				echo $USER_DEST > /usr/local/etc/xray/servername
				colorEcho $BLUE "选中的符合条件的网站是： $USER_DEST"				

			fi	   
		fi	
	else
	    colorEcho $BLUE "目标网址保持不变!"  
	fi	
	
    echo ""
	read -p "是否需要重新生成shortID:（0：保持不变；1：重新生成）" USER_SID
	if [[ $USER_SID == 1 ]]; then
        echo ""
		echo "正在重新生成shortID..."
		USER_SID=$(openssl rand -hex 8)
		echo $USER_SID > /usr/local/etc/xray/sid
		colorEcho $BLUE "shortID： $USER_SID"
		echo ""
 	else
	    colorEcho $BLUE "shortID保持不变!"  
	fi	

    		
}

start() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl restart ${NAME}
    sleep 2
    port=`grep -o '"port": [0-9]*' $CONFIG_FILE | awk '{print $2}'`
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
    echo -e "  ${GREEN}6.  ${RED}修改reality配置${PLAIN}"		
    echo " -------------"
    echo -e "  ${GREEN}7.${PLAIN}  启动xray"
    echo -e "  ${GREEN}8.${PLAIN}  重启xray"
    echo -e "  ${GREEN}9.${PLAIN}  停止xray"
    echo " -------------"
    echo -e "  ${GREEN}10.${PLAIN}  返回上一级菜单"	
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
			getuuid
			getname
			getkey
			getip
			getport
			setFirewall
			getdest
			getsid
			generate_config
		    restart
			print_config
			generate_link
            ;;
        5)
			generate_link  
            ;;
        6)
            Modify_xrayconfig
			generate_config
		    restart
			print_config
			generate_link      
            ;;
        7)
            start
			Xray
            ;;
        8)
            restart
			Xray
            ;;
        9)
            stop
			Xray
            ;;
		10)
			menu
            ;;
        *)
            echo " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

Xray
